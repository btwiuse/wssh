package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
)

// Asking an agent to sign a Solana transaction, from this end.
//
// Nothing here builds a transaction. That is deliberate: the serialisation
// belongs to the library that is meant to keep up with Solana, and it runs on
// the far side of the socket where the wallet is. What this does is express an
// intent as instructions, hand them over, and check what comes back.

// SystemProgramID is the System Program, which is what a transfer calls.
//
// It is a run of '1's, which is also why it is worth having as a constant
// rather than typing: it is exactly the kind of address that a base58 decoder
// gets wrong, and every transfer goes through it.
const SystemProgramID = "11111111111111111111111111111111"

// TransferInstruction describes a transfer in the terms a person would use:
// an amount and a destination. Everything else is what the far side is for.
type TransferInstruction struct {
	// Lamports is the amount, in the smallest unit. A whole SOL is
	// 1_000_000_000 lamports.
	Lamports uint64 `json:"lamports"`

	// To is the destination account, base58.
	To string `json:"to"`
}

// NewSolanaTransfer builds the instruction list for a transfer.
//
// The data field is a System Program transfer: a four-byte discriminant of
// two, then the amount as eight little-endian bytes. That is twelve bytes of
// fixed layout rather than a serialisation format, which is why it can be
// written here without the drift risk that putting the transaction itself in
// Go would carry.
func NewSolanaTransfer(transfer TransferInstruction) ([]agentkey.SolanaInstruction, error) {
	if transfer.Lamports == 0 {
		return nil, errors.New("a transfer of nothing is not worth asking for")
	}
	if _, err := siws.Base58Decode(transfer.To); err != nil {
		return nil, fmt.Errorf("the destination is not a Solana address: %w", err)
	}

	data := make([]byte, 12)
	data[0], data[1], data[2], data[3] = 2, 0, 0, 0
	for i := 0; i < 8; i++ {
		data[4+i] = byte(transfer.Lamports >> (8 * i))
	}

	return []agentkey.SolanaInstruction{{
		ProgramID: SystemProgramID,
		// The destination is written to and never signs; the fee payer, which
		// does sign, is added by whoever builds the transaction.
		Accounts: []agentkey.SolanaAccount{{
			Address:    transfer.To,
			IsSigner:   false,
			IsWritable: true,
		}},
		DataBase58: siws.Base58Encode(data),
	}}, nil
}

// SolanaTxAt asks the agent listening on sockPath to sign a transaction.
//
// An empty path means $SSH_AUTH_SOCK, which is what a shell sets up for
// everything else that wants a signature and so the obvious default here too.
func SolanaTxAt(ctx context.Context, sockPath string, req agentkey.SolanaTxRequest) (agentkey.SolanaTxResponse, error) {
	if sockPath == "" {
		sockPath = os.Getenv("SSH_AUTH_SOCK")
	}
	if sockPath == "" {
		return agentkey.SolanaTxResponse{}, errors.New(
			"no agent: SSH_AUTH_SOCK is not set, so nothing here can ask for a signature")
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return agentkey.SolanaTxResponse{}, fmt.Errorf("reach the agent at %s: %w", filepath.Base(sockPath), err)
	}
	defer conn.Close() //nolint:errcheck

	return SolanaTxOver(ctx, conn, req)
}

// SolanaTxOver asks an agent, on a connection already open, to sign.
//
// The socket is left in a state a caller cannot do much else with afterwards,
// so this takes the connection rather than a path and says so: one request per
// connection.
// solanaTxTimeout bounds one request. It is generous because the far end may be
// waiting for a person to read a wallet prompt, and past it the answer will
// not be coming.
const solanaTxTimeout = 5 * time.Minute

func SolanaTxOver(ctx context.Context, conn net.Conn, req agentkey.SolanaTxRequest) (agentkey.SolanaTxResponse, error) {
	var resp agentkey.SolanaTxResponse

	body, err := json.Marshal(req)
	if err != nil {
		return resp, fmt.Errorf("pack the request: %w", err)
	}

	// The agent client's Extension has no context of its own and blocks, so the
	// bound is a socket deadline. Without one a wallet prompt that nobody
	// answers would hold this process for ever.
	deadline := time.Now().Add(solanaTxTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return resp, fmt.Errorf("bound the request: %w", err)
	}

	agentConn := agent.NewClient(conn)
	raw, err := agentConn.Extension(agentkey.SolanaTxExtension, body)
	if err != nil {
		return resp, describeExtensionFailure(err)
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return resp, fmt.Errorf("the agent's answer is not readable: %w", err)
	}
	if resp.Refusal != "" {
		return resp, errors.New(resp.Refusal)
	}
	if len(resp.SignedTransaction) == 0 {
		return resp, errors.New("the agent returned no signed transaction")
	}
	return resp, nil
}

// describeExtensionFailure works out what an agent not answering means here.
//
// The agent protocol distinguishes the two cases exactly, which is worth using.
// A plain failure means the agent has never heard of the extension, and the
// likeliest reason is that it is a real ssh-agent: one of those signs whatever
// it is asked to, so this whole conversation is unnecessary and git or
// ssh-keygen would have worked. Saying that is more use than telling someone to
// go and attach a wallet they may not need.
//
// An extension failure means it does know the extension and said no. That
// reason travels in the answer rather than here, because the protocol drops it.
func describeExtensionFailure(err error) error {
	if errors.Is(err, agent.ErrExtensionUnsupported) {
		return errors.New(
			"this agent does not sign Solana transactions. If it is a real " +
				"ssh-agent you do not need this command: it will sign anything " +
				"you ask of it, so git push and ssh-keygen work as they always " +
				"have. Otherwise it is a browser agent with no wallet attached, " +
				"which needs one, and the agent forwarding that reaches it")
	}
	msg := err.Error()
	if len(msg) > 400 {
		msg = msg[:400] + "..."
	}
	return fmt.Errorf("the agent refused to sign: %s", msg)
}

// LatestBlockhash asks an RPC endpoint for the most recent blockhash.
//
// A blockhash goes stale in about a minute, which is why this is fetched just
// before asking rather than cached: a transaction built against an old one is
// rejected on arrival, and the failure looks like a signing problem rather than
// a timing one.
func LatestBlockhash(ctx context.Context, rpcURL string) (string, error) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}`)

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build the blockhash request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ask %s for a blockhash: %w", hostOf(rpcURL), err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s answered the blockhash request with %s", hostOf(rpcURL), resp.Status)
	}

	// getLatestBlockhash wraps its answer in a context, so the blockhash is a
	// level further in than it looks. Reading result.blockhash finds nothing,
	// silently, which is worse than a wrong address would be.
	var answer struct {
		Result struct {
			Context struct {
				Slot       int    `json:"slot"`
				APIVersion string `json:"apiVersion"`
			} `json:"context"`
			Value struct {
				Blockhash            string `json:"blockhash"`
				LastValidBlockHeight int    `json:"lastValidBlockHeight"`
			} `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer); err != nil {
		return "", fmt.Errorf("read the blockhash answer: %w", err)
	}
	if answer.Error != nil {
		return "", fmt.Errorf("%s: %s", hostOf(rpcURL), answer.Error.Message)
	}
	if answer.Result.Value.Blockhash == "" {
		return "", fmt.Errorf("%s returned no blockhash", hostOf(rpcURL))
	}
	return answer.Result.Value.Blockhash, nil
}

// ParseLamports reads an amount given in SOL.
// hostOf is what a URL is called in an error message: the host, without the
// scheme, path or anything else that would be noise.
func hostOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL
	}
	return parsed.Host
}

func ParseLamports(sol string) (uint64, error) {
	amount, err := strconv.ParseFloat(sol, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not an amount of SOL", sol)
	}
	if amount <= 0 {
		return 0, errors.New("an amount has to be more than nothing")
	}
	// A lamport is a billionth of a SOL. Anything past a hundred billion is
	// more than the total supply, which is a typo rather than a transfer.
	const perSOL = 1_000_000_000
	lamports := uint64(amount * perSOL)
	if lamports == 0 {
		return 0, errors.New("that is less than a lamport")
	}
	if lamports > 500_000_000_000_000_000 {
		return 0, errors.New("that is more lamports than exist")
	}
	return lamports, nil
}

var _ = time.Second
