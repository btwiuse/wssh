package solana

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"strings"
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

// MemoProgramID is the SPL Memo v2 program. It logs the string it is given
// and writes no state, so a memo costs one signature fee and moves nothing.
//
// The address is not obvious and the wrong one does not decode to 32 bytes,
// so it is worth having as a constant: a memo built with a mistyped program
// id reaches the wallet and comes back as "not a Solana address", which is
// legible once but not twice.
const MemoProgramID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

// NewMemo builds the instruction that attaches a note to a transaction.
//
// The accounts list is empty. The memo program's only account is the signer,
// and the wallet is the signer, so naming one here would be saying nothing
// the far side does not already know - and the agent protocol's parser is
// taught to let this program through with an empty list for that reason.
func NewMemo(text string) ([]agentkey.SolanaInstruction, error) {
	if text == "" {
		return nil, errors.New("a memo of nothing is not worth asking for")
	}
	// The program rejects anything longer as "Memo too long", and the
	// transaction lands as a fee-burning error. Checking here means the
	// limit is something a person reads before signing rather than after.
	if len(text) > memoMaxBytes {
		return nil, fmt.Errorf("a memo is limited to %d bytes, this one is %d", memoMaxBytes, len(text))
	}
	return []agentkey.SolanaInstruction{{
		ProgramID:  MemoProgramID,
		Accounts:   []agentkey.SolanaAccount{},
		DataBase58: siws.Base58Encode([]byte(text)),
	}}, nil
}

// memoMaxBytes is the program limit on the note itself, in bytes of UTF-8
// rather than of the base58 the request carries it in.
const memoMaxBytes = 566

// TransferInstruction describes a transfer in the terms a person would use:
// an amount and a destination. Everything else is what the far side is for.
type TransferInstruction struct {
	// Lamports is the amount, in the smallest unit. A whole SOL is
	// 1_000_000_000 lamports.
	Lamports uint64 `json:"lamports"`

	// To is the destination account, base58.
	To string `json:"to"`
}

// NewTransfer builds the instruction list for a transfer.
//
// The data field is a System Program transfer: a four-byte discriminant of
// two, then the amount as eight little-endian bytes. That is twelve bytes of
// fixed layout rather than a serialisation format, which is why it can be
// written here without the drift risk that putting the transaction itself in
// Go would carry.
func NewTransfer(transfer TransferInstruction) ([]agentkey.SolanaInstruction, error) {
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

// Ask asks the agent listening on sockPath to sign a transaction.
//
// An empty path means $SSH_AUTH_SOCK, which is what a shell sets up for
// everything else that wants a signature and so the obvious default here too.
func Ask(ctx context.Context, sockPath string, req agentkey.SolanaTxRequest) (agentkey.SolanaTxResponse, error) {
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

	return AskOver(ctx, conn, req)
}

// AskOver asks an agent, on a connection already open, to sign.
//
// The socket is left in a state a caller cannot do much else with afterwards,
// so this takes the connection rather than a path and says so: one request per
// connection.
// solanaTxTimeout bounds one request. It is generous because the far end may be
// waiting for a person to read a wallet prompt, and past it the answer will
// not be coming.
const solanaTxTimeout = 5 * time.Minute

func AskOver(ctx context.Context, conn net.Conn, req agentkey.SolanaTxRequest) (agentkey.SolanaTxResponse, error) {
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

// ResolveNetwork turns the friendly --network name into an RPC URL. The empty
// string and the named clusters all have a default; anything else is treated
// as a custom URL, which is what makes the same flag useful for a private
// cluster or a paid provider.
//
// The named values use the same endpoints the official Solana CLI does:
// flipping the name changes both the blockhash source and the destination for
// a send, so one switch covers both.
func ResolveNetwork(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "mainnet", "mainnet-beta":
		return "https://api.mainnet-beta.solana.com"
	case "testnet":
		return "https://api.testnet.solana.com"
	case "devnet":
		return "https://api.devnet.solana.com"
	default:
		return name
	}
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
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read the blockhash answer: %w", err)
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return "", fmt.Errorf("%s answered with a non-JSON body (%d bytes): %q",
			hostOf(rpcURL), len(raw), trimForLog(raw, 120))
	}
	if answer.Error != nil {
		if answer.Error.Code != 0 {
			return "", fmt.Errorf("%s (code %d): %s",
				hostOf(rpcURL), answer.Error.Code, answer.Error.Message)
		}
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

// urlOf returns the URL string used in messages that name the endpoint.
// It is the full URL when it parses cleanly, the input otherwise: the
// difference matters when --rpc is a host that does not in fact answer
// at the path our client tried, which the host alone does not show.
func urlOf(rawURL string) string {
	if _, err := url.Parse(rawURL); err != nil {
		return rawURL
	}
	return rawURL
}

// SendTransaction posts a signed transaction to an RPC endpoint and waits
// for it to be confirmed.
//
// The wait is bounded because a transaction that the cluster will not accept
// fails fast, and one it accepts lands within a few seconds; anything past
// that is something the caller will have to read about on their own, and
// pretending to wait for it would just delay the news.
func SendTransaction(ctx context.Context, rpcURL string, signed []byte) (string, error) {
	body := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":["%s",{"encoding":"base64","skipPreflight":true,"preflightCommitment":"confirmed"}]}`,
		base64.StdEncoding.EncodeToString(signed),
	))

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build the send request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send to %s: %w", hostOf(rpcURL), err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s answered the send request with %s", hostOf(rpcURL), resp.Status)
	}

	var answer struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	// The full URL tells the user which endpoint was actually hit, which
	// matters when --rpc is set to a host that does not in fact implement
	// sendTransaction: code -32601 from the right host is "use a real
	// Solana endpoint", from the wrong one is "check your URL".
	url := urlOf(rpcURL)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read the send answer: %w", err)
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		// A non-JSON body is the cluster's last word on what went wrong,
		// and the only chance to name it before the message is lost:
		// surfacing the bytes here is what turns "it did not work" into a
		// reason to look at.
		return "", fmt.Errorf("%s answered with a non-JSON body (%d bytes): %q",
			url, len(raw), trimForLog(raw, 120))
	}
	if answer.Error != nil {
		// Standard JSON-RPC codes are specific enough to be worth naming:
		// code -32601 is "the cluster does not implement sendTransaction",
		// which is the difference between a proxy problem and a code bug.
		switch {
		case answer.Error.Code == -32601:
			return "", fmt.Errorf("%s does not implement sendTransaction: %s",
				url, answer.Error.Message)
		case answer.Error.Code != 0:
			return "", fmt.Errorf("%s refused the transaction (code %d): %s",
				url, answer.Error.Code, answer.Error.Message)
		default:
			return "", fmt.Errorf("%s refused the transaction: %s",
				url, answer.Error.Message)
		}
	}
	if answer.Result == "" {
		return "", fmt.Errorf("%s returned no signature", url)
	}
	return answer.Result, nil
}

func trimForLog(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// SignatureStatus is what a cluster says about a signature it has seen.
type SignatureStatus struct {
	ConfirmationStatus string `json:"confirmationStatus"`
	Confirmations      *int   `json:"confirmations"`
	Err                any    `json:"err"`
	Slot               uint64 `json:"slot"`
}

// Confirmed is whether the transaction reached a state a sender can rely on.
// A transaction that landed and failed its instructions is not confirmed: the
// signature exists, the money did not move.
func (s SignatureStatus) Confirmed() bool {
	return s.Err == nil &&
		(s.ConfirmationStatus == "confirmed" || s.ConfirmationStatus == "finalized")
}

// ConfirmTransaction waits for the cluster to say a signature has been
// recorded, and reports what it found.
//
// The method is getSignatureStatuses rather than confirmTransaction. The
// latter answers -32601 "Method not found" on a public cluster, which made
// every --send against mainnet fail after a broadcast that had in fact
// succeeded: the transaction was on chain and the command said it was not.
// getSignatureStatuses is the method that exists everywhere, and it answers
// for a signature the cluster has not seen yet by returning null, which is
// what makes polling possible.
//
// A transaction that landed but failed its instructions is an error, not a
// success. Reporting it as sent is the one wrong answer available here: the
// fee is spent and nothing else happened, and a person reading the output
// has to be told that.
func ConfirmTransaction(ctx context.Context, rpcURL, signature string) error {
	deadline := time.Now().Add(90 * time.Second)
	for {
		status, err := signatureStatus(ctx, rpcURL, signature)
		if err != nil {
			return err
		}
		// A null value means the cluster has not seen the signature yet,
		// which is the normal state immediately after a broadcast.
		if status != nil {
			if status.Err != nil {
				return fmt.Errorf("the transaction failed on chain: %v", status.Err)
			}
			if status.Confirmed() {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("signature %s did not confirm within %s", signature, 90*time.Second)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// signatureStatus asks the cluster about one signature. A nil status with a
// nil error means the cluster has not seen it yet.
func signatureStatus(ctx context.Context, rpcURL, signature string) (*SignatureStatus, error) {
	body := []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[["%s"],{"searchTransactionHistory":true}]}`,
		signature,
	))

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build the confirm request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("confirm at %s: %w", hostOf(rpcURL), err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s answered the confirm request with %s", hostOf(rpcURL), resp.Status)
	}

	var answer struct {
		Result struct {
			Value []*SignatureStatus `json:"value"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read the confirm answer: %w", err)
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("%s answered with a non-JSON body (%d bytes): %q",
			hostOf(rpcURL), len(raw), trimForLog(raw, 120))
	}
	if answer.Error != nil {
		if answer.Error.Code != 0 {
			return nil, fmt.Errorf("%s (code %d): %s",
				hostOf(rpcURL), answer.Error.Code, answer.Error.Message)
		}
		return nil, fmt.Errorf("%s: %s", hostOf(rpcURL), answer.Error.Message)
	}
	if len(answer.Result.Value) == 0 {
		return nil, nil
	}
	return answer.Result.Value[0], nil
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
