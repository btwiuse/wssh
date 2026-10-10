package agentkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/btwiuse/wssh/auth/siws"
)

// SolanaTxExtension is the agent extension a session uses to ask the wallet to
// sign a transaction.
//
// It exists because the agent protocol has no such operation. Its Sign takes
// arbitrary bytes, and a wallet will not sign arbitrary bytes - that is the
// whole reason signing in needed a protocol of its own. An extension carries
// whatever the two sides agree on, and both ends of this one are ours, so it
// can carry a Solana transaction instead.
//
// Anything in the session may send this. There is no allow list and no
// remembered approval: the request goes to the wallet every time, and the
// wallet is the only thing that decides whether it is reasonable. That is a
// deliberate choice - a "trust this session" shortcut would hand the wallet
// open to anything that got as far as a shell.
const SolanaTxExtension = "solana-tx@wssh"

// SolanaTxRequest is what a session sends.
//
// It is a list of instructions rather than a signed-over blob, because the
// transaction is built in the page from the parts and the wallet is shown what
// it came to. Sending finished bytes would put the wallet in the position of
// approving something the page did not show them in the form they were shown.
type SolanaTxRequest struct {
	// Blockhash is the recent blockhash the transaction will be built
	// against, base58. A blockhash goes stale in about a minute, so this is
	// usually worth fetching just before asking rather than caching.
	Blockhash string `json:"blockhash"`

	// Label is free text carried along for the page to show. It is not
	// trusted: the decoded instructions are shown beside it, not instead.
	Label string `json:"label,omitempty"`

	// Payer is the account that pays the fee, when the session is signing for
	// itself rather than handing the transaction to a wallet. Empty means a
	// connected wallet pays.
	Payer string `json:"payer,omitempty"`

	Instructions []SolanaInstruction `json:"instructions"`
}

// SolanaInstruction is one instruction, still in its raw form: the program to
// call, the accounts it takes, and the bytes it takes them with.
type SolanaInstruction struct {
	ProgramID  string          `json:"programId"`
	Accounts   []SolanaAccount `json:"accounts"`
	DataBase58 string          `json:"data"`
}

// SolanaAccount is one account an instruction takes, with the roles it is
// passed in.
//
// The roles are part of the instruction, not a detail the far end can work out:
// an account marked writable that is not, or a signer that is not, produces a
// transaction that either fails to send or does something other than what was
// asked for. They are stated rather than guessed for the same reason the
// transaction is built there - the browser is the side that can show them.
type SolanaAccount struct {
	Address    string `json:"address"`
	IsSigner   bool   `json:"isSigner"`
	IsWritable bool   `json:"isWritable"`
}

// SolanaTxResponse is what the extension answers with, either way.
//
// A refusal is carried in here rather than returned as an error because the
// agent protocol has nowhere to put one: an extension that fails answers with
// a single byte saying so, and the reason is dropped on the floor. Returning
// the reason as content is the only way the person who asked gets to hear it.
//
// An agent that does not know the extension at all is a different thing
// entirely, and the protocol does distinguish it: that is a plain failure
// rather than an extension failure, and it is what a real ssh-agent looks
// like. It never reaches here.
type SolanaTxResponse struct {
	// Refusal is why the answer is no, in words meant for whoever asked.
	// Empty means the answer is yes.
	Refusal string `json:"refusal,omitempty"`

	// Payer is the base58 wallet public key that holds the signing key.
	// Returned on every response so a caller that did not already know
	// which pubkey the agent represents can ask once and pass it back
	// on later requests (the memo program, for example, needs the signer
	// listed in accounts and the wallet fills the signer itself only
	// when the request already names it).
	Payer string `json:"payer,omitempty"`

	// message is the part the signature covers, kept so a fixture can be read
	// apart in a test. It is not on the wire.
	message           []byte `json:"-"`
	Signature         []byte `json:"signature,omitempty"`
	SignedTransaction []byte `json:"signedTransaction,omitempty"`
}

// refused reports whether this is an answer of no.
func (r SolanaTxResponse) refused() bool { return r.Refusal != "" }

// ownPublicKey is the ed25519 key an agent holds, or nil if it is something
// else. Everything else here is checked against it.
func ownPublicKey(signer gossh.Signer) ed25519.PublicKey {
	crypto, ok := signer.PublicKey().(gossh.CryptoPublicKey)
	if !ok {
		return nil
	}
	pub, _ := crypto.CryptoPublicKey().(ed25519.PublicKey)
	return pub
}

// walletPayer is the base58 wallet public key, or empty when no signer is
// attached. The response carries it on every path - refusal, success, or
// missing-input - so a caller that did not already know which pubkey the
// agent represents can ask once and pass it back on later requests.
func walletPayer(signer gossh.Signer) string {
	if pub := ownPublicKey(signer); pub != nil {
		return siws.Base58Encode(pub)
	}
	return ""
}

// SolanaBuild asks for a transaction to be built without being signed, for an
// agent whose key is local. The serialisation happens there because the library
// that tracks Solana's format lives there; the signature comes back here.
type SolanaBuild func(req SolanaTxRequest) ([]byte, error)

// SolanaAsk carries a request to whoever holds the wallet and brings back what
// it decided, along with the key it says signed.
//
// It is a function rather than a key because the key is not ours: it lives in a
// wallet extension, and getting a signature out of one is a conversation, not
// a computation.
//
// The key comes back with the answer rather than being taken on trust, because
// the answer has to be checked against something. The caller only accepts it if
// it is one of the keys this agent was built with, so a page claiming to hold
// some other key gets a signature that does not verify rather than one it could
// pass on.
type SolanaAsk func(req SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error)

// SolanaTx is the transaction half of the agent.
type SolanaTx struct {
	// Ask reaches a wallet. When it is set the wallet signs.
	Ask SolanaAsk

	// Build makes an unsigned transaction, for an agent whose key is local.
	// Used when Ask is nil.
	Build SolanaBuild

	// MaxInstructions bounds what one request may ask for. It is a sanity
	// limit on a message size, not a policy: the wallet sees the result
	// either way.
	MaxInstructions int
}

// Limits on a request, well above anything an ordinary transaction needs and
// well below anything worth relaying.
const (
	solanaMaxRequest      = 64 << 10
	solanaDefaultMaxInstr = 64
	solanaMaxAccounts     = 64
)

func (t *SolanaTx) maxInstructions() int {
	if t.MaxInstructions > 0 {
		return t.MaxInstructions
	}
	return solanaDefaultMaxInstr
}

// ParseSolanaTxRequest reads and checks a request.
//
// Strictness here is about refusing to relay nonsense, not about deciding what
// is safe: every field is checked to be well formed and within bounds, and the
// judgement about whether the transaction should be signed is left to the
// wallet, which is the one party that can show it to a person.
// SolanaMemoProgramV2 is the address of the SPL Memo v2 program. The
// only thing it does is log the data it is invoked with, and the only
// account it takes is the signer - which the wallet always adds itself,
// so the request can carry an empty accounts list without losing
// information about who is signing.
const SolanaMemoProgramV2 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

// isNoAccountProgram reports whether a program ID names an instruction
// the wallet fills the signer for, so an empty accounts list on the wire
// does not mean the wallet does not know who is signing.
func isNoAccountProgram(programID string) bool {
	return programID == SolanaMemoProgramV2
}

func ParseSolanaTxRequest(contents []byte) (SolanaTxRequest, error) {
	var req SolanaTxRequest

	if len(contents) == 0 || len(contents) > solanaMaxRequest {
		return req, fmt.Errorf("a transaction request is %d bytes", len(contents))
	}

	dec := json.NewDecoder(bytes.NewReader(contents))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("the transaction request is not readable: %w", err)
	}

	if len(req.Instructions) == 0 {
		return req, errors.New("a transaction request carries no instructions")
	}
	if len(req.Instructions) > solanaDefaultMaxInstr {
		return req, fmt.Errorf("a transaction request carries %d instructions", len(req.Instructions))
	}
	if _, err := siws.Base58Decode(req.Blockhash); err != nil {
		return req, fmt.Errorf("the blockhash is not a base58 value: %w", err)
	}

	for i, in := range req.Instructions {
		if _, err := siws.Base58Decode(in.ProgramID); err != nil {
			return req, fmt.Errorf("instruction %d names a program that is not base58", i)
		}
		// Programs that take only the signer (Memo v2 today) accept an empty
		// accounts list because the wallet fills the signer itself. Anything
		// else still has to name its accounts up front, since a missing one
		// is a regression of the request shape rather than something the
		// wallet can recover from.
		if len(in.Accounts) == 0 && !isNoAccountProgram(in.ProgramID) {
			return req, fmt.Errorf("instruction %d names no accounts", i)
		}
		if len(in.Accounts) > solanaMaxAccounts {
			return req, fmt.Errorf("instruction %d names %d accounts", i, len(in.Accounts))
		}
		for j, account := range in.Accounts {
			if _, err := siws.Base58Decode(account.Address); err != nil {
				return req, fmt.Errorf("instruction %d account %d is not base58", i, j)
			}
		}
		if _, err := siws.Base58Decode(in.DataBase58); err != nil {
			return req, fmt.Errorf("instruction %d has data that is not base58", i)
		}
	}
	return req, nil
}

// VerifySolanaTx checks a signature against the transaction it came with.
//
// The wallet signs a message, not a transaction, and the message is the part
// of a signed transaction after the signatures. Checking that the signature
// verifies over those bytes is what makes the two halves belong together: it
// catches a signature that belongs to some other message, a signed transaction
// that was altered between the wallet and here, and a response whose signature
// field disagrees with the one actually in the transaction.
func VerifySolanaTx(resp SolanaTxResponse, signer ed25519.PublicKey) error {
	if len(resp.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("the wallet returned a %d byte signature, want %d",
			len(resp.Signature), ed25519.SignatureSize)
	}
	if len(resp.SignedTransaction) == 0 {
		return errors.New("the wallet returned no signed transaction")
	}

	signatures, message, err := splitSolanaTransaction(resp.SignedTransaction)
	if err != nil {
		return err
	}

	// A single signer, and it has to be the wallet that signed: a transaction
	// carrying anyone else's signature is not this wallet's transaction.
	if len(signatures) != 1 {
		return fmt.Errorf("a signed transaction carries %d signatures, want 1", len(signatures))
	}
	if !bytes.Equal(signatures[0], resp.Signature) {
		return errors.New("the signature does not match the one in the transaction")
	}
	if !ed25519.Verify(signer, message, signatures[0]) {
		return errors.New("the signature does not verify against the wallet's key")
	}
	return nil
}

// splitSolanaTransaction separates a signed transaction into its signatures
// and the message they cover.
//
// The layout is fixed and shallow: a compact-u16 count, that many 64-byte
// signatures, and then the message. Nothing here needs to understand Solana,
// which is the point - the serialisation is done in the page by the library
// that is meant to, and this only has to find the boundary.
func splitSolanaTransaction(signed []byte) (signatures [][]byte, message []byte, err error) {
	count, rest, err := readCompactU16(signed)
	if err != nil {
		return nil, nil, fmt.Errorf("the transaction is not readable: %w", err)
	}
	if count == 0 {
		return nil, nil, errors.New("the transaction carries no signature")
	}

	signed = rest
	need := count * ed25519.SignatureSize
	if len(signed) < need {
		return nil, nil, fmt.Errorf("the transaction claims %d signatures but is %d bytes", count, len(signed))
	}
	for i := range count {
		signatures = append(signatures, signed[i*ed25519.SignatureSize:(i+1)*ed25519.SignatureSize])
	}
	return signatures, signed[need:], nil
}

// readCompactU16 reads Solana's compact-u16: seven bits per byte, low first,
// with the high bit marking continuation.
//
// It is here rather than pulled from a library because it is eight lines and
// everything built on it is a fixed-length split. A malformed value is bounded
// rather than trusted, so a bad one costs a refusal and nothing else.
func readCompactU16(b []byte) (value int, rest []byte, err error) {
	for i := 0; i < len(b); i++ {
		if i >= 3 {
			// Three bytes is the most a compact-u16 can be, and the message
			// count in a transaction is small; anything longer is not a
			// transaction.
			return 0, nil, errors.New("the value is longer than a compact-u16 can be")
		}
		if i == 0 && b[0] == 0 {
			return 0, b[1:], nil
		}
		value |= int(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			return value, b[i+1:], nil
		}
	}
	return 0, nil, errors.New("the value ends before it does")
}

// ExtensionHandler builds the agent's Extension method.
//
// Anything the agent is asked that is not ours is refused with the error the
// protocol specifies, so a standard tool asking for something it does not
// understand gets a plain failure rather than silence. That matters here: an
// agent that answered every extension the same way would be indistinguishable
// from one that had no idea what was being asked.
func (t *SolanaTx) ExtensionHandler(signer gossh.Signer) func(name string, contents []byte) ([]byte, error) {
	return func(name string, contents []byte) ([]byte, error) {
		if name != SolanaTxExtension {
			return nil, agent.ErrExtensionUnsupported
		}
		if t == nil || (t.Ask == nil && t.Build == nil) {
			return nil, errors.New("this agent cannot sign Solana transactions: " +
				"there is no wallet behind it and no key here to sign with")
		}

		req, err := ParseSolanaTxRequest(contents)
		if err != nil {
			return json.Marshal(SolanaTxResponse{Refusal: err.Error()})
		}
		if len(req.Instructions) > t.maxInstructions() {
			return json.Marshal(SolanaTxResponse{
				Refusal: fmt.Sprintf("a transaction request carries %d instructions, the limit is %d",
					len(req.Instructions), t.maxInstructions()),
				Payer:   walletPayer(signer),
			})
		}

		// Where the key is decides who signs. A wallet behind the page is
		// asked; a key this process already holds - the one an SSH session
		// authenticates with - signs here, because it is the same kind of key
		// and refusing it on the grounds that it did not come from a wallet
		// would be refusing arithmetic.
		if t.Ask != nil {
			resp, used, err := t.Ask(req)
			if err != nil {
				return json.Marshal(SolanaTxResponse{
					Refusal: fmt.Sprintf("the wallet did not sign: %v", err),
					Payer:   walletPayer(signer),
				})
			}
			if used == nil || !bytes.Equal(used, ownPublicKey(signer)) {
				return json.Marshal(SolanaTxResponse{
					Refusal: "the answer was signed by a key this agent does not hold",
					Payer:   walletPayer(signer),
				})
			}
			if err := VerifySolanaTx(resp, ownPublicKey(signer)); err != nil {
				return json.Marshal(SolanaTxResponse{Refusal: err.Error(), Payer: walletPayer(signer)})
			}
			if resp.Payer == "" {
				resp.Payer = walletPayer(signer)
			}
			return json.Marshal(resp)
		}

		if signer == nil {
			return json.Marshal(SolanaTxResponse{
				Refusal: "this session has nothing that can sign a transaction: " +
					"connect a wallet, or give the session a key",
				Payer:   walletPayer(signer),
			})
		}

		// A transaction is paid for by the account that signs it. When this
		// agent is the one signing, that account is known here and nowhere
		// else - the page has no idea which key the session authenticated
		// with - so it is filled in rather than asked for.
		if req.Payer == "" {
			if pub := ownPublicKey(signer); pub != nil {
				req.Payer = siws.Base58Encode(pub)
			}
		}

		// Built elsewhere, signed here. The page builds it because the
		// serialisation belongs to the library that tracks Solana's format;
		// the signature belongs here because the key is here.
		built, err := t.Build(req)
		if err != nil {
			return json.Marshal(SolanaTxResponse{Refusal: err.Error(), Payer: walletPayer(signer)})
		}
		signatures, message, err := splitSolanaTransaction(built)
		if err != nil {
			return json.Marshal(SolanaTxResponse{Refusal: err.Error(), Payer: walletPayer(signer)})
		}

		signed, err := signer.Sign(rand.Reader, message)
		if err != nil {
			return json.Marshal(SolanaTxResponse{
				Refusal: "the session key could not sign: " + err.Error(),
				Payer:   walletPayer(signer),
			})
		}

		out := append([]byte{byte(len(signatures))}, signed.Blob...)
		return json.Marshal(SolanaTxResponse{
			Payer:            walletPayer(signer),
			Signature:         signed.Blob,
			SignedTransaction: append(out, message...),
		})
	}
}

// WithSolana attaches the transaction extension to a keyring.
//
// It is separate from Keyring because it needs a way to reach a wallet, and a
// keyring on its own is just a list of signers. A keyring without it refuses
// the extension, which is the same thing it would have done anyway.
func WithSolana(ring Agent, ask SolanaAsk, build SolanaBuild) error {
	kr, ok := ring.(*keyring)
	if !ok {
		return errors.New("this agent does not support extensions")
	}
	kr.solana = &SolanaTx{
		Ask:   ask,
		Build: build,
	}
	return nil
}
