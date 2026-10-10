package agentkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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

// WalletCommentPrefix labels a key that came out of a connected wallet, as
// `solana:<address>`.
//
// It lives here rather than in the browser client because both sides have to
// agree on it: the client writes it, and a command reading the agent's key
// list looks for it to tell which of the keys a wallet will be asked to sign
// with. A label only one side knows about is one side can read and the other
// cannot.
//
// The address is part of the label because a comment is the only part of a
// line that survives being pasted into authorized_keys. And `solana:` rather
// than `wallet:` because ed25519 is not Solana's - Sui and Near wallets are on
// the same curve - so the prefix says what the address is *in*, which is the
// part a reader cannot work out from the string itself.
const WalletCommentPrefix = "solana:"

// IsWalletComment reports whether a key comment is one of ours, naming the
// connected wallet's account.
func IsWalletComment(comment string) bool {
	return strings.HasPrefix(comment, WalletCommentPrefix)
}

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

	// Signer is the account whose key must sign this transaction: which key
	// in the agent should be used. Empty means nobody named one, and a
	// connected wallet picks.
	//
	// It was called Payer, and that conflated two roles the field was
	// answering. It decides *who signs*; the fee payer follows from it
	// because Solana requires the fee payer to be a required signer - not
	// the other way round, and not because the caller said so. Naming a
	// signer is the question a caller actually has; the account that ends
	// up paying is a consequence.
	Signer string `json:"signer,omitempty"`

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
// payerIsLocal reports whether the request names a payer that this agent can
// sign with itself, rather than one only the wallet can.
//
// The three cases, and none of them is a guess:
//
//   - no payer named: the wallet is asked, as it always was.
//   - the payer is the wallet's own key: the wallet is asked, because that
//     key's private half is on the far side of a bridge and the only way to
//     use it is to show a person the transaction.
//   - the payer is some other key this agent holds: signed here. An ed25519
//     key is an ed25519 key whatever it was made for, and the transaction is
//     built by the page - the serialisation belongs to the library that
//     tracks the chain - and signed on this side.
func (t *SolanaTx) payerIsLocal(req SolanaTxRequest, signers []gossh.Signer) bool {
	if req.Signer == "" || t.Wallet == nil {
		return false
	}
	raw, err := siws.Base58Decode(req.Signer)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return false
	}
	// Not the wallet's, so if this agent holds it, it can sign for itself.
	return !bytes.Equal(raw, t.Wallet)
}

// signerForAddress is the signer holding a named base58 account.
func signerForAddress(signers []gossh.Signer, address string) (gossh.Signer, bool) {
	raw, err := siws.Base58Decode(address)
	if err != nil {
		return nil, false
	}
	return signerHolding(signers, raw)
}

// signerHolding is the signer in signers whose public key is the one given.
//
// Asking "is this key one of ours" rather than "which one is it" is what
// lets an agent hold more than one key while a wallet is connected: the
// wallet decides, and this only has to agree.
func signerHolding(signers []gossh.Signer, pub ed25519.PublicKey) (gossh.Signer, bool) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, false
	}
	for _, s := range signers {
		if s == nil {
			continue
		}
		if got := ownPublicKey(s); got != nil && bytes.Equal(got, pub) {
			return s, true
		}
	}
	return nil, false
}

// noSignerRefusal is why nothing here can sign, said in a sentence that will
// survive the trip. Counted rather than described, because "this session has
// nothing that can sign" is true of zero and of three, and the fix is
// different for each.
func noSignerRefusal(held int) string {
	switch held {
	case 0:
		return "this session has nothing that can sign a transaction: " +
			"connect a wallet, or give the session a key"
	case 1:
		// Unreachable from here, but a wrong count would read as a bug in
		// the check rather than as a real state.
		return "this session holds one key, which cannot sign without a wallet"
	default:
		return fmt.Sprintf(
			"this session holds %d keys and no wallet to choose between them: "+
				"connect a wallet, or leave exactly one key in the session", held)
	}
}

func ownPublicKey(signer gossh.Signer) ed25519.PublicKey {
	crypto, ok := signer.PublicKey().(gossh.CryptoPublicKey)
	if !ok {
		return nil
	}
	pub, _ := crypto.CryptoPublicKey().(ed25519.PublicKey)
	return pub
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
	// Used when the payer names a key this agent holds that is not the
	// wallet's, and when there is no wallet at all.
	Build SolanaBuild

	// Wallet is which of the agent's keys the wallet holds, when there is a
	// wallet and it is known. The private half is on the far side of a
	// bridge, so this key can be signed with but only by asking: it is the
	// one key that must reach a person rather than being signed here.
	//
	// Nil when there is no wallet, or when a wallet is attached but its key
	// was not declared. A request that names a payer cannot be routed
	// reliably without it, so it goes to the wallet - which is the
	// conservative direction, being the one that asks a person.
	Wallet ed25519.PublicKey

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
		//
		// The wording names the agent rather than the wallet because the
		// browser-side builder has its own check with the same words. A
		// refusal that does not say which side produced it is one the reader
		// has to bisect by hand, and this one means the build in front of you
		// predates the carve-out.
		if len(in.Accounts) == 0 && !isNoAccountProgram(in.ProgramID) {
			return req, fmt.Errorf(
				"the agent refused instruction %d: it names no accounts, and only "+
					"the memo program may leave the accounts list empty", i)
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
func (t *SolanaTx) ExtensionHandler(signers []gossh.Signer) func(name string, contents []byte) ([]byte, error) {
	return func(name string, contents []byte) ([]byte, error) {
		if name != SolanaTxExtension {
			return nil, agent.ErrExtensionUnsupported
		}
		if t == nil || (t.Ask == nil && t.Build == nil) {
			return json.Marshal(SolanaTxResponse{
				Refusal: "this agent cannot sign Solana transactions: " +
					"there is no wallet behind it and no key here to sign with",
			})
		}

		req, err := ParseSolanaTxRequest(contents)
		if err != nil {
			return json.Marshal(SolanaTxResponse{Refusal: err.Error()})
		}
		if len(req.Instructions) > t.maxInstructions() {
			return json.Marshal(SolanaTxResponse{
				Refusal: fmt.Sprintf("a transaction request carries %d instructions, the limit is %d",
					len(req.Instructions), t.maxInstructions()),
			})
		}

		// Where the key is decides who signs. A wallet behind the page is
		// asked; a key this process already holds - the one an SSH session
		// authenticates with - signs here, because it is the same kind of key
		// and refusing it on the grounds that it did not come from a wallet
		// would be refusing arithmetic.
		//
		// A named payer decides which of the two, and it has to: a browser
		// forwards the imported SSH keys and the wallet in one agent, so
		// "there is a wallet" says nothing about who should sign. Asking the
		// wallet for a transaction that named somebody else's account would
		// hand back a signature over the wrong fee payer, and the caller
		// would have no way to tell.
		if t.Ask != nil && !t.payerIsLocal(req, signers) {
			// The wallet's key is here, so either the request named it or it
			// named nobody and the wallet picks. Either way there is nothing
			// to disambiguate: a browser that imported an SSH key and also
			// connected a wallet forwards both, and one key in an agent is
			// not a precondition for signing. What does have to be checked
			// is the answer - that it came from a key this agent actually
			// holds - which is a question about the reply rather than about
			// the request.
			resp, used, err := t.Ask(req)
			if err != nil {
				// Carried as it stands, not wrapped. The page already says
				// "the wallet did not sign" when that is what happened, and
				// prefixing it here again is how a refusal arrived as
				// "the wallet did not sign: the wallet did not sign: User
				// rejected the request." Worse, not every failure here is a
				// signing failure: "no fee payer: connect a wallet" is not,
				// and calling it one is simply false.
				return json.Marshal(SolanaTxResponse{Refusal: err.Error()})
			}
			signer, ok := signerHolding(signers, used)
			if !ok {
				return json.Marshal(SolanaTxResponse{
					Refusal: "the wallet signed with a key this agent does not hold",
				})
			}
			// A payer that was named has to be the one that signed. The
			// wallet picks its own account, and picking a different one from
			// the one asked for is an answer to a different question - the
			// caller would be handed a signature whose fee payer is not the
			// account it named, and nothing downstream could tell.
			if req.Signer != "" {
				wanted, held := signerForAddress(signers, req.Signer)
				if !held || !bytes.Equal(ownPublicKey(wanted), ownPublicKey(signer)) {
					return json.Marshal(SolanaTxResponse{
						Refusal: fmt.Sprintf(
							"the request named %s as the payer but the wallet signed with %s",
							req.Signer, siws.Base58Encode(used)),
					})
				}
			}
			if err := VerifySolanaTx(resp, ownPublicKey(signer)); err != nil {
				return json.Marshal(SolanaTxResponse{Refusal: err.Error()})
			}
			return json.Marshal(resp)
		}

		// Signing here. The payer says which key when it is named, which is
		// what makes several keys a normal case rather than a question this
		// cannot answer - the same reasoning as the plain-agent path in
		// solana/agentsign.go, which also takes the payer over the key
		// count.
		var signer gossh.Signer
		switch {
		case req.Signer != "":
			found, ok := signerForAddress(signers, req.Signer)
			if !ok {
				return json.Marshal(SolanaTxResponse{
					Refusal: fmt.Sprintf(
						"the payer %s is not a key this session holds; "+
							"sol-keys lists the ones it does", req.Signer),
				})
			}
			signer = found
		case len(signers) == 1:
			signer = signers[0]
		default:
			// With no payer there is nobody to choose an account, so
			// several keys is an unanswerable question rather than a normal
			// case. It is refused here, as a Refusal, rather than as a bare
			// error: a bare error becomes the single failure byte the agent
			// protocol allows and the sentence explaining it never reaches
			// the caller.
			return json.Marshal(SolanaTxResponse{
				Refusal: noSignerRefusal(len(signers)),
			})
		}

		// A transaction is paid for by the account that signs it. When this
		// agent is the one signing, that account is known here and nowhere
		// else - the page has no idea which key the session authenticated
		// with - so it is filled in rather than asked for.
		if req.Signer == "" {
			if pub := ownPublicKey(signer); pub != nil {
				req.Signer = siws.Base58Encode(pub)
			}
		}

		// Built elsewhere, signed here. The page builds it because the
		// serialisation belongs to the library that tracks Solana's format;
		// the signature belongs here because the key is here.
		built, err := t.Build(req)
		if err != nil {
			return json.Marshal(SolanaTxResponse{Refusal: err.Error()})
		}
		signatures, message, err := splitSolanaTransaction(built)
		if err != nil {
			return json.Marshal(SolanaTxResponse{Refusal: err.Error()})
		}

		signed, err := signer.Sign(rand.Reader, message)
		if err != nil {
			return json.Marshal(SolanaTxResponse{
				Refusal: "the session key could not sign: " + err.Error(),
			})
		}

		// One signature goes in here, so a transaction with room for more
		// cannot be filled. Filling the first slot and declaring the count
		// the page asked for produces a transaction that is short by whole
		// signatures, with the message glued to the end of the signature
		// region - and it produced no error at all, which is how a request
		// asking for two signers came back looking signed.
		//
		// The page can build one (it allocates a slot per signer); signing
		// one needs a key per signer, and every one of them has to be in
		// this agent. Until that is true, say so.
		if len(signatures) != 1 {
			return json.Marshal(SolanaTxResponse{
				Refusal: fmt.Sprintf(
					"this transaction needs %d signatures and only one key is here to sign with; "+
						"every required signer has to be in the agent", len(signatures)),
			})
		}

		out := append([]byte{1}, signed.Blob...)
		return json.Marshal(SolanaTxResponse{
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
func WithSolana(ring Agent, ask SolanaAsk, build SolanaBuild, wallet ed25519.PublicKey) error {
	kr, ok := ring.(*keyring)
	if !ok {
		return errors.New("this agent does not support extensions")
	}
	kr.solana = &SolanaTx{
		Ask:   ask,
		Build: build,
		// Which of the agent's keys is the wallet's. Needed because a
		// browser forwards the imported SSH keys and the wallet in one
		// agent, and a request naming its payer has to be routed to the
		// right one: the wallet's key goes to a person, anyone else's is
		// signed here. A nil wallet means "not known", and then a request
		// that names a payer cannot be told apart from one that does not,
		// so it goes to the wallet as before.
		Wallet: wallet,
	}
	return nil
}
