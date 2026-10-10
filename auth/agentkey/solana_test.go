package agentkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/btwiuse/wssh/auth/siws"
	gossh "golang.org/x/crypto/ssh"

	"golang.org/x/crypto/ssh/agent"
)

// A request a session might send, in the shape it goes over the wire.
func testRequest(t *testing.T) SolanaTxRequest {
	t.Helper()
	return SolanaTxRequest{
		Blockhash: "9xQeVvM816uMixesDjoeL7PkZn7W5jNf1WnokxBfXmG",
		Label:     "pay an invoice",
		Instructions: []SolanaInstruction{{
			ProgramID:  "11111111111111111111111111111111",
			Accounts:   []SolanaAccount{{Address: "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5", IsWritable: true}},
			DataBase58: "3Bxs4NN24MbuWbgFAG5oEpC9AQeTcegpnKnpBzgUEBQtUBAGHShAmQwsdxoAtp4C",
		}},
	}
}

func marshalRequest(t *testing.T, req SolanaTxRequest) []byte {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

// A transaction is laid out as a compact-u16 count, that many 64-byte
// signatures, then the message. Building one here is the whole of what the
// agent needs to know about the format.
func buildSignedTransaction(pub ed25519.PublicKey, priv ed25519.PrivateKey, message []byte) []byte {
	out := []byte{1} // one signature
	out = append(out, ed25519.Sign(priv, message)...)
	return append(out, message...)
}

// The happy path, end to end: a request goes in, a signed transaction comes
// out, and the signature checks out against the message it covers.
func TestSolanaExtensionSignsATransaction(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ring, _ := mustKeyring(t, priv)

	var asked SolanaTxRequest
	if err := WithSolana(ring, func(req SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error) {
		asked = req
		message := []byte("a transaction message, whatever the page built")
		return SolanaTxResponse{
			Signature:         ed25519.Sign(priv, message),
			SignedTransaction: buildSignedTransaction(pub, priv, message),
		}, pub, nil
	}, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	raw, err := ring.Extension(SolanaTxExtension, marshalRequest(t, testRequest(t)))
	if err != nil {
		t.Fatalf("extension: %v", err)
	}

	var got SolanaTxResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("response is not readable: %v", err)
	}
	if len(got.Signature) != ed25519.SignatureSize {
		t.Errorf("signature is %d bytes", len(got.Signature))
	}
	if asked.Blockhash != testRequest(t).Blockhash {
		t.Errorf("the wallet was asked about a different transaction: %+v", asked)
	}
	if _, message, err := splitSolanaTransaction(got.SignedTransaction); err != nil {
		t.Fatalf("split: %v", err)
	} else if !ed25519.Verify(pub, message, got.Signature) {
		t.Error("the signature does not verify against the message it came with")
	}
}

// An agent that cannot sign a transaction says so plainly rather than
// answering the extension with something a caller might mistake for a result.
func TestExtensionWithoutAWalletIsRefused(t *testing.T) {
	ring, _ := mustKeyring(t)
	_, err := ring.Extension(SolanaTxExtension, marshalRequest(t, testRequest(t)))
	if !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Fatalf("got %v, want ErrExtensionUnsupported", err)
	}
}

// Anything that is not ours is refused with the error the protocol specifies.
// An agent that answered every extension alike would look to a standard tool
// like one that had no idea what it was being asked.
func TestUnknownExtensionIsRefused(t *testing.T) {
	ring, _ := mustKeyring(t)
	if err := WithSolana(ring, func(SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error) {
		t.Fatal("the wallet should not have been asked about an unknown extension")
		return SolanaTxResponse{}, nil, nil
	}, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	for _, name := range []string{"", "something-else", "solana-tx", SolanaTxExtension + " "} {
		if _, err := ring.Extension(name, nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
			t.Errorf("%q: got %v, want ErrExtensionUnsupported", name, err)
		}
	}
}

// The signature is checked against the message it arrived with, so a caller
// cannot be handed a signature that belongs to some other message.
func TestExtensionRejectsASignatureForAnotherMessage(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)

	ring, _ := mustKeyring(t, priv)
	if err := WithSolana(ring, func(SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error) {
		other := []byte("a completely different message")
		return SolanaTxResponse{
			Signature:         ed25519.Sign(strangerPriv, other),
			SignedTransaction: buildSignedTransaction(pub, strangerPriv, other),
		}, pub, nil
	}, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	got := mustRefuse(t, ring, marshalRequest(t, testRequest(t)))
	if !strings.Contains(got, "verify") {
		t.Errorf("the refusal should say the signature does not verify, got %q", got)
	}
}

// The answer has to come from a key this agent actually holds, or a page could
// hand back a signature by a key it does not have and have it believed.
func TestExtensionRejectsAKeyWeDoNotHold(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)

	ring, _ := mustKeyring(t, priv)
	if err := WithSolana(ring, func(SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error) {
		message := []byte("a message")
		return SolanaTxResponse{
			Signature:         ed25519.Sign(otherPriv, message),
			SignedTransaction: buildSignedTransaction(otherPub, otherPriv, message),
		}, otherPub, nil
	}, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	got := mustRefuse(t, ring, marshalRequest(t, testRequest(t)))
	if !strings.Contains(got, "does not hold") {
		t.Errorf("the refusal should name the problem, got %q", got)
	}
}

// A transaction carrying someone else's signature alongside is not this
// wallet's transaction, even though one of the signatures is ours.
func TestVerifyRejectsAMultiSignedTransaction(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("a message")

	signed := []byte{2}
	signed = append(signed, ed25519.Sign(priv, message)...)
	signed = append(signed, ed25519.Sign(priv, message)...)
	signed = append(signed, message...)

	err := VerifySolanaTx(SolanaTxResponse{
		Signature:         ed25519.Sign(priv, message),
		SignedTransaction: signed,
	}, pub)
	if err == nil || !strings.Contains(err.Error(), "signatures") {
		t.Fatalf("got %v, want a refusal about the signature count", err)
	}
}

// The signature field and the signature in the transaction have to be the same
// one. A caller reading only the field would otherwise be told something the
// transaction does not agree with.
func TestVerifyRejectsAMismatchedSignatureField(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("a message")

	err := VerifySolanaTx(SolanaTxResponse{
		Signature:         ed25519.Sign(otherPriv, message),
		SignedTransaction: buildSignedTransaction(pub, priv, message),
	}, pub)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("got %v, want a refusal about the mismatch", err)
	}
}

func TestSplitSolanaTransaction(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("the message being covered")
	sig := ed25519.Sign(priv, message)

	// Compact-u16 encodes small values in one byte, so one signature is 0x01.
	signed := append([]byte{1}, sig...)
	signed = append(signed, message...)

	signatures, got, err := splitSolanaTransaction(signed)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(signatures) != 1 || string(signatures[0]) != string(sig) {
		t.Fatalf("signatures came back wrong: %x", signatures)
	}
	if string(got) != string(message) {
		t.Errorf("message came back as %q", got)
	}

	// A count that runs past the end of the buffer is refused rather than
	// read out of bounds, however plausible it looks.
	if _, _, err := splitSolanaTransaction([]byte{1, 2, 3}); err == nil {
		t.Error("a truncated transaction should not have split")
	}
	if _, _, err := splitSolanaTransaction([]byte{0, 1, 2}); err == nil {
		t.Error("a transaction with no signature should not have split")
	}
	if _, _, err := splitSolanaTransaction(nil); err == nil {
		t.Error("nothing at all should not have split")
	}
}

// A request has to be readable and well formed before it goes anywhere near a
// wallet. Every field is checked; none of them decides whether the transaction
// should be signed, which is the wallet's business.
func TestParseSolanaTxRequestRefusesWhatItCannotRead(t *testing.T) {
	good := marshalRequest(t, testRequest(t))

	bad := map[string][]byte{
		"nothing":            nil,
		"not json":           []byte("please sign this"),
		"a json array":       []byte("[]"),
		"unknown field":      []byte(`{"blockhash":"2","instructions":[],"sneaky":1}`),
		"no instructions":    []byte(`{"blockhash":"2","instructions":[]}`),
		"bad blockhash":      []byte(`{"blockhash":"not base58 0O","instructions":[{"programId":"2","accounts":[{"address":"2"}],"data":"2"}]}`),
		"bad program":        []byte(`{"blockhash":"2","instructions":[{"programId":"0Ol","accounts":[{"address":"2"}],"data":"2"}]}`),
		"no accounts":        []byte(`{"blockhash":"2","instructions":[{"programId":"2","accounts":[],"data":"2"}]}`),
		"bad account":        []byte(`{"blockhash":"2","instructions":[{"programId":"2","accounts":[{"address":"0Ol"}],"data":"2"}]}`),
		"bad data":           []byte(`{"blockhash":"2","instructions":[{"programId":"2","accounts":[{"address":"2"}],"data":"I0"}]}`),
		"an empty field":     []byte(`{"blockhash":"","instructions":[{"programId":"2","accounts":[{"address":"2"}],"data":"2"}]}`),
		"a null instruction": []byte(`{"blockhash":"2","instructions":[null]}`),
	}
	for name, body := range bad {
		if _, err := ParseSolanaTxRequest(body); err == nil {
			t.Errorf("%s should not have parsed", name)
		}
	}

	if _, err := ParseSolanaTxRequest(good); err != nil {
		t.Errorf("a well formed request was refused: %v", err)
	}
}

// A request is bounded on size, so a session cannot make the browser hold an
// arbitrarily large message while it waits for someone to read it.
func TestParseSolanaTxRequestBoundsSize(t *testing.T) {
	huge := append([]byte(`{"blockhash":"2","instructions":[{"programId":"2","accounts":[{"address":"2"}],"data":"`), make([]byte, solanaMaxRequest)...)
	huge = append(huge, []byte(`"}]}`)...)

	if _, err := ParseSolanaTxRequest(huge); err == nil {
		t.Error("an enormous request should have been refused")
	}
}

// The instruction count is a sanity limit, not a policy, and it is checked
// before the wallet is disturbed.
func TestExtensionBoundsTheInstructionCount(t *testing.T) {
	ring, _ := mustKeyring(t)
	asked := false
	if err := WithSolana(ring, func(SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error) {
		asked = true
		return SolanaTxResponse{}, nil, nil
	}, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}
	// The limit is a sanity bound rather than a knob, so it is set here rather
	// than configured: sixty-five instructions is more than anything real.
	ring.solana.MaxInstructions = 2

	req := testRequest(t)
	req.Instructions = append(req.Instructions, req.Instructions[0], req.Instructions[0])

	raw, err := ring.Extension(SolanaTxExtension, marshalRequest(t, req))
	if err != nil {
		t.Fatalf("an over-large request should be an answer: %v", err)
	}
	var got SolanaTxResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("answer is not readable: %v", err)
	}
	if !strings.Contains(got.Refusal, "the limit is 2") {
		t.Errorf("the answer should say the request was over the limit, got %q", got.Refusal)
	}
	if asked {
		t.Error("the wallet should not have been disturbed by an over-large request")
	}
}

// mustKeyring builds a one-key ring from the private keys given, or from a
// fresh one. The matching public keys come back so a test can sign and verify
// with the same key the ring holds.
func mustKeyring(t *testing.T, privs ...ed25519.PrivateKey) (*keyring, []ed25519.PublicKey) {
	t.Helper()

	var signers []gossh.Signer
	var pubs []ed25519.PublicKey
	for _, priv := range privs {
		signer, err := gossh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		signers = append(signers, signer)
		pubs = append(pubs, priv.Public().(ed25519.PublicKey))
	}
	if len(signers) == 0 {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		signer, err := gossh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		signers, pubs = []gossh.Signer{signer}, []ed25519.PublicKey{pub}
	}

	ring, err := Keyring(signers)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	kr, ok := ring.(*keyring)
	if !ok {
		t.Fatalf("keyring is %T", ring)
	}
	return kr, pubs
}

// The agent protocol drops the reason an extension was refused: it answers
// with a single byte. Carrying the reason in the answer instead is the only
// way the person who asked ever hears it.
func TestExtensionCarriesTheReasonInTheAnswer(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ring, _ := mustKeyring(t, priv)

	if err := WithSolana(ring, func(SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error) {
		return SolanaTxResponse{}, nil, errors.New("the user closed the wallet prompt")
	}, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	raw, err := ring.Extension(SolanaTxExtension, marshalRequest(t, testRequest(t)))
	if err != nil {
		t.Fatalf("a refusal should be an answer, not a failure: %v", err)
	}

	var got SolanaTxResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("answer is not readable: %v", err)
	}
	if !strings.Contains(got.Refusal, "closed the wallet prompt") {
		t.Errorf("the reason did not survive: %q", got.Refusal)
	}
	if len(got.SignedTransaction) != 0 {
		t.Error("a refusal should carry no transaction")
	}
}

// A malformed request is the caller's mistake, and it is answered rather than
// thrown: a failure code would lose the sentence saying what was wrong with
// it.
func TestExtensionAnswersAMalformedRequest(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ring, _ := mustKeyring(t, priv)
	if err := WithSolana(ring, func(SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error) {
		t.Error("the wallet should not have been asked about a malformed request")
		return SolanaTxResponse{}, nil, nil
	}, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	raw, err := ring.Extension(SolanaTxExtension, []byte(`{"blockhash":"2","instructions":[]}`))
	if err != nil {
		t.Fatalf("a malformed request should be an answer: %v", err)
	}
	var got SolanaTxResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("answer is not readable: %v", err)
	}
	if !strings.Contains(got.Refusal, "no instructions") {
		t.Errorf("the reason should say what was wrong, got %q", got.Refusal)
	}
}

// mustRefuse runs the extension and returns the reason it gave for saying no.
//
// Refusals arrive as answers rather than errors, because the agent protocol
// drops the reason from an error. A test that only checked that something came
// back would pass on a refusal that said nothing, which for the checks below is
// the whole point.
func mustRefuse(t *testing.T, ring *keyring, body []byte) string {
	t.Helper()

	raw, err := ring.Extension(SolanaTxExtension, body)
	if err != nil {
		t.Fatalf("a refusal should be an answer, not a failure: %v", err)
	}
	var got SolanaTxResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("answer is not readable: %v", err)
	}
	if got.Refusal == "" {
		t.Fatal("expected a refusal, got a signed transaction")
	}
	if len(got.SignedTransaction) != 0 {
		t.Error("a refusal must not carry a transaction")
	}
	return got.Refusal
}

// An agent whose key is local signs the transaction itself.
//
// There is nothing wallet-specific about an ed25519 key: the one an SSH
// session authenticates with is the same kind of key as the one a Solana
// wallet holds, and the account that pays the fee is the same thing as the
// account that signs. Refusing on the grounds that the key did not come from
// a wallet would be refusing arithmetic.
func TestLocalKeySignsWithoutAWallet(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ring, _ := mustKeyring(t, priv)

	message := []byte("a transaction message the page built")
	unsigned := append([]byte{1}, make([]byte, ed25519.SignatureSize)...)
	unsigned = append(unsigned, message...)

	// No wallet behind this: the transaction comes back built and is signed
	// here.
	if err := WithSolana(ring, nil, func(SolanaTxRequest) ([]byte, error) {
		return unsigned, nil
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	raw, err := ring.Extension(SolanaTxExtension, marshalRequest(t, testRequest(t)))
	if err != nil {
		t.Fatalf("extension: %v", err)
	}

	var got SolanaTxResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("answer is not readable: %v", err)
	}
	if got.Refusal != "" {
		t.Fatalf("a local key should have signed, got %q", got.Refusal)
	}
	if err := VerifySolanaTx(got, pub); err != nil {
		t.Fatalf("the locally signed transaction did not verify: %v", err)
	}

	// And it covers the message the page built, byte for byte.
	signatures, covered, err := splitSolanaTransaction(got.SignedTransaction)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if string(covered) != string(message) {
		t.Errorf("the signature covers %q, want %q", covered, message)
	}
	if !ed25519.Verify(pub, covered, signatures[0]) {
		t.Error("the signature does not verify over what it claims to cover")
	}
}

// An agent with a key and no way to build a transaction still cannot sign one,
// and says which of the two it is rather than looking like an agent that has
// never heard of transactions.
func TestAgentWithNothingToBuildWithRefuses(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ring, _ := mustKeyring(t, priv)

	if err := WithSolana(ring, nil, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Nothing behind it and nothing here to sign with: that has to come back
	// as a failure code rather than an answer, because there is nothing this
	// agent could ever do with the request.
	if _, err := ring.Extension(SolanaTxExtension, marshalRequest(t, testRequest(t))); err == nil {
		t.Fatal("an agent that can do neither should not have answered")
	}
}

// The payer is whoever signs, and when the session's own key is the signer
// the agent already knows that. Asking for it makes the caller repeat back
// something the answer to a previous question already established.
func TestPayerDefaultsToTheSigningKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ring, _ := mustKeyring(t, priv)

	message := []byte("a message")
	unsigned := append([]byte{1}, make([]byte, ed25519.SignatureSize)...)
	unsigned = append(unsigned, message...)

	var asked SolanaTxRequest
	if err := WithSolana(ring, nil, func(req SolanaTxRequest) ([]byte, error) {
		asked = req
		return unsigned, nil
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	raw, err := ring.Extension(SolanaTxExtension, marshalRequest(t, testRequest(t)))
	if err != nil {
		t.Fatalf("extension: %v", err)
	}
	var got SolanaTxResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("answer is not readable: %v", err)
	}
	if got.Refusal != "" {
		t.Fatalf("expected a signature, got %q", got.Refusal)
	}

	want := Base58EncodeForTest(t, pub)
	if asked.Payer != want {
		t.Errorf("payer came back as %q, want the signing key %q", asked.Payer, want)
	}
}

// A payer that was named is left alone: the caller may be paying for someone
// else, which is the whole reason the field exists.
func TestAnExplicitPayerIsNotOverridden(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ring, _ := mustKeyring(t, priv)

	message := []byte("a message")
	unsigned := append([]byte{1}, make([]byte, ed25519.SignatureSize)...)
	unsigned = append(unsigned, message...)

	var asked SolanaTxRequest
	if err := WithSolana(ring, nil, func(req SolanaTxRequest) ([]byte, error) {
		asked = req
		return unsigned, nil
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	req := testRequest(t)
	req.Payer = "someone-else"
	if _, err := ring.Extension(SolanaTxExtension, marshalRequest(t, req)); err != nil {
		t.Fatalf("extension: %v", err)
	}
	if asked.Payer != "someone-else" {
		t.Errorf("an explicit payer was replaced with %q", asked.Payer)
	}
}

func Base58EncodeForTest(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	return siws.Base58Encode(pub)
}
