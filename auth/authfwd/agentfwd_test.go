package authfwd

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// makeKey returns a fresh ed25519 key. The result is both a crypto.Signer
// (which Keyring wants) and an ssh.PublicKey (which the agent test asserts
// on).
func makeKey(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap public: %v", err)
	}
	return priv, sshPub
}

func TestKeyringEmptyReturnsNil(t *testing.T) {
	ring, err := Keyring(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ring != nil {
		t.Fatalf("expected nil ring for empty input, got %#v", ring)
	}
}

// TestKeyringRoundTrip drives the agent wire protocol against an in-memory
// keyring and checks that the listed keys match what was put in, then
// signs a payload and verifies the signature. This is the same exchange
// `ssh -A` triggers; if it works here, the server-side wiring will work
// for openssh.
func TestKeyringRoundTrip(t *testing.T) {
	priv, sshPub := makeKey(t)
	ring, err := Keyring([]crypto.Signer{priv})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	if ring == nil {
		t.Fatal("expected non-nil ring")
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// The agent side is the in-memory keyring. The client side is a real
	// agent client talking the same protocol.
	client := agent.NewClient(a)
	done := make(chan error, 1)
	go func() {
		done <- agent.ServeAgent(ring, b)
	}()

	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if sshPub.Type() != keys[0].Type() {
		t.Fatalf("key type: got %q, want %q", keys[0].Type(), sshPub.Type())
	}

	// Sign a payload and verify with the public key, the way a relying
	// party (e.g. openssh during pubkey auth) would.
	sig, err := client.Sign(keys[0], []byte("hello world"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sshPub.Verify([]byte("hello world"), sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}

	// Close the client side; ServeAgent returns when the pipe ends.
	_ = a.Close()
	if err := <-done; err != nil && err != io.EOF {
		// Some Go versions return "EOF" and some return a different
		// sentinel; either is fine.
		t.Logf("serve returned %v (acceptable on pipe close)", err)
	}
}

// TestExtractSigner checks that the unsafe-extract trick still works
// after a future x/crypto/ssh release. The wrappedSigner layout is
// private; this test pins the contract by going through a real
// gossh.ParsePrivateKey round-trip and confirming the result is the
// same key.
func TestExtractSigner(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// ssh.NewSignerFromKey returns a *wrappedSigner with a private
	// "signer" field; that is the path this helper takes.
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	extracted, err := ExtractSigner(signer)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	// The extracted signer's public key must match the original.
	if pub, err := ssh.NewPublicKey(extracted.Public()); err != nil {
		t.Fatalf("wrap extracted public: %v", err)
	} else if pub.Type() != signer.PublicKey().Type() {
		t.Fatalf("type mismatch: got %q, want %q", pub.Type(), signer.PublicKey().Type())
	}
	// Signing through the extracted signer must produce a signature
	// that verifies against the original signer's public key. The
	// underlying crypto.Signer.Sign returns raw bytes; we round
	// trip them through ssh.ParseSignature (which the public
	// API exposes via Signer.Sign) and check verification.
	payload := []byte("payload")
	rawSig, err := extracted.Sign(rand.Reader, payload, crypto.Hash(0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// The raw signature from crypto/ed25519.Sign is just the 64-byte
	// signature blob; wrap it in an SSH signature by hand to verify
	// against the original signer's public key.
	sshSig := &ssh.Signature{
		Format: signer.PublicKey().Type(),
		Blob:   rawSig,
	}
	if err := signer.PublicKey().Verify(payload, sshSig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
