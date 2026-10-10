package agentkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// makeKey returns a fresh ed25519 key as the two things the rest of these
// tests need: the ssh.Signer a keyring holds, and the ssh.PublicKey a relying
// party verifies against.
func makeKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("wrap signer: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap public: %v", err)
	}
	return signer, sshPub
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

func TestKeyringRejectsNilSigner(t *testing.T) {
	if _, err := Keyring([]ssh.Signer{nil}); err == nil {
		t.Fatal("expected an error for a nil signer")
	}
}

// TestKeyringRoundTrip drives the agent wire protocol against an in-memory
// keyring and checks that the listed keys match what was put in, then signs a
// payload and verifies the signature. This is the exchange openssh performs
// against an agent, so if it holds here it holds over the SSH channel too.
func TestKeyringRoundTrip(t *testing.T) {
	signer, sshPub := makeKey(t)
	ring, err := Keyring([]ssh.Signer{signer})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// One end is the keyring speaking the agent protocol, the other a real
	// agent client speaking it back.
	client := agent.NewClient(a)
	done := make(chan error, 1)
	go func() { done <- agent.ServeAgent(ring, b) }()

	keys, err := client.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if got, want := keys[0].Type(), sshPub.Type(); got != want {
		t.Fatalf("key type: got %q, want %q", got, want)
	}

	sig, err := client.Sign(keys[0], []byte("hello world"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sshPub.Verify([]byte("hello world"), sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}

	_ = a.Close()
	if err := <-done; err != nil && err != io.EOF {
		t.Logf("serve returned %v (acceptable on pipe close)", err)
	}
}

// The comment is the only thing a session has to go on to tell two keys
// apart, so what the caller supplied has to arrive exactly. It used to be
// filled in with the algorithm name instead, which is information nothing
// can use: ssh-add prints the type in parentheses after the comment anyway,
// and sol-keys reports it as a field of its own.
func TestListCarriesTheSuppliedComment(t *testing.T) {
	signer, _ := makeKey(t)
	ring, err := KeyringWithComments([]Key{{
		Signer:  signer,
		Comment: "wallet@FRucBU2bikra3LVBGfuxgwrtHka7qiQUCUWH4A2kHFRz",
	}})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	keys, err := ring.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if got, want := keys[0].Comment, "wallet@FRucBU2bikra3LVBGfuxgwrtHka7qiQUCUWH4A2kHFRz"; got != want {
		t.Errorf("comment is %q, want %q", got, want)
	}
}

// A keyring built without comments says nothing rather than guessing. An
// invented label is worse than an absent one: it looks like the agent knows
// where the key came from, and a person reading it believes it.
func TestListSaysNothingWhenNoCommentWasGiven(t *testing.T) {
	signer, _ := makeKey(t)
	ring, err := Keyring([]ssh.Signer{signer})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	keys, err := ring.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Comment != "" {
		t.Errorf("comment is %q, want nothing rather than an invented label", keys[0].Comment)
	}
	if got, want := keys[0].Comment, keys[0].Type(); got == want {
		t.Errorf("the algorithm name is being used as a comment; that is the defect this replaces")
	}
}

// A key the server was not configured with must not be signable, or the
// keyring would be signing for identities it never agreed to hold.
func TestSignRejectsUnknownKey(t *testing.T) {
	signer, _ := makeKey(t)
	ring, err := Keyring([]ssh.Signer{signer})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	_, otherPub := makeKey(t)
	if _, err := ring.Sign(otherPub, []byte("payload")); err == nil {
		t.Fatal("expected a refusal to sign with a key that is not in the ring")
	}
}

// The keys are chosen by whoever starts the server, so a session must not be
// able to add one, drop one, or lock the ring out from under the others.
func TestKeyringIsFixed(t *testing.T) {
	signer, sshPub := makeKey(t)
	ring, err := Keyring([]ssh.Signer{signer})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	_, extra, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	checks := map[string]func() error{
		"Add":       func() error { return ring.Add(agent.AddedKey{PrivateKey: extra}) },
		"Remove":    func() error { return ring.Remove(sshPub) },
		"RemoveAll": ring.RemoveAll,
		"Lock":      func() error { return ring.Lock([]byte("pass")) },
		"Unlock":    func() error { return ring.Unlock(nil) },
	}
	for name, call := range checks {
		if err := call(); err == nil {
			t.Errorf("%s should report that the keyring is fixed", name)
		}
	}

	// The refusal must leave the ring working, not break it.
	keys, err := ring.List()
	if err != nil {
		t.Fatalf("list after refusals: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected the original key to survive, got %d keys", len(keys))
	}
}

// Signers hands back copies, so a caller cannot reach into the ring and change
// what the next session sees.
func TestSignersDoesNotAlias(t *testing.T) {
	signer, _ := makeKey(t)
	ring, err := Keyring([]ssh.Signer{signer})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	got, err := ring.Signers()
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(got))
	}
	got[0] = nil

	again, err := ring.Signers()
	if err != nil {
		t.Fatalf("signers again: %v", err)
	}
	if again[0] == nil {
		t.Fatal("mutating the returned slice changed the keyring")
	}
}
