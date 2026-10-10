//go:build !js

package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// The question this file exists for: does the layer that asks actually get
// used? Wrapping only one of the two lists the browser hands to the session
// asked for nothing, because the keyring the session talks to is preferred
// whenever there is one - and there is one whenever the user has any key at
// all. An imported key then signed without asking, while the comment beside it
// claimed the opposite.
func TestConfirmBeforeSigning(t *testing.T) {
	ask := func(string) (bool, error) { return true, nil }

	if !confirmBeforeSigning(true, ask) {
		t.Error("forwarding with a way to ask should confirm")
	}
	// No way to ask is not permission: a ConfirmingSigner asked with nothing
	// behind it refuses rather than signing, so this must not read as "go
	// ahead".
	if confirmBeforeSigning(true, nil) {
		t.Error("no way to ask must not read as permission to sign")
	}
	if confirmBeforeSigning(false, ask) {
		t.Error("forwarding off must not ask")
	}
}

// A signer handed to the page is wrapped so it asks, and the wrapper still
// reports the inner key. That second half matters beyond tidiness: the Solana
// extension reads the public key back out of the signer to check that the
// wallet signed with a key this agent holds, and a wrapper that did not carry
// it through would make every such answer look like a stranger's.
func TestConfirmOneWrapsAndStillReportsTheKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	inner, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	asked := 0
	wrapped := confirmOne(inner, func(string) (bool, error) { asked++; return true, nil })

	if _, ok := wrapped.(*ConfirmingSigner); !ok {
		t.Fatalf("the signer came back as %T, not wrapped", wrapped)
	}
	want, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	if !bytes.Equal(wrapped.PublicKey().Marshal(), want.Marshal()) {
		t.Error("the wrapper does not report the key inside it")
	}
	// The extension reads the curve out of that key to name the account, so
	// a wrapper that swallowed it would refuse every answer.
	if _, ok := wrapped.PublicKey().(gossh.CryptoPublicKey); !ok {
		t.Error("the key behind the wrapper is not a CryptoPublicKey")
	}

	if _, err := wrapped.Sign(rand.Reader, []byte("hello")); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if asked != 1 {
		t.Errorf("the page was asked %d times, want 1", asked)
	}
}

// Saying no must produce no signature, and must not be remembered: the next
// signature asks again. A yes that stuck would hand the key open to whatever
// in the session asked next.
func TestADeclinedSignatureIsNotRemembered(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	inner, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	answers := []bool{false, true}
	asked := 0
	wrapped := confirmOne(inner, func(string) (bool, error) {
		asked++
		if asked > len(answers) {
			t.Fatal("the page was asked more times than there were answers")
		}
		return answers[asked-1], nil
	})

	if _, err := wrapped.Sign(rand.Reader, []byte("first")); !errors.Is(err, ErrSignatureDeclined) {
		t.Fatalf("the first signature returned %v, want a decline", err)
	}
	if _, err := wrapped.Sign(rand.Reader, []byte("second")); err != nil {
		t.Fatalf("the second signature should have been asked again and been allowed: %v", err)
	}
	if asked != 2 {
		t.Errorf("the page was asked %d times, want 2 - a refusal must not be remembered", asked)
	}
}

// The label is what the question shows a person, so it has to name the key
// rather than be empty: a dialog that says "sign this?" with no key in it is
// the question nobody can answer.
func TestConfirmOneLabelsTheKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	inner, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	var summary string
	wrapped := confirmOne(inner, func(s string) (bool, error) { summary = s; return true, nil })
	if _, err := wrapped.Sign(rand.Reader, []byte("hello")); err != nil {
		t.Fatalf("sign: %v", err)
	}

	encoded, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	fingerprint := gossh.FingerprintSHA256(encoded)
	if !bytes.Contains([]byte(summary), []byte(fingerprint)) {
		t.Errorf("the question does not name the key: %q", summary)
	}
	if !bytes.Contains([]byte(summary), []byte(gossh.KeyAlgoED25519)) {
		t.Errorf("the question does not say what kind of key it is: %q", summary)
	}
}
