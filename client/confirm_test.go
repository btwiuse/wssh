//go:build !js

package client_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/btwiuse/wssh/client"
	gossh "golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) (gossh.Signer, gossh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap public: %v", err)
	}
	return signer, sshPub
}

// The whole point: a signature only happens after a yes.
func TestConfirmingSignerSignsAfterApproval(t *testing.T) {
	inner, sshPub := testSigner(t)

	var asked []string
	signer := client.NewConfirmingSigner(inner, "mykey", func(summary string) (bool, error) {
		asked = append(asked, summary)
		return true, nil
	})

	payload := []byte("please sign me")
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sshPub.Verify(payload, sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
	if len(asked) != 1 {
		t.Fatalf("expected exactly one question, got %d", len(asked))
	}
	if !strings.Contains(asked[0], "mykey") {
		t.Fatalf("the question does not name the key: %q", asked[0])
	}
}

// A no has to stop the signature, not merely be recorded.
func TestConfirmingSignerRefusesWhenDeclined(t *testing.T) {
	inner, _ := testSigner(t)

	signer := client.NewConfirmingSigner(inner, "mykey", func(string) (bool, error) {
		return false, nil
	})

	if _, err := signer.Sign(rand.Reader, []byte("x")); !errors.Is(err, client.ErrSignatureDeclined) {
		t.Fatalf("got %v, want ErrSignatureDeclined", err)
	}
}

// Silence is not consent. A signer with no way to ask must not sign, which is
// what keeps a miswired browser from quietly becoming a standing permission.
func TestConfirmingSignerWithoutACallbackRefuses(t *testing.T) {
	inner, _ := testSigner(t)
	signer := client.NewConfirmingSigner(inner, "mykey", nil)

	if _, err := signer.Sign(rand.Reader, []byte("x")); err == nil {
		t.Fatal("a signer that cannot ask signed anyway")
	}
}

// One yes is one signature. A signer that remembered would be exactly the
// standing permission this exists to prevent.
func TestConfirmingSignerAsksEveryTime(t *testing.T) {
	inner, sshPub := testSigner(t)

	var mu sync.Mutex
	asked := 0
	signer := client.NewConfirmingSigner(inner, "mykey", func(string) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		asked++
		return true, nil
	})

	for i := range 3 {
		payload := []byte{byte(i)}
		sig, err := signer.Sign(rand.Reader, payload)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		if err := sshPub.Verify(payload, sig); err != nil {
			t.Fatalf("signature %d did not verify: %v", i, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if asked != 3 {
		t.Fatalf("expected 3 questions for 3 signatures, got %d", asked)
	}
}

func TestConfirmingSignerPassesThroughAskErrors(t *testing.T) {
	inner, _ := testSigner(t)
	boom := errors.New("page went away")

	signer := client.NewConfirmingSigner(inner, "mykey", func(string) (bool, error) {
		return false, boom
	})

	_, err := signer.Sign(rand.Reader, []byte("x"))
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the ask error", err)
	}
}

// The question has to describe the signature honestly. Showing text when the
// bytes are binary would put a guess in front of the user's approval.
func TestSummaryShowsTextAndFallsBackToHex(t *testing.T) {
	inner, _ := testSigner(t)

	var got string
	signer := client.NewConfirmingSigner(inner, "mykey", func(summary string) (bool, error) {
		got = summary
		return false, nil
	})

	if _, err := signer.Sign(rand.Reader, []byte("hello there")); err == nil {
		t.Fatal("expected the decline")
	}
	if !strings.Contains(got, "hello there") {
		t.Errorf("printable data should be shown as text, got %q", got)
	}

	binary := []byte{0x00, 0x01, 0xff, 0xfe}
	if _, err := signer.Sign(rand.Reader, binary); err == nil {
		t.Fatal("expected the decline")
	}
	if !strings.Contains(got, "0001fffe") {
		t.Errorf("binary data should be shown as hex, got %q", got)
	}
}

// Long blobs are truncated rather than dumped: the point is to let someone
// recognise what they are approving, not to read it.
func TestSummaryTruncatesLongData(t *testing.T) {
	inner, _ := testSigner(t)

	var got string
	signer := client.NewConfirmingSigner(inner, "mykey", func(summary string) (bool, error) {
		got = summary
		return false, nil
	})

	if _, err := signer.Sign(rand.Reader, make([]byte, 4096)); err == nil {
		t.Fatal("expected the decline")
	}
	if !strings.Contains(got, "4096 bytes") {
		t.Errorf("the size should still be exact, got %q", got)
	}
	if !strings.Contains(got, "...") {
		t.Errorf("the preview should be elided, got %q", got)
	}
}
