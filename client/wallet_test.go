//go:build !js

package client_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/btwiuse/wssh/client"
	gossh "golang.org/x/crypto/ssh"
)

// A wallet signature is accepted only because it verifies against the wallet's
// own key. That is the whole contract: the key is elsewhere, so nothing else
// ties the two together.
func TestWalletSignerSignsThroughTheWallet(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := client.NewWalletSigner(pub, "Phantom 7xK..", func(_ string, data []byte) ([]byte, error) {
		return ed25519.Sign(priv, data), nil
	})
	if err != nil {
		t.Fatalf("new wallet signer: %v", err)
	}

	payload := []byte("something the session wanted signed")
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig.Format != gossh.KeyAlgoED25519 {
		t.Fatalf("signature format %q, want %q", sig.Format, gossh.KeyAlgoED25519)
	}
	if err := signer.PublicKey().Verify(payload, sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
	if got := signer.PublicKey().Type(); got != "ssh-ed25519" {
		t.Fatalf("key type %q, want ssh-ed25519", got)
	}
}

// A wallet that prefixes or otherwise decorates its output is not signing the
// raw message, and the SSH side would fail much later and much less clearly.
// Say so now instead.
func TestWalletSignerRejectsWrongLength(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := client.NewWalletSigner(pub, "wallet", func(_ string, data []byte) ([]byte, error) {
		// A prefixed signature: a plausible thing for a wallet to return.
		return append([]byte{0x01, 0x02}, ed25519.Sign(priv, data)...), nil
	})
	if err != nil {
		t.Fatalf("new wallet signer: %v", err)
	}

	_, err = signer.Sign(rand.Reader, []byte("x"))
	if err == nil {
		t.Fatal("accepted a signature of the wrong length")
	}
	if !strings.Contains(err.Error(), "raw message") {
		t.Errorf("error should name the cause, got %v", err)
	}
}

// A signature that does not verify is worse than no signature, because it
// would be carried to the far end and rejected there as a protocol error.
func TestWalletSignerRejectsAForgedSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)

	signer, err := client.NewWalletSigner(pub, "wallet", func(_ string, data []byte) ([]byte, error) {
		return ed25519.Sign(other, data), nil // right length, wrong key
	})
	if err != nil {
		t.Fatalf("new wallet signer: %v", err)
	}

	_, err = signer.Sign(rand.Reader, []byte("x"))
	if err == nil {
		t.Fatal("accepted a signature from the wrong key")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("error should say it does not verify, got %v", err)
	}
}

func TestWalletSignerPassesThroughRefusal(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	declined := errors.New("user rejected")

	signer, err := client.NewWalletSigner(pub, "wallet", func(string, []byte) ([]byte, error) {
		return nil, declined
	})
	if err != nil {
		t.Fatalf("new wallet signer: %v", err)
	}

	if _, err := signer.Sign(rand.Reader, []byte("x")); !errors.Is(err, declined) {
		t.Fatalf("got %v, want the refusal", err)
	}
}

func TestNewWalletSignerRejectsBadInput(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ask := func(string, []byte) ([]byte, error) { return nil, nil }

	if _, err := client.NewWalletSigner(pub[:10], "wallet", ask); err == nil {
		t.Error("accepted a public key of the wrong length")
	}
	// No way to reach the key is not a silent fallback to something else.
	if _, err := client.NewWalletSigner(pub, "wallet", nil); err == nil {
		t.Error("accepted a signer with nothing to ask")
	}
}

// The question has to name the key and describe the data honestly.
func TestWalletSummary(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	var got string
	signer, err := client.NewWalletSigner(pub, "Phantom 7xK..", func(summary string, _ []byte) ([]byte, error) {
		got = summary
		return nil, errors.New("stop here")
	})
	if err != nil {
		t.Fatalf("new wallet signer: %v", err)
	}

	if _, err := signer.Sign(rand.Reader, []byte("hello there")); err == nil {
		t.Fatal("expected the refusal")
	}
	if !strings.Contains(got, "Phantom 7xK..") || !strings.Contains(got, "hello there") {
		t.Errorf("summary should name the key and show the text, got %q", got)
	}

	if _, err := signer.Sign(rand.Reader, []byte{0x00, 0xff, 0xfe}); err == nil {
		t.Fatal("expected the refusal")
	}
	if !strings.Contains(got, "00fffe") {
		t.Errorf("binary data should be shown as hex, got %q", got)
	}
}

// The bytes handed to the wallet must be exactly the bytes to be signed. A
// wallet that is asked to sign something else produces a signature that
// verifies against nothing.
func TestWalletGetsTheExactBytes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	var seen []byte
	signer, _ := client.NewWalletSigner(pub, "wallet", func(_ string, data []byte) ([]byte, error) {
		seen = append([]byte(nil), data...)
		return ed25519.Sign(priv, data), nil
	})

	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	if _, err := signer.Sign(rand.Reader, payload); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if string(seen) != string(payload) {
		t.Fatalf("wallet saw %x, want %x", seen, payload)
	}
}

// A signing question has to name the key the way the person holding it calls
// it. For a Solana wallet that is the account address, and it is shown whole:
// a prompt that displays half an identifier is worse than no prompt.
func TestWalletLabelPrefersTheAddress(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	const address = "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"

	if got := client.WalletLabel(address, pub); got != address {
		t.Errorf("got %q, want the address %q", got, address)
	}

	// The address is threaded through into the question, so check the question
	// rather than only the helper.
	var got string
	signer, err := client.NewWalletSigner(pub, address, func(summary string, _ []byte) ([]byte, error) {
		got = summary
		return nil, errors.New("stop")
	})
	if err != nil {
		t.Fatalf("new wallet signer: %v", err)
	}
	if _, err := signer.Sign(rand.Reader, []byte("x")); err == nil {
		t.Fatal("expected the refusal")
	}
	if !strings.Contains(got, address) {
		t.Errorf("question does not name the address: %q", got)
	}
}

// Without an address the fingerprint is the fallback, and it describes the same
// key: SSH's ed25519 blob and a Solana address are the same 32 bytes.
func TestWalletLabelFallsBackToTheFingerprint(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	got := client.WalletLabel("", pub)
	if !strings.HasPrefix(got, "wallet SHA256:") {
		t.Errorf("got %q, want a fingerprint", got)
	}

	sshPub, _ := gossh.NewPublicKey(pub)
	if want := "wallet " + gossh.FingerprintSHA256(sshPub); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The address really is the same key in another alphabet, which is why it can
// be recovered from what a session prints.
func TestSolanaAddressIsTheSameKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	blob := sshPub.Marshal()

	// SSH wire format is two length-prefixed strings: the algorithm name, then
	// the key itself.
	readString := func(b []byte) ([]byte, []byte) {
		n := int(binary.BigEndian.Uint32(b[:4]))
		return b[4 : 4+n], b[4+n:]
	}
	algo, rest := readString(blob)
	if string(algo) != gossh.KeyAlgoED25519 {
		t.Fatalf("algorithm %q, want %q", algo, gossh.KeyAlgoED25519)
	}
	got, _ := readString(rest)
	if !bytes.Equal(got, pub) {
		t.Fatalf("the key in the SSH blob is not the ed25519 public key:\n ssh %x\n sol %x", got, pub)
	}
}
