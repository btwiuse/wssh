package client_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestWriteOpenSSHPrivateKeyRoundTrip is a smoke test: produce a
// key file with the test helper, then load it through the
// standard library's parser. The shape of the openssh-key-v1
// format is finicky, and the parser is strict; if the helper
// drifts, the parser complains and this test fails.
func TestWriteOpenSSHPrivateKeyRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	writeOpenSSHPrivateKey(t, path, priv)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatalf("parse: %v\nfile:\n%s", err, string(raw))
	}
	want, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("wrap expected: %v", err)
	}
	if !keyEqual(signer.PublicKey().Marshal(), want.PublicKey().Marshal()) {
		t.Fatalf("public keys do not match")
	}
}
