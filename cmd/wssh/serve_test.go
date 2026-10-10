package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// --agent-keys is the one place a wssh server knows where its signing keys
// came from: it read them off disk by name. That name is what ends up at the
// end of every `ssh-add -l` line in a session and in sol-keys, and it is the
// only thing that distinguishes one loaded key from another.
func TestBuildAgentLabelsEachKeyWithItsFileName(t *testing.T) {
	dir := t.TempDir()
	first := writeTestKey(t, dir, "solana.ed25519")
	second := writeTestKey(t, dir, "bastion.ed25519")

	ring, err := buildAgent([]string{first, second})
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}
	if ring == nil {
		t.Fatal("buildAgent returned no agent for two keys")
	}

	keys, err := ring.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}

	// Matched by name rather than by position: the order the agent answers
	// in is not the order the files were given, and a test that assumed it
	// would agree with itself rather than with the code.
	for _, key := range keys {
		if key.Comment != filepath.Base(first) && key.Comment != filepath.Base(second) {
			t.Errorf("comment is %q, want one of the two file names", key.Comment)
		}
	}
	if keys[0].Comment == keys[1].Comment {
		t.Errorf("both keys are labelled %q, so they cannot be told apart", keys[0].Comment)
	}
}

// The label is a file name, not a path: the directory is the operator's
// business and printing it in every session's key listing is noise. This is
// also what ssh-add does for a key in ~/.ssh.
func TestBuildAgentLabelsWithTheBaseNameOnly(t *testing.T) {
	dir := t.TempDir()
	// A subdirectory, so a full path would be visibly longer than a name.
	nested := filepath.Join(dir, "keys")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := writeTestKey(t, nested, "id_ed25519")

	ring, err := buildAgent([]string{path})
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}
	keys, err := ring.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got, want := keys[0].Comment, "id_ed25519"; got != want {
		t.Errorf("comment is %q, want the file name %q", got, want)
	}
}

// The comment must not cost the keyring its ability to sign. A label that
// works for display and breaks Sign would be worse than no label at all.
func TestTheLabelledKeyringStillSigns(t *testing.T) {
	path := writeTestKey(t, t.TempDir(), "signer.ed25519")

	ring, err := buildAgent([]string{path})
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}
	keys, err := ring.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	// Over a real agent protocol connection rather than by calling the
	// interface, because the wire form is where a comment could go wrong.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _ = agent.ServeAgent(ring, server) }()

	signed, err := agent.NewClient(client).Sign(keys[0], []byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed == nil {
		t.Fatal("no signature came back")
	}
}

// An empty list is not an error and not an agent, so callers can use the
// result without checking.
func TestBuildAgentWithNoKeys(t *testing.T) {
	ring, err := buildAgent(nil)
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}
	if ring != nil {
		t.Error("buildAgent made an agent out of no keys")
	}
}

// writeTestKey writes a real, unencrypted PEM key and returns its path.
func writeTestKey(t *testing.T, dir, name string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, name)
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Parsed here so a key this function cannot read fails at the fixture
	// rather than inside the assertion it was written for.
	if _, err := gossh.ParsePrivateKey(block); err != nil {
		t.Fatalf("the fixture key does not parse: %v", err)
	}
	return path
}
