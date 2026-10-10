package solana

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// The case this exists for: an agent with no Solana extension, which is what
// every ssh-agent is. It signs whatever it is handed, so the transaction has
// to be built here and the message handed over as an ordinary signature
// request.
func TestSignWithAPlainSSHAgent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	// A keyring with no Solana extension on it, deliberately.
	ring, err := agentkey.Keyring([]gossh.Signer{signer})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	sock := serveForTest(t, ring)

	// The payer and the account the instruction signs with are the same
	// key, so both have to move together.
	addr := siws.Base58Encode(pub)
	req := goldenRequest(t)
	req.Signer = addr
	req.Instructions[0].Accounts[0].Address = addr

	resp, err := SignWithAgent(context.Background(), sock, req)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(resp.SignedTransaction) == 0 {
		t.Fatal("no signed transaction came back")
	}
	if len(resp.Signature) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(resp.Signature), ed25519.SignatureSize)
	}

	// The signature has to be over the message the wallet would have been
	// shown, or it is a signature of nothing.
	unsigned, err := BuildTransaction(req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	message := unsigned[1+ed25519.SignatureSize:]
	if !ed25519.Verify(pub, message, resp.Signature) {
		t.Error("the signature is not over the message that was built")
	}
	who, err := FeePayer(resp.SignedTransaction)
	if err != nil {
		t.Fatalf("the result cannot be read back: %v", err)
	}
	if who != req.Signer {
		t.Errorf("the signed transaction reads back a payer of %q, want %q", who, req.Signer)
	}
}

// An agent that does not hold the payer has to say so. Signing with some
// other key it happens to have would produce a transaction the cluster
// rejects with nothing pointing here.
func TestSignWithAgentRefusesWhenTheKeyIsAbsent(t *testing.T) {
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	otherSigner, err := gossh.NewSignerFromKey(other)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ring, err := agentkey.Keyring([]gossh.Signer{otherSigner})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	sock := serveForTest(t, ring)

	req := goldenRequest(t)
	if _, err := SignWithAgent(context.Background(), sock, req); err == nil {
		t.Error("an agent without the key should have been asked and refused")
	}
}

// netListenUnix publishes an agent on a real socket. The path is kept short
// because a unix socket path is capped at about 104 bytes and a test's own
// temp directory name is easily longer than that on its own.
func netListenUnix(t *testing.T) (net.Listener, error) {
	dir, err := os.MkdirTemp("", "s")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return net.Listen("unix", filepath.Join(dir, "a.sock"))
}

// serveForTest puts an agent on a real unix socket, because the thing being
// tested is a conversation with one.
func serveForTest(t *testing.T, ring agentkey.Agent) string {
	t.Helper()
	ln, err := netListenUnix(t)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck
				_ = agent.ServeAgent(ring, conn)
			}()
		}
	}()
	return ln.Addr().String()
}
