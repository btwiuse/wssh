package client_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/ssh"
	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth/authfwd"
	"github.com/btwiuse/wssh/client"
	"github.com/btwiuse/wssh/shell"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestClientUsesAgentKeyForAuthAndForwarding covers the client half
// of the agent story. The server has a single authorized key in
// its authfwd keyring; the client dials with the matching
// unencrypted private key, the server's publickey handler
// accepts it (because the same key is in the keyring, in a
// different role), and the client also opens an
// auth-agent@openssh.com channel on the same connection to
// expose the same key to whatever runs on the remote side.
//
// Both halves have to be exercised in one test: the agent
// channel alone is just plumbing, and the auth alone is just
// pubkey auth. The interesting contract is that a single key
// serves both.
func TestClientUsesAgentKeyForAuthAndForwarding(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", "/bin/sh")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	privKeyPath := filepath.Join(dir, "id_ed25519")
	writeOpenSSHPrivateKey(t, privKeyPath, priv)

	// The keyring is what the server offers to the agent
	// channel. The PublicKeyHandler is installed directly on the
	// SSH server: when the offered public key matches the one we
	// have here, accept. Both pieces of the server's behaviour
	// are gated on this single key.
	ring, err := authfwd.Keyring([]crypto.Signer{priv})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	server, err := wssh.NewServer(wssh.Options{
		HostKeyPath: filepath.Join(dir, "host_ed25519"),
		Middleware:  []wish.Middleware{shell.Middleware()},
		Pty:         true,
		Agent:       ring,
		SSHOptions: []ssh.Option{
			ssh.PublicKeyAuth(func(_ ssh.Context, key ssh.PublicKey) bool {
				return keyEqual(key.Marshal(), sshPub.Marshal())
			}),
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/ws", server)
	go func() { _ = http.Serve(ln, mux) }()
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := client.Dial(ctx, client.Options{
		URL:            "ws://" + ln.Addr().String() + "/ws",
		User:           "tester",
		Cols:           80,
		Rows:           24,
		AgentKeyPath:   privKeyPath,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		OnData:         func([]byte) {},
		OnClose:        func(error) {},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()

	// The first session is up. Run a command over a fresh
	// session on the same connection: same authenticated
	// connection, no pty, stdout piped straight to a buffer.
	// A different auth would have failed before reaching this
	// point.
	rawSess, err := sess.Client().NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer rawSess.Close()
	if err := rawSess.RequestPty("xterm", 24, 80, gossh.TerminalModes{gossh.ECHO: 0}); err != nil {
		t.Fatalf("pty: %v", err)
	}
	stdin, err := rawSess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	stdout, err := rawSess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	if err := rawSess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 4096)
		var acc []byte
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if err != nil {
				done <- result{string(acc), err}
				return
			}
		}
	}()
	go func() {
		_, _ = stdin.Write([]byte("echo AGENT_AUTH_OK; exit\n"))
		_ = stdin.Close()
	}()
	rawSess.Wait()
	res := <-done
	if !strings.Contains(res.out, "AGENT_AUTH_OK") {
		t.Fatalf("auth did not succeed; got %q", res.out)
	}

	// The agent channel is open on the same connection. Talk
	// to it as a real agent client would. The authfwd keyring
	// has only the one key; we should see exactly that key
	// listed and be able to sign with it.
	cli, closer := openAgentChannel(t, sess)
	defer closer()

	keys, err := cli.List()
	if err != nil {
		t.Fatalf("agent list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Type() != sshPub.Type() {
		t.Fatalf("agent key type: got %q, want %q", keys[0].Type(), sshPub.Type())
	}
	sig, err := cli.Sign(keys[0], []byte("client-agent-canary"))
	if err != nil {
		t.Fatalf("agent sign: %v", err)
	}
	if err := sshPub.Verify([]byte("client-agent-canary"), sig); err != nil {
		t.Fatalf("agent signature did not verify: %v", err)
	}
}

// openAgentChannel opens an "auth-agent@openssh.com" channel on
// the session's underlying *ssh.Client and wraps it in an
// agent.ExtendedAgent. The closer returned shuts both the
// channel and the request-pump goroutine down.
func openAgentChannel(t *testing.T, sess *client.Session) (agent.ExtendedAgent, func()) {
	t.Helper()
	c := sess.Client()
	if c == nil {
		t.Fatal("session has no underlying ssh client")
	}
	ch, reqs, err := c.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		t.Fatalf("open agent channel: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
		close(done)
	}()
	closer := func() {
		_ = ch.Close()
		<-done
	}
	return agent.NewClient(ch), closer
}

// keyEqual compares two byte slices. Pulled out of the test body
// to keep the assertions readable.
func keyEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
