package agentkey_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/shell"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestSSHAuthSockIsUsable covers the full path: a real wssh.Server
// with the agent configured, dialed through the real WebSocket
// transport, the shell env carries SSH_AUTH_SOCK, and the local
// socket at that path is a working ssh-agent. The test then uses
// the socket from the test process (as any program on the
// remote would) to list and sign.
//
// This is what makes `ssh -A` work transparently: openssh's
// -A flag is for the client-to-server direction, but the same
// pattern (a local agent on the remote side) works for
// server-to-client when the server itself runs the agent.
func TestSSHAuthSockIsUsable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", "/bin/sh")
	// The middleware runs the shell as a login shell, so $HOME decides
	// whose profile gets sourced. Leaving it alone would let the
	// developer's own .profile set PS1, print a banner, or be slow
	// enough to eat the commands below, and the test would fail for
	// reasons that have nothing to do with the agent.
	t.Setenv("HOME", dir)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}

	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ring, err := agentkey.Keyring([]gossh.Signer{signer})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	server, err := wssh.NewServer(wssh.Options{
		HostKeyPath: filepath.Join(dir, "host_ed25519"),
		Middleware:  []wish.Middleware{shell.Middleware()},
		Pty:         true,
		Agent:       ring,
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

	// Dial through the WebSocket. No agent key on the client side
	// is fine -- the server has no PublicKeyHandler installed, so
	// the SSH handshake completes with the "none" method.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cc, chans, reqs, err := dialWebSocket(ctx, "ws://"+ln.Addr().String()+"/ws", "tester")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()
	c := gossh.NewClient(cc, chans, reqs)

	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{gossh.ECHO: 0}); err != nil {
		t.Fatalf("pty: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	type result struct{ out string }
	done := make(chan struct{}, 1)
	var acc []byte
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	// Print the value of SSH_AUTH_SOCK and a sentinel so the
	// test can find both in the captured output. The two
	// commands are on separate lines so the shell runs them
	// independently: the first prints the path, the second
	// prints the sentinel. A single `;`-separated line works
	// in bash but the test shell on Termux is /bin/sh, which
	// can stop reading at the first newline of the first
	// command's output, depending on the terminal mode.
	go func() {
		_, _ = stdin.Write([]byte("printenv SSH_AUTH_SOCK\necho END_OF_AUTH_SOCK\nexit\n"))
		_ = stdin.Close()
	}()
	sess.Wait()
	<-done
	res := result{string(acc)}
	if res.out == "" {
		t.Fatalf("no output from remote shell")
	}

	// Extract the path printed by the shell. The output is
	// "<path>\nEND_OF_AUTH_SOCK\n", but a real shell may have
	// other output mixed in (a prompt, etc). Find the line
	// that ends with END_OF_AUTH_SOCK and take the line before
	// it.
	path := extractSSHAuthSockPath(t, res.out)
	if path == "" {
		t.Fatalf("SSH_AUTH_SOCK not found in shell output: %q", res.out)
	}

	// Talk to the socket. The agent process running inside the
	// wssh server is serving the in-memory keyring; from the
	// test's perspective the socket is just a normal local
	// agent.
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	defer conn.Close()
	cli := agent.NewClient(conn)
	keys, err := cli.List()
	if err != nil {
		t.Fatalf("agent list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Type() != sshPub.Type() {
		t.Fatalf("key type: got %q, want %q", keys[0].Type(), sshPub.Type())
	}
	sig, err := cli.Sign(keys[0], []byte("auth-sock-canary"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sshPub.Verify([]byte("auth-sock-canary"), sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// extractSSHAuthSockPath returns the path printed by the remote
// shell, or empty if it cannot be found. The shell prints the
// value followed by the sentinel "END_OF_AUTH_SOCK" on its own
// line. The surrounding terminal is a PTY: there is a prompt
// before every command, the shell echoes what was typed, and
// only the output of the command carries the path. The output
// looks like:
//
//	:/.../dir $ printenv SSH_AUTH_SOCK
//	/path/to/agent.sock
//	:/.../dir $ echo END_OF_AUTH_SOCK
//	END_OF_AUTH_SOCK
//	:/.../dir $ exit
//
// We locate the sentinel line and walk backwards over the
// prompt-echo line to the output line that holds the path.
func extractSSHAuthSockPath(t *testing.T, output string) string {
	t.Helper()
	const sentinel = "END_OF_AUTH_SOCK"
	lines := splitLines(output)
	for i, line := range lines {
		// Not equality: an interactive shell prints its prompt on the
		// same line as the command's output, so the sentinel arrives as
		// "<prompt> END_OF_AUTH_SOCK".
		if !strings.HasSuffix(trim(line), sentinel) {
			continue
		}
		if i == 0 {
			return ""
		}
		// Same reason for the path on the line above: take its last
		// field, which is the path rather than the prompt in front of it.
		fields := strings.Fields(trim(lines[i-1]))
		if len(fields) == 0 {
			continue
		}
		return fields[len(fields)-1]
	}
	return ""
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
