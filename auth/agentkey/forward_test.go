//go:build !js

package agentkey_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	charmlog "charm.land/log/v2"
	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/client"
	"github.com/btwiuse/wssh/shell"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// startForwardingServer brings up a wssh that either offers agent forwarding
// or does not, and returns its WebSocket URL.
func startForwardingServer(t *testing.T, forward bool) string {
	t.Helper()
	return startForwardingServerWithLogger(t, forward, nil)
}

func startForwardingServerWithLogger(t *testing.T, forward bool, logger *charmlog.Logger) string {
	t.Helper()

	dir := t.TempDir()
	script := filepath.Join(dir, "fake-shell")
	body := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-c\" ]; then exec /bin/sh -c \"$2\"; fi\n" +
		"while IFS= read -r line; do eval \"$line\"; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake shell: %v", err)
	}
	t.Setenv("SHELL", script)

	middleware := []wish.Middleware{shell.Middleware()}
	if forward {
		// Last in the list: wish composes first to last with the last
		// outermost, so this is what makes Forward run before the shell.
		middleware = append(middleware, agentkey.Forward())
	}

	server, err := wssh.NewServer(wssh.Options{
		HostKeyPath:  filepath.Join(dir, "host_ed25519"),
		Logger:       logger,
		Middleware:   middleware,
		Pty:          true,
		ForwardAgent: forward,
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

	return "ws://" + ln.Addr().String() + "/ws"
}

// liveSession keeps a session open so the relayed socket, which is torn down
// with the connection, is still there to be used.
type liveSession struct {
	sess *client.Session
	mu   sync.Mutex
	buf  strings.Builder
}

func (l *liveSession) onData(p []byte) {
	l.mu.Lock()
	l.buf.Write(p)
	l.mu.Unlock()
}

func (l *liveSession) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// openForwardingSession dials with the given signers offered as an agent and
// asks the shell what SSH_AUTH_SOCK it was given.
func openForwardingSession(t *testing.T, url string, signers []gossh.Signer) (*liveSession, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	live := &liveSession{}
	sess, err := client.Dial(ctx, client.Options{
		URL:          url,
		User:         "tester",
		AgentSigners: signers,
		OnData:       live.onData,
		OnClose:      func(error) {},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if err := sess.Write([]byte("printenv SSH_AUTH_SOCK\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The path is the only line that is a socket under the server's temp
	// directory; waiting for it avoids depending on the exact prompt.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if path := sockPath(live.String()); path != "" {
			return live, path
		}
		time.Sleep(50 * time.Millisecond)
	}
	return live, ""
}

func sockPath(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "wssh-agent-fwd-") && strings.HasSuffix(line, ".sock") {
			return line
		}
	}
	return ""
}

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

// TestForwardedAgentSignsForTheSession is the point of the feature: the key
// stays on the client, and a program in the session still gets a signature.
//
// The server and the test share a machine here, which is the only thing that
// would not hold in production, and it lets the test stand in for the program
// that would be talking to SSH_AUTH_SOCK in the session.
func TestForwardedAgentSignsForTheSession(t *testing.T) {
	url := startForwardingServer(t, true)
	signer, sshPub := testSigner(t)

	_, path := openForwardingSession(t, url, []gossh.Signer{signer})
	if path == "" {
		t.Fatal("the session was not given SSH_AUTH_SOCK")
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial the relayed socket: %v", err)
	}
	defer conn.Close()

	remote := agent.NewClient(conn)
	keys, err := remote.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected the client's 1 key, got %d", len(keys))
	}
	if got, want := keys[0].Type(), sshPub.Type(); got != want {
		t.Fatalf("key type: got %q, want %q", got, want)
	}

	payload := []byte("something the session wanted signed")
	sig, err := remote.Sign(keys[0], payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sshPub.Verify(payload, sig); err != nil {
		t.Fatalf("the signature from the forwarded agent did not verify: %v", err)
	}

	// A signature over something else must not verify, or the relayed socket
	// would be signing for whatever it is handed rather than what was asked.
	other, err := remote.Sign(keys[0], []byte("something else"))
	if err != nil {
		t.Fatalf("sign again: %v", err)
	}
	if err := sshPub.Verify([]byte("something else"), other); err != nil {
		t.Fatalf("second signature did not verify: %v", err)
	}
}

// A client that offers its agent to a server that did not ask for forwarding
// gets an ordinary session: no socket, and no channel opened behind its back.
func TestForwardedAgentIsOffByDefault(t *testing.T) {
	url := startForwardingServer(t, false)
	signer, _ := testSigner(t)

	live, path := openForwardingSession(t, url, []gossh.Signer{signer})
	if path != "" {
		t.Fatalf("server published SSH_AUTH_SOCK=%q without --forward-agent", path)
	}
	if strings.Contains(live.String(), "wssh-agent-fwd-") {
		t.Fatalf("relay socket leaked into the session without --forward-agent: %q", live.String())
	}
}
