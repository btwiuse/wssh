package authfwd_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth/authfwd"
	"github.com/btwiuse/wssh/shell"
	"github.com/coder/websocket"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestServerOpensAgentChannel drives the in-memory agent the way a
// real client (the browser, or a CLI that wants to sign with the loaded
// keys) would: by opening an "auth-agent@openssh.com" channel on a
// pre-established SSH connection. The connection rides on top of the
// same WebSocket transport wssh serves over HTTP, so this exercises the
// same code path the browser front end uses.
//
// Note: the openssh client does not have a flag for this. `ssh -A` is
// the reverse direction -- it forwards the client's local agent to the
// server, which is the opposite of what we built. To talk to a
// server-side agent, openssh users would need a separate tool. The
// agent protocol is the same in both directions; this test confirms
// the server side works.
func TestServerOpensAgentChannel(t *testing.T) {
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

	ring, err := authfwd.Keyring([]crypto.Signer{priv})
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

	clientConn, chans, reqs, err := dialWebSocket(testCtx(t), "ws://"+ln.Addr().String()+"/ws", "tester")
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer clientConn.Close()

	sshClient := gossh.NewClient(clientConn, chans, reqs)
	sess, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	modes := gossh.TerminalModes{gossh.ECHO: 0}
	if err := sess.RequestPty("xterm", 24, 80, modes); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	go func() {
		_, _ = stdin.Write([]byte("exit\n"))
		_ = stdin.Close()
	}()

	// Open the agent channel directly. The server's authfwd handler
	// accepts any such channel; the bytes on it are the agent protocol.
	ch, agReqs, err := sshClient.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		t.Fatalf("open agent channel: %v", err)
	}
	go gossh.DiscardRequests(agReqs)
	defer ch.Close()

	cli := agent.NewClient(ch)
	keys, err := cli.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Type() != sshPub.Type() {
		t.Fatalf("key type: got %q, want %q", keys[0].Type(), sshPub.Type())
	}
	sig, err := cli.Sign(keys[0], []byte("hello wssh agent"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sshPub.Verify([]byte("hello wssh agent"), sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// dialWebSocket opens a WebSocket connection to the test server and
// returns the SSH-level connection, channels, and requests, exactly the
// way the browser front end would. The returned conn is a thin
// adapter over the WebSocket; SSH bytes written to it become WebSocket
// binary frames, and frames read from it appear as reads on the conn.
func dialWebSocket(ctx context.Context, url, user string) (gossh.Conn, <-chan gossh.NewChannel, <-chan *gossh.Request, error) {
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	netConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	// The test server runs with no auth handler, so anything the client
	// offers is accepted. The throwaway key is just to give the client
	// a real auth method to try.
	signer, err := gossh.NewSignerFromKey(throwawayKey())
	if err != nil {
		_ = netConn.Close()
		return nil, nil, nil, err
	}
	return gossh.NewClientConn(netConn, url, &gossh.ClientConfig{
		User:            user,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
	})
}

// throwawayKey returns a fresh ed25519 key whose only job is to give
// the SSH client something to offer during authentication. The server
// has no auth handler, so the key itself is not consulted.
func throwawayKey() ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}
