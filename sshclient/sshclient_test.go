//go:build !js

package sshclient_test

import (
	"bytes"
	"context"
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
	"github.com/btwiuse/wssh/shell"
	"github.com/btwiuse/wssh/sshclient"
)

// These tests drive a real wsshd over a real WebSocket on loopback. Keeping
// sshclient free of syscall/js is what makes this possible: the exact code the
// browser runs is exercised here, with ordinary error messages and a debugger
// that works.

const timeout = 20 * time.Second

// startServer brings up a wsshd on loopback and returns its WebSocket URL plus
// a buffer of its log.
func startServer(t *testing.T) (string, *bytes.Buffer) {
	t.Helper()

	// A stand-in shell keeps the test independent of the developer's $SHELL
	// and of whatever their profile prints on first use. It covers both shapes
	// the middleware uses: `shell -c <command>`, and a bare read-eval loop.
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-shell")
	body := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-c\" ]; then exec /bin/sh -c \"$2\"; fi\n" +
		"while IFS= read -r line; do eval \"$line\"; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake shell: %v", err)
	}
	t.Setenv("SHELL", script)

	var logBuf bytes.Buffer
	logger := charmlog.New(&logBuf)
	logger.SetLevel(charmlog.DebugLevel)

	server, err := wssh.NewServer(wssh.Options{
		HostKeyPath: filepath.Join(dir, "host_ed25519"),
		Middleware:  []wish.Middleware{shell.Middleware()},
		Pty:         true,
		Logger:      logger,
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

	return "ws://" + ln.Addr().String() + "/ws", &logBuf
}

// collector accumulates terminal output for assertions.
type collector struct {
	mu   sync.Mutex
	buf  strings.Builder
	done chan error
}

func newCollector() *collector { return &collector{done: make(chan error, 1)} }

func (c *collector) onData(p []byte) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
}

func (c *collector) onClose(err error) { c.done <- err }

func (c *collector) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func TestSessionRunsCommandAndEnds(t *testing.T) {
	url, srvLog := startServer(t)
	col := newCollector()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sess, err := sshclient.Dial(ctx, sshclient.Options{
		URL:     url,
		User:    "tester",
		Command: "echo NATIVE_CLIENT_OK",
		OnData:  col.onData,
		OnClose: col.onClose,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close() //nolint:errcheck

	select {
	case err := <-col.done:
		if err != nil {
			t.Fatalf("session ended with error: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out; output=%q server log=%s", col.String(), srvLog.String())
	}

	if got := col.String(); !strings.Contains(got, "NATIVE_CLIENT_OK") {
		t.Fatalf("output %q lacks the expected text; server log=%s", got, srvLog.String())
	}
}

func TestSessionIsInteractive(t *testing.T) {
	url, srvLog := startServer(t)
	col := newCollector()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sess, err := sshclient.Dial(ctx, sshclient.Options{
		URL:    url,
		User:   "tester",
		OnData: col.onData,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close() //nolint:errcheck

	if err := sess.Write([]byte("echo INTERACTIVE_OK\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A resize has to reach the remote PTY, or full-screen programs keep
	// drawing to the geometry they started with.
	if err := sess.Resize(100, 40); err != nil {
		t.Fatalf("resize: %v", err)
	}

	deadline := time.After(15 * time.Second)
	for {
		if strings.Contains(col.String(), "INTERACTIVE_OK") {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out; output=%q server log=%s", col.String(), srvLog.String())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
