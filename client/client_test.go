//go:build !js

package client_test

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/btwiuse/wssh/client"
	"github.com/btwiuse/wssh/shell"
)

// These tests drive a real wsshd over a real WebSocket on loopback. Keeping
// client free of syscall/js is what makes this possible: the exact code the
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

	sess, err := client.Dial(ctx, client.Options{
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

	sess, err := client.Dial(ctx, client.Options{
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

// A page keeps delivering keystrokes after the far side has gone, so writing to
// a finished session has to be an ordinary error. It must not panic: in
// WebAssembly an unrecovered panic takes the whole runtime down and the user
// is left with a dead page until they reload.
func TestWriteAfterSessionEndsDoesNotPanic(t *testing.T) {
	url, _ := startServer(t)
	col := newCollector()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sess, err := client.Dial(ctx, client.Options{
		URL:    url,
		User:   "tester",
		OnData: col.onData,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// End the session, then keep typing at it.
	sess.CloseStdin()
	sess.CloseStdin() // idempotent

	if err := sess.Write([]byte("x")); !errors.Is(err, client.ErrSessionClosed) {
		t.Fatalf("Write after CloseStdin: got %v, want ErrSessionClosed", err)
	}
	if err := sess.WriteContext(ctx, []byte("x")); !errors.Is(err, client.ErrSessionClosed) {
		t.Fatalf("WriteContext after CloseStdin: got %v, want ErrSessionClosed", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close after CloseStdin: %v", err)
	}
	if err := sess.Write([]byte("y")); !errors.Is(err, client.ErrSessionClosed) {
		t.Fatalf("Write after Close: got %v, want ErrSessionClosed", err)
	}
	if err := sess.Resize(80, 24); err == nil {
		t.Fatal("Resize after Close should report an error")
	}
}

// The same, but ending the session the way the browser does when the remote
// shell exits on its own.
func TestWriteAfterRemoteExitDoesNotPanic(t *testing.T) {
	url, _ := startServer(t)
	col := newCollector()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sess, err := client.Dial(ctx, client.Options{
		URL:     url,
		User:    "tester",
		Command: "true", // exits at once, closing the session underneath us
		OnData:  col.onData,
		OnClose: col.onClose,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close() //nolint:errcheck

	select {
	case <-col.done:
	case <-ctx.Done():
		t.Fatal("session never ended")
	}

	// Whatever the page does next, this must not panic.
	for range 3 {
		if err := sess.Write([]byte("x")); err != nil &&
			!errors.Is(err, client.ErrSessionClosed) && !errors.Is(err, client.ErrInputFull) {
			t.Fatalf("unexpected error after exit: %v", err)
		}
	}
}

// A session has to start with a PATH that its child processes can see, not
// just one the shell can look commands up with.
//
// The distinction is the whole bug: macOS /etc/profile does set PATH, but as
// an unexported shell variable, so the shell finds ls while everything it
// spawns - a python that shells out, a Makefile that calls git - sees nothing.
// `env` is an external binary, so it reads the exported environment and is the
// only thing here that can tell the two cases apart.
func TestSessionExportsPathToChildProcesses(t *testing.T) {
	url, srvLog := startServer(t)
	col := newCollector()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sess, err := client.Dial(ctx, client.Options{
		URL:     url,
		User:    "tester",
		Command: "env | grep -q '^PATH=' && echo PATH_EXPORTED",
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

	if got := col.String(); !strings.Contains(got, "PATH_EXPORTED") {
		t.Fatalf("child process cannot see PATH; output=%q server log=%s",
			got, srvLog.String())
	}
}
