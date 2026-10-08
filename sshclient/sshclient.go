// Package sshclient runs an SSH session over a WebSocket.
//
// It is the browser half of webssh, and the exact mirror of the server: the
// server accepts a WebSocket and hands the bytes to a wish SSH server, and
// this dials the same WebSocket and hands the bytes to an SSH client. Neither
// side interprets the SSH protocol for the other, which is why the server
// needed no changes to grow a browser front end.
//
// Nothing here touches syscall/js. The same code runs natively, which is what
// makes the session logic testable without a browser in the loop.
package sshclient

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

// Options configures a session.
type Options struct {
	// URL of the WebSocket endpoint, e.g. ws://host/ws or wss://host/ws.
	URL string

	// User to authenticate as.
	User string

	// Cols and Rows are the initial terminal geometry. They are requested
	// before the shell starts, so the first screenful is laid out correctly.
	Cols, Rows int

	// Command to run. Empty means an interactive shell.
	Command string

	// Term is the TERM value to request. Defaults to xterm-256color.
	Term string

	// OnData receives everything the remote side writes, including stderr
	// from the shell. It may be called from a goroutine and must be quick.
	OnData func([]byte)

	// OnClose is called once when the session ends, with the reason if there
	// was one.
	OnClose func(error)

	// HostKeyCallback verifies the server's host key. Left nil, nothing is
	// verified: a browser has no known_hosts to check against. Production
	// callers should pin a key.
	HostKeyCallback ssh.HostKeyCallback
}

// Session is a live connection.
type Session struct {
	sshSess *ssh.Session
	conn    *websocket.Conn
	cancel  context.CancelFunc

	// stdin is a queue rather than a direct writer: keystrokes have to keep
	// their order, and a write to the SSH channel can block, which must never
	// happen on the thread that is driving the JavaScript event loop.
	stdin chan []byte

	closeOnce sync.Once
	closeErr  error
}

// Dial opens a session and starts the remote program. It returns once the
// session is established, not when it ends.
func Dial(ctx context.Context, opts Options) (*Session, error) {
	if opts.Cols <= 0 {
		opts.Cols = 80
	}
	if opts.Rows <= 0 {
		opts.Rows = 24
	}
	if opts.Term == "" {
		opts.Term = "xterm-256color"
	}
	if opts.HostKeyCallback == nil {
		opts.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	// Bound by the caller's context, and cancelled when the session ends.
	ctx, cancel := context.WithCancel(ctx)

	wsConn, _, err := websocket.Dial(ctx, opts.URL, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("dial websocket: %w", err)
	}

	// SSH is a self-contained protocol on a byte stream, so the WebSocket only
	// has to be a reliable pipe in both directions.
	netConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

	// address is only used to label the connection in errors; there is no
	// meaningful host to verify against on the far side of a pipe.
	clientConn, chans, reqs, err := ssh.NewClientConn(netConn, opts.URL, &ssh.ClientConfig{
		User:            opts.User,
		HostKeyCallback: opts.HostKeyCallback,
	})
	if err != nil {
		cancel()
		_ = wsConn.Close(websocket.StatusNormalClosure, "")
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)

	sshSess, err := client.NewSession()
	if err != nil {
		cancel()
		_ = client.Close()
		return nil, fmt.Errorf("open session: %w", err)
	}

	if err := sshSess.RequestPty(opts.Term, opts.Rows, opts.Cols, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		cancel()
		_ = client.Close()
		return nil, fmt.Errorf("request pty: %w", err)
	}

	stdin, err := sshSess.StdinPipe()
	if err != nil {
		cancel()
		_ = client.Close()
		return nil, fmt.Errorf("stdin: %w", err)
	}
	stdout, err := sshSess.StdoutPipe()
	if err != nil {
		cancel()
		_ = client.Close()
		return nil, fmt.Errorf("stdout: %w", err)
	}
	stderr, err := sshSess.StderrPipe()
	if err != nil {
		cancel()
		_ = client.Close()
		return nil, fmt.Errorf("stderr: %w", err)
	}

	if opts.Command != "" {
		err = sshSess.Start(opts.Command)
	} else {
		err = sshSess.Shell()
	}
	if err != nil {
		cancel()
		_ = client.Close()
		return nil, fmt.Errorf("start remote program: %w", err)
	}

	s := &Session{
		sshSess: sshSess,
		conn:    wsConn,
		cancel:  cancel,
		stdin:   make(chan []byte, 64),
	}

	go s.pump(stdin, stdout, stderr, opts)

	return s, nil
}

// pump moves data in both directions until the remote side hangs up.
func (s *Session) pump(stdin io.WriteCloser, stdout, stderr io.Reader, opts Options) {
	go func() {
		for data := range s.stdin {
			if _, err := stdin.Write(data); err != nil {
				break
			}
		}
		_ = stdin.Close()
	}()

	var wg sync.WaitGroup
	deliver := func(r io.Reader) {
		defer wg.Done()
		buf := make([]byte, 8192)
		for {
			n, err := r.Read(buf)
			if n > 0 && opts.OnData != nil {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				opts.OnData(chunk)
			}
			if err != nil {
				return
			}
		}
	}
	wg.Add(2)
	go deliver(stdout)
	// The shell writes diagnostics to stderr; fold them into the same stream
	// rather than dropping them.
	go deliver(stderr)
	wg.Wait()

	waitErr := s.sshSess.Wait()
	s.close(waitErr)
	if opts.OnClose != nil {
		opts.OnClose(waitErr)
	}
}

// Write sends keystrokes to the remote program. It never blocks: if the remote
// end is not draining, the input is dropped rather than stalling the caller.
func (s *Session) Write(p []byte) error {
	select {
	case s.stdin <- p:
		return nil
	default:
		return fmt.Errorf("input buffer full")
	}
}

// Resize tells the remote program about a new terminal size. Without this a
// resized terminal leaves full-screen programs drawing to stale dimensions.
func (s *Session) Resize(cols, rows int) error {
	return s.sshSess.WindowChange(rows, cols) //nolint:wrapcheck
}

// Close ends the session.
func (s *Session) Close() error {
	s.close(nil)
	return s.closeErr
}

func (s *Session) close(cause error) {
	s.closeOnce.Do(func() {
		s.cancel()
		s.closeErr = s.conn.Close(websocket.StatusNormalClosure, "")
		close(s.stdin)
		_ = cause
	})
}
