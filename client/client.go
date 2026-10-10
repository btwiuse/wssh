// Package client runs an SSH session over a WebSocket.
//
// It is the browser half of webssh, and the exact mirror of the server: the
// server accepts a WebSocket and hands the bytes to a wish SSH server, and
// this dials the same WebSocket and hands the bytes to an SSH client. Neither
// side interprets the SSH protocol for the other, which is why the server
// needed no changes to grow a browser front end.
//
// Nothing here touches syscall/js. The same code runs natively, which is what
// makes the session logic testable without a browser in the loop.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	neturl "net/url"
	"os"
	"strconv"
	"sync"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrSessionClosed is returned when input is offered to a session that has
// already finished. It is a normal outcome, not a failure: a browser keeps
// delivering keystrokes until the page is reloaded, and the server may have
// gone away at any moment.
var ErrSessionClosed = errors.New("session closed")

// ErrInputFull is returned when the remote side is not draining fast enough.
// Only the non-blocking Write gives up like this; WriteContext waits instead.
var ErrInputFull = errors.New("input buffer full")

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
	// verified, which means anything between here and the server can
	// impersonate it. Callers that can should pin a key; see
	// golang.org/x/crypto/ssh/knownhosts, which reads the usual file.
	HostKeyCallback ssh.HostKeyCallback

	// Auth are the methods to offer, in the order they should be tried. Empty
	// means only "none" is possible, which every server here rejects once it
	// has any authentication handler installed.
	//
	// The caller decides what to offer. There is no guessing at ~/.ssh or the
	// environment: a browser has no home directory to read, and a password
	// typed into a terminal and a key uploaded to a page are not the same
	// thing to obtain.
	Auth []ssh.AuthMethod

	// AgentKeyPath, if set, is the path to a private key the dial
	// will load and use in two ways: as a publickey auth method
	// against the server, and as the basis for an in-band ssh-agent
	// served over the "auth-agent@openssh.com" channel. The same
	// key does both jobs, so the server can authenticate the user
	// with what it sees in the channel, and the channel can hand
	// out signatures for things the user does on the remote side.
	AgentKeyPath string
}

// Session is a live connection.
type Session struct {
	// sshClient is the underlying SSH client the session was opened
	// from. It is exported via Client() so callers that need to
	// open additional channels (notably the "auth-agent@openssh.com"
	// channel, for an in-band ssh-agent) can reach the same
	// connection. The session itself is a wrapper around an
	// *ssh.Session; the client is the layer that owns the
	// connection and the channels map.
	sshClient *ssh.Client
	sshSess   *ssh.Session
	conn      *websocket.Conn
	cancel    context.CancelFunc

	// stdin is a queue rather than a direct writer: keystrokes have to keep
	// their order, and a write to the SSH channel can block, which must never
	// happen on the thread that is driving the JavaScript event loop.
	stdin chan []byte
	done  chan struct{}

	closeOnce sync.Once
	stdinOnce sync.Once
	closeErr  error
}

// Client returns the underlying *ssh.Client the session was opened
// from. It is the same client the session's channel is multiplexed
// over, so additional channels (such as "auth-agent@openssh.com")
// opened through it share the session's authentication and lifetime.
//
// Returns nil only when Dial succeeded without producing a client,
// which today does not happen; callers can treat a nil return as
// "the session never started".
func (s *Session) Client() *ssh.Client {
	return s.sshClient
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
	// The SSH destination is the WebSocket authority, not the URL. That is
	// what identifies the far end everywhere else -- in known_hosts entries and
	// in the wording of a host key warning -- and a URL would not match either.
	parsed, err := neturl.Parse(opts.URL)
	if err != nil {
		cancel()
		_ = wsConn.Close(websocket.StatusNormalClosure, "")
		return nil, fmt.Errorf("parse %q: %w", opts.URL, err)
	}
	address := parsed.Host
	if address == "" {
		address = opts.URL
	}

	// Host key verification inspects the peer address and expects host:port.
	// The WebSocket reports a placeholder, which nothing can match, so the
	// connection is given one that describes where we actually dialled.
	netConn = &peerAddrConn{Conn: netConn, addr: webPeer(parsed)}

	// If an agent key path was given, the same key has to be
	// offered for publickey auth as well as exposed on the agent
	// channel. The two halves have to match: the server's
	// PublicKeyHandler must accept this key for the handshake to
	// succeed, after which the agent channel is the one the
	// remote side uses for further work.
	if opts.AgentKeyPath != "" {
		signer, err := loadAgentKey(opts.AgentKeyPath)
		if err != nil {
			cancel()
			_ = wsConn.Close(websocket.StatusNormalClosure, "")
			return nil, err
		}
		opts.Auth = append(opts.Auth, ssh.PublicKeys(signer))
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(netConn, address, &ssh.ClientConfig{
		User:            opts.User,
		HostKeyCallback: opts.HostKeyCallback,
		Auth:            opts.Auth,
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
		sshClient: client,
		sshSess:   sshSess,
		conn:      wsConn,
		cancel:    cancel,
		stdin:     make(chan []byte, 64),
		done:      make(chan struct{}),
	}

	// If an agent key path was given, open the auth-agent channel on
	// the same connection and tell the server we want agent
	// forwarding. The same key is what the server saw during auth,
	// so the channel can answer signatures for the rest of the
	// session, including whatever the remote shell tries to do over
	// its forwarded agent.
	if opts.AgentKeyPath != "" {
		if err := s.openAgent(opts.AgentKeyPath); err != nil {
			_ = s.Close()
			return nil, err
		}
	}

	go s.pump(stdin, stdout, stderr, opts)

	return s, nil
}

// openAgent loads the key at path, opens an "auth-agent@openssh.com"
// channel on the session's underlying *ssh.Client, and asks the
// server to forward that channel to any further sessions the user
// opens on the remote side (the "ssh -A" equivalent).
//
// The key is loaded with ssh.ParsePrivateKey. Encrypted keys are
// not supported: passphrase prompting is the wrong shape for a
// browser-driven dial and is also out of scope for the typical CLI
// use of this option, where the key file is meant to be the one
// matching the server's --authorized-keys.
//
// The auth method is built on top of an in-memory ssh-agent: the
// same key is exposed to the server as both a PublicKeys auth
// method and as a signable entry in the agent's keyring. The agent
// lives on a goroutine that pumps bytes between the SSH channel and
// the keyring.
func (s *Session) openAgent(path string) error {
	signer, err := loadAgentKey(path)
	if err != nil {
		return err
	}
	// Open the agent channel. The server's agentkey handler accepts
	// any auth-agent@openssh.com channel; bytes on it are the
	// standard agent protocol.
	ch, reqs, err := s.sshClient.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return fmt.Errorf("open agent channel: %w", err)
	}
	go ssh.DiscardRequests(reqs)

	// Build a tiny agent that holds the one key, and serve it on
	// the channel. The signer ssh.ParsePrivateKey just returned is already
	// exactly what the agent protocol asks for, so it goes in as it is.
	ring, err := agentkey.Keyring([]ssh.Signer{signer})
	if err != nil {
		_ = ch.Close()
		return fmt.Errorf("build agent keyring: %w", err)
	}
	go func() {
		defer ch.Close() //nolint:errcheck
		// Discard the expected close errors (channel/EOF); anything
		// else is a real problem that the user should know about.
		if err := agent.ServeAgent(ring, ch); err != nil && !isExpectedAgentClose(err) {
			_ = err // debug builds may want a hook here
		}
	}()

	// Request agent forwarding for any further sessions the
	// remote side might start (the equivalent of openssh's `ssh
	// -A`). On the server side this is just a global request; if
	// the server has the auth-agent-req handler installed, the
	// remote shell will see SSH_AUTH_SOCK set when it starts.
	if err := agent.RequestAgentForwarding(s.sshSess); err != nil {
		// Forwarding is a best-effort hint; the channel we just
		// opened still works for direct sign requests from this
		// process. The user will simply not get the agent when
		// they SSH further from the remote side.
		_ = err
	}
	return nil
}

// loadAgentKey reads a private key from disk and wraps it in an
// ssh.Signer. The wrapper is good enough for PublicKeys auth
// (which only needs PublicKey); the in-memory agent uses
// ExtractSigner on the same value to recover the underlying
// crypto.Signer. Encrypted keys are rejected -- passphrase
// prompting is the wrong shape for a browser-driven dial.
func loadAgentKey(path string) (ssh.Signer, error) {
	raw, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read agent key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse agent key %s: %w", path, err)
	}
	return signer, nil
}

// pump moves data in both directions until the remote side hangs up.
func (s *Session) pump(stdin io.WriteCloser, stdout, stderr io.Reader, opts Options) {
	// Input is queued on a channel that is never closed. Closing it would be
	// the obvious way to end the writer, but any later Write would then panic
	// on a send to a closed channel -- and in WebAssembly an unrecovered panic
	// takes the whole runtime down, so the page would need reloading to get a
	// terminal back. Closure travels on s.done instead, and only this
	// goroutine ever listens on both.
	go func() {
		for {
			select {
			case data := <-s.stdin:
				if _, err := stdin.Write(data); err != nil {
					return
				}
			case <-s.done:
				// End of input: tell the remote, but leave the connection
				// open so it can finish and report.
				_ = stdin.Close()
				return
			}
		}
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
//
// That suits a browser, where stalling the callback would stall the whole
// event loop. A terminal wants the opposite; see WriteContext.
func (s *Session) Write(p []byte) error {
	// Check first: with buffer room available, the select below would pick
	// between accepting the keystroke and reporting the session as over at
	// random, and a caller asking whether its input landed deserves a real
	// answer rather than a coin toss.
	select {
	case <-s.done:
		return ErrSessionClosed
	default:
	}
	select {
	case s.stdin <- p:
		return nil
	case <-s.done:
		return ErrSessionClosed
	default:
		return ErrInputFull
	}
}

// WriteContext queues keystrokes, waiting for room rather than dropping them.
// A terminal should never silently lose what someone typed.
func (s *Session) WriteContext(ctx context.Context, p []byte) error {
	// Prefer saying the session is over over accepting input that nobody is
	// left to read: with buffer room available, the select below would pick
	// either case at random.
	select {
	case <-s.done:
		return ErrSessionClosed
	default:
	}
	select {
	case s.stdin <- p:
		return nil
	case <-s.done:
		return ErrSessionClosed
	case <-ctx.Done():
		return ctx.Err()
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
		s.CloseStdin()
		_ = cause
	})
}

// CloseStdin signals end of input to the remote program while leaving the
// connection open.
//
// This is not the same as Close. Tearing the socket down the moment stdin
// ends means the far side never gets to read what is already buffered and
// never gets to report anything; sending EOF instead lets a shell finish its
// last command and exit on its own terms.
//
// Calling it more than once is fine, and writing to a session afterwards is
// safe: it reports ErrSessionClosed rather than falling over.
func (s *Session) CloseStdin() {
	s.stdinOnce.Do(func() { close(s.done) })
}

// peerAddrConn reports a network-shaped address for a WebSocket connection.
type peerAddrConn struct {
	net.Conn
	addr net.Addr
}

func (c *peerAddrConn) RemoteAddr() net.Addr { return c.addr }

// webPeer turns the WebSocket URL into an address with a port, defaulting the
// way the scheme implies.
func webPeer(u *neturl.URL) net.Addr {
	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" || u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return &net.TCPAddr{}
	}
	return &net.TCPAddr{IP: net.ParseIP(u.Hostname()), Port: number}
}

// isExpectedAgentClose matches the closed-connection errors that bubble
// up from agent.ServeAgent when the SSH channel ends before the agent
// does. They are not worth logging: a client tearing down the
// session is the normal end. The sentinels are not exported, so
// match by message instead.
func isExpectedAgentClose(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	return msg == "EOF" ||
		msg == "io: read/write on closed pipe" ||
		msg == "use of closed network connection" ||
		msg == "channel not open"
}
