// Package wssh serves SSH sessions over a WebSocket.
//
// A client dials it with a stock ssh client and a byte-stream proxy:
//
//	ssh -o 'ProxyCommand=websocat -b wss://host:port' user@host
//
// The trick is that SSH already is a self-contained protocol on a byte stream:
// key exchange, authentication and window-change requests all travel in-band.
// So the WebSocket layer does not have to understand any of it, it only has to
// be a reliable bidirectional pipe. That keeps the transport honest -- resizes
// and ^C work over the WebSocket for exactly the same reason they work over
// TCP.
//
// A Server is an http.Handler, so binding it to a port is the caller's job:
//
//	ln, _ := net.Listen("tcp", ":8080")
//	http.Serve(ln, server)
package wssh

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"charm.land/log/v2"
	"charm.land/ssh"
	"charm.land/wish/v2"
	"github.com/btwiuse/wssh/auth/authfwd"
	"github.com/coder/websocket"
)

// Options configures a Server.
type Options struct {
	// HostKeyPath is the ed25519 host key, generated on first use. It must
	// stay stable across restarts: change it and every client reports a host
	// key mismatch. Point it at a mounted volume on ephemeral platforms.
	HostKeyPath string

	// Middleware runs for every session, outermost first.
	Middleware []wish.Middleware

	// Pty allocates a pseudo-terminal, which is what makes an interactive
	// shell possible.
	Pty bool

	// OriginPatterns restricts which Origin headers are accepted. Empty
	// disables the check, which is the right default for ssh(1) and
	// websocat: neither sends an Origin, so there is nothing to verify.
	OriginPatterns []string

	// Path is the URL path sessions are served on. Empty, the default, means
	// any path opens one, which is what a bare SSH server wants: it serves
	// nothing else, so there is nothing to collide with. Set it when the same
	// port also serves other things, as the browser front end does.
	Path string

	// AllowTcpForwarding enables the direct-tcpip channel, which backs
	// `ssh -L` and `ssh -D`. Off by default.
	//
	// Read this before turning it on: direct-tcpip lets the client name an
	// arbitrary destination and the server dials it on the client's behalf.
	// Unrestricted, that is an open proxy into whatever network the server
	// can reach -- loopback services and cloud metadata endpoints included.
	// Pair it with authentication before exposing this to anyone.
	AllowTcpForwarding bool

	// SSHOptions are extra options handed straight to the underlying SSH
	// server, applied after the structured settings above. This is how
	// authentication is installed: see package auth.
	//
	// The zero value accepts every connection, because the SSH server allows
	// unauthenticated clients only while no auth handler is installed. Passing
	// anything from package auth turns authentication on.
	SSHOptions []ssh.Option

	// Agent, when non-nil, exposes an in-memory ssh-agent over the
	// "auth-agent@openssh.com" channel. Build it with authfwd.Keyring. The
	// loaded keys are kept in this process: clients can sign with any of
	// them, so the same authentication rule that applies to
	// --authorized-keys applies here.
	Agent authfwd.Agent

	// Logger receives session-level detail. Defaults to the charm default
	// logger, which honours whatever level the process has set.
	Logger *log.Logger
}

// Server accepts WebSocket requests and serves each one as an SSH session.
type Server struct {
	sessions *ssh.Server
	opts     Options
}

var _ http.Handler = (*Server)(nil)

// NewServer builds the SSH side. It knows nothing about how requests arrive.
func NewServer(opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}

	sshOpts := []ssh.Option{
		// Set explicitly: left to itself wish generates a key in the working
		// directory, which litters the repo and changes on every fresh deploy.
		wish.WithHostKeyPath(opts.HostKeyPath),
		wish.WithMiddleware(opts.Middleware...),
	}
	if opts.Pty {
		sshOpts = append(sshOpts, ssh.AllocatePty())
	}
	// Applied last so callers can override anything above.
	sshOpts = append(sshOpts, opts.SSHOptions...)

	sessions, err := wish.NewServer(sshOpts...)
	if err != nil {
		return nil, fmt.Errorf("create ssh server: %w", err)
	}

	// HandleConn skips the setup that Serve does, so install the default
	// handlers here. Without the "session" channel handler every channel open
	// is rejected with "unsupported channel type", immediately after
	// authentication has already succeeded.
	//
	// The map is copied rather than aliased: DefaultChannelHandlers is a
	// package-level variable, so writing to it in place would leak the
	// direct-tcpip handler into every other server in the process.
	channels := make(map[string]ssh.ChannelHandler, len(ssh.DefaultChannelHandlers)+1)
	for name, handler := range ssh.DefaultChannelHandlers {
		channels[name] = handler
	}
	sessions.ChannelHandlers = channels
	sessions.RequestHandlers = ssh.DefaultRequestHandlers
	sessions.SubsystemHandlers = ssh.DefaultSubsystemHandlers

	if opts.AllowTcpForwarding {
		// DirectTCPIPHandler reads the destination from the channel data and
		// dials it itself, but only once this callback agrees. It is what
		// rejects the channel otherwise.
		channels["direct-tcpip"] = ssh.DirectTCPIPHandler
		sessions.LocalPortForwardingCallback = func(ssh.Context, string, uint32) bool { return true }
	}

	if opts.Agent != nil {
		// The agent's authfwd.Forwarding option mutates ChannelHandlers
		// and RequestHandlers on the server, but we reset ChannelHandlers
		// to a fresh copy of defaults right above, so the option has
		// already been clobbered. Re-apply it directly to the map
		// instead. This keeps the agent channel alongside the session
		// and direct-tcpip handlers in one place.
		authfwd.Install(sessions, opts.Agent)
	}

	return &Server{sessions: sessions, opts: opts}, nil
}

// ServeHTTP completes the WebSocket handshake and hands the resulting byte
// stream to the SSH server, which runs the handshake and then the session to
// completion. It blocks for the life of the session.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only a configured path narrows this down. With none set, any path opens
	// a session: there is nothing else on the server to collide with, and a
	// client is then free to use whatever URL it likes.
	if s.opts.Path != "" && r.URL.Path != s.opts.Path {
		http.NotFound(w, r)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: s.opts.OriginPatterns,
		// The payload is already encrypted. Compressing it burns CPU on both
		// ends and leaks plaintext length over the wire.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		// Accept has already written the error response.
		s.opts.Logger.Debug("upgrade failed", "error", err, "remote", r.RemoteAddr)
		return
	}

	// The socket must not hang off r.Context(): this handler blocks for the
	// whole session, and the session is what keeps it alive.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	netConn := websocket.NetConn(ctx, conn, websocket.MessageBinary)
	defer netConn.Close() //nolint:errcheck

	s.opts.Logger.Debug("session starting", "remote", r.RemoteAddr)
	s.sessions.HandleConn(netConn)
	s.opts.Logger.Debug("session finished", "remote", r.RemoteAddr)
}

// Shutdown stops the server, letting live sessions finish within ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.sessions.Shutdown(ctx); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}
