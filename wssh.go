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
	"net"
	"net/http"

	"charm.land/log/v2"
	"charm.land/ssh"
	"charm.land/wish/v2"
	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
	"github.com/coder/websocket"
	gossh "golang.org/x/crypto/ssh"
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
	// "auth-agent@openssh.com" channel. Build it with agentkey.Keyring. The
	// loaded keys are kept in this process: clients can sign with any of
	// them, so the same authentication rule that applies to
	// --authorized-keys applies here.
	Agent agentkey.Agent

	// WalletAuth lets a browser that owns a Solana account connect by signing
	// a short readable message, rather than the binary blob SSH authentication
	// requires. Nil, or an empty allow list, leaves it off.
	WalletAuth *siws.SIWSAuth

	// ForwardAgent makes the *client's* agent available to sessions on
	// the same connection, which is what `ssh -A` does: the client keeps
	// its keys and the server asks it to sign.
	//
	// This is the opposite direction to Agent, and a different shape of
	// trust. Nothing about the private key crosses the connection, but
	// anything running in the session can have the client sign anything
	// it asks for. Off unless asked for.
	//
	// It only takes effect together with agentkey.Forward() in the
	// Middleware list. Note the order: wish composes middleware from first
	// to last with the last one outermost, so Forward has to come *after*
	// the shell middleware in the slice to run before it, which is what
	// puts the socket in place before the environment is built.
	ForwardAgent bool

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

	// Copied for the same reason the channel map is: the request handlers are
	// a package-level variable too, and InstallForwarding writes into this
	// one. Aliasing it would hand every other server in the process an agent
	// forwarder it never asked for.
	requests := make(map[string]ssh.RequestHandler, len(ssh.DefaultRequestHandlers))
	for name, handler := range ssh.DefaultRequestHandlers {
		requests[name] = handler
	}
	sessions.RequestHandlers = requests
	sessions.SubsystemHandlers = ssh.DefaultSubsystemHandlers

	if opts.AllowTcpForwarding {
		// DirectTCPIPHandler reads the destination from the channel data and
		// dials it itself, but only once this callback agrees. It is what
		// rejects the channel otherwise.
		channels["direct-tcpip"] = ssh.DirectTCPIPHandler
		sessions.LocalPortForwardingCallback = func(ssh.Context, string, uint32) bool { return true }
	}

	if opts.ForwardAgent {
		agentkey.InstallForwarding(sessions)
	}

	if opts.WalletAuth != nil && opts.WalletAuth.Enabled() {
		installWalletAuth(sessions, opts.WalletAuth)
	}

	if opts.Agent != nil {
		// The agent's agentkey.Forwarding option mutates ChannelHandlers
		// and RequestHandlers on the server, but we reset ChannelHandlers
		// to a fresh copy of defaults right above, so the option has
		// already been clobbered. Re-apply it directly to the map
		// instead. This keeps the agent channel alongside the session
		// and direct-tcpip handlers in one place.
		agentkey.Install(sessions, opts.Agent)
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

	// A client that is willing to sign in says so by offering this
	// subprotocol, and it is echoed back only when this server will ask. That
	// is what keeps the exchange out of the way of an ordinary connection: a
	// client that sees no subprotocol goes straight into SSH without waiting
	// to find out whether anyone was going to ask it anything.
	var subprotocols []string
	if s.opts.WalletAuth != nil && s.opts.WalletAuth.Enabled() {
		subprotocols = []string{SIWSSubprotocol}
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: s.opts.OriginPatterns,
		Subprotocols:   subprotocols,
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

	// A wallet sign-in happens here, over the same WebSocket, before any SSH
	// byte moves. It is in band for the same reason public key authentication
	// is: the connection is already open, so the server can ask a question and
	// get an answer on it, and a refused sign-in can say why.
	//
	// Doing it here rather than in the URL is what keeps the credential out of
	// proxy logs, browser history and the address bar. It also means there is
	// no second endpoint and no separate protocol on the side.
	// Asked only of clients that asked to be asked. Sending the challenge to
	// everyone put the bytes of a sign-in request in front of a client that
	// came with a key and never wanted one, which is functionally the same as
	// refusing it.
	var authorized bool
	if conn.Subprotocol() == SIWSSubprotocol {
		authorized = s.exchangeSignIn(ctx, conn, r.Host)
		if !authorized {
			// The reason has already gone back over the socket, in full.
			_ = conn.Close(websocket.StatusPolicyViolation, "sign-in refused")
			return
		}
	}

	// A wallet sign-in arrives in the query string, because a browser cannot
	// set headers on a WebSocket. It rides along on the connection rather than
	// being checked here: this handler is the one place that can see the HTTP
	// request, and the SSH server has already started by the time it returns.
	var netConn net.Conn = websocket.NetConn(ctx, conn, websocket.MessageBinary)
	if authorized {
		netConn = &walletConn{Conn: netConn, authorized: true}
	}
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

// ServeTCP drives raw TCP connections on ln as SSH sessions, the same way
// ssh -p PORT host reaches the same server the browser reaches over a
// WebSocket. The wish Server carries the host key, channel handlers, and
// wish middleware - NewServer installs them all - so HandleConn on a raw
// conn is enough to share the configuration without rebuilding it.
//
// The function blocks until ln is closed or Accept fails for another reason.
// A closed listener returns immediately with no error, since that is how
// this Server is shut down; per-connection errors stay on the goroutines
// that ran HandleConn.
func (s *Server) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close() //nolint:errcheck
			s.opts.Logger.Debug("session starting", "remote", c.RemoteAddr().String(), "scheme", "tcp/ssh")
			s.sessions.HandleConn(c)
			s.opts.Logger.Debug("session finished", "remote", c.RemoteAddr().String(), "scheme", "tcp/ssh")
		}(conn)
	}
}

// walletAddressKey marks a connection that arrived with a verified wallet
// sign-in. It is read by the config hook below, and by nothing else.
const walletAddressKey = "wssh.wallet-address"

// walletConn carries a completed sign-in to the point where it is needed.
//
// The SSH server builds its own context per connection, having already started
// the handshake by the time anything can be attached to it, so the fact that
// the sign-in worked has to ride in on the connection itself.
type walletConn struct {
	net.Conn
	authorized bool
}

// installWalletAuth makes a verified wallet sign-in into a completed SSH
// authentication.
//
// SSH's own authentication cannot be satisfied by a wallet: its challenge is
// binary and a wallet will not sign it. So the exchange above answers a
// different question, and the handshake is then told not to ask one. Nothing
// about the SSH protocol changes; a connection that has proved itself is let
// through the way an unauthenticated server allows everything, except that here
// it had to prove something first.
func installWalletAuth(srv *ssh.Server, cfg *siws.SIWSAuth) {
	prevConn := srv.ConnCallback
	srv.ConnCallback = func(ctx ssh.Context, conn net.Conn) net.Conn {
		if prevConn != nil {
			if conn = prevConn(ctx, conn); conn == nil {
				return nil
			}
		}
		carrier, ok := conn.(*walletConn)
		if !ok || !carrier.authorized {
			return conn
		}
		ctx.SetValue(walletAddressKey, true)
		return conn
	}

	// Configuring wallet sign-in has to mean the server requires something.
	// With no SSH handler installed, wish allows every connection, so an
	// operator who set --authorized-addresses and nothing else would be running
	// an open server while believing the opposite. Installing a handler that
	// refuses everything closes that: a verified connection is let through by
	// the config hook below, and everyone else has nothing that works.
	if srv.PublicKeyHandler == nil && srv.PasswordHandler == nil &&
		srv.KeyboardInteractiveHandler == nil {
		srv.PublicKeyHandler = func(ssh.Context, ssh.PublicKey) bool { return false }
	}

	// A connection that proved itself needs no further authentication. This is
	// per connection, which is why it works at all: the flag lives on the
	// config this hook builds, not on the server.
	prevConfig := srv.ServerConfigCallback
	srv.ServerConfigCallback = func(ctx ssh.Context) *gossh.ServerConfig {
		var config *gossh.ServerConfig
		if prevConfig != nil {
			config = prevConfig(ctx)
		} else {
			config = &gossh.ServerConfig{}
		}
		if ctx.Value(walletAddressKey) != nil {
			config.NoClientAuth = true
		}
		return config
	}
}
