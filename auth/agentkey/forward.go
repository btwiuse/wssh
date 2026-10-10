package agentkey

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"charm.land/log/v2"
	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Forwarding makes the *client's* agent available to sessions on the same
// connection. It is the direction openssh calls agent forwarding: the client
// keeps its keys, the server relays signing requests back to it, and
// SSH_AUTH_SOCK in the session points at a socket that answers by asking.
//
// The private key never crosses. A signature request names a public key and a
// blob; the reply is a signature over that blob and nothing else. What that
// buys is a signer that can ask the user before answering, which a key handed
// over in advance cannot.
//
// The trust is worth stating plainly: once forwarding is on, anything running
// in the session can have the client sign anything it asks for. That is what
// `ssh -A` means, and it is why this is a separate switch from Install rather
// than something the presence of keys implies.
//
// Install registers the global request. Forward is the middleware to put ahead
// of the shell middleware. They are separate because a server that never sees
// the request must not pay for the machinery, and a caller that forwards
// should not have to remember to also install a request handler.
type forwardState struct {
	mu     sync.Mutex
	ready  bool
	client agent.Agent
}

// forwardCtxKey holds the per-connection *forwardState. The SSH context is
// per connection, so this is naturally shared by every session on it, which is
// what we want: one channel to the client, one socket, many sessions.
const forwardCtxKey = "wssh.agent-forward-state"

// Middleware is what wish calls middleware, aliased rather than imported so
// that this package stays free of wish. The browser client imports this
// package, and wish pulls in bubbletea, which has no js/wasm build.
type Middleware = func(ssh.Handler) ssh.Handler

// Forward is the middleware that makes the client's agent reachable from a
// session. It has to run before the shell middleware, so that the socket
// exists by the time the environment is built.
//
// Which in the slice means *last*: wish composes middleware from first to last
// with the last one outermost. []Middleware{shell, Forward} is what you want,
// and it reads backwards, so say so in a comment wherever it is assembled.
func Forward() Middleware {
	return func(next ssh.Handler) ssh.Handler {
		return func(s ssh.Session) {
			// Subsystems are not shells and do not get SSH_AUTH_SOCK, but
			// sftp-style transfers would benefit from the same socket, so
			// the hook runs for them too.
			attach(s)
			next(s)
		}
	}
}

// attach opens the connection back to the client, once per connection, and
// publishes the local socket path on the context for environ() to pick up.
//
// Failure is not an error. A client that asked for forwarding and then closed
// the channel, or an older client that asked without offering anything, should
// get an ordinary session with no SSH_AUTH_SOCK rather than a rejected one.
func attach(s ssh.Session) {
	if !ssh.AgentRequested(s) {
		return
	}
	ctx := s.Context()
	conn, ok := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)
	if !ok {
		log.Debug("agent forwarding requested but no connection on the context")
		return
	}

	state, _ := ctx.Value(forwardCtxKey).(*forwardState)
	if state == nil {
		state = &forwardState{}
		ctx.SetValue(forwardCtxKey, state)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.ready {
		return
	}

	ch, reqs, err := conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		log.Debug("could not reach the client's agent", "error", err)
		return
	}
	go gossh.DiscardRequests(reqs)

	upstream := agent.NewClient(ch)
	path, closeSocket, err := listenRelay(upstream)
	if err != nil {
		_ = ch.Close()
		log.Debug("relayed agent socket", "error", err)
		return
	}

	state.ready = true
	ctx.SetValue(SSHAuthSockKey, path)
	go func() {
		<-ctx.Done()
		closeSocket()
		_ = ch.Close()
	}()
}

// listenRelay publishes upstream on a local socket: every connection to it is
// answered by holding the agent conversation up the SSH channel to the client.
//
// Requests are serialised. agent.NewClient keeps one channel and one sequence
// number, so two concurrent conversations on it would interleave into garbage.
// The cost is that a slow signer holds up the next request behind it, which is
// the right way round: a signature waiting on a human should queue rather than
// have the requests it is queued with answered out of order.
func listenRelay(upstream agent.Agent) (string, func(), error) {
	dir, err := os.MkdirTemp("", "wssh-agent-fwd-")
	if err != nil {
		return "", nil, fmt.Errorf("relay tempdir: %w", err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "agent.sock"))
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("relay listen: %w", err)
	}

	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				mu.Lock()
				defer mu.Unlock()
				_ = agent.ServeAgent(upstream, c)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
		_ = os.RemoveAll(dir)
	}, nil
}
