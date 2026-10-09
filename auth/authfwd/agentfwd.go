// Package authfwd exposes an in-memory ssh-agent to clients, plus the
// wish options that wire the agent protocol into the server.
//
// The agent speaks the standard ssh-agent protocol on a single SSH channel:
// the client opens a channel of type "auth-agent@openssh.com" and the bytes
// on that channel are the agent protocol. Keys never leave the process and
// every request is served from memory. That makes the agent a different
// shape of trust from authorized_keys: a client that has been allowed to
// forward the agent can sign with any of the loaded keys, so any one of
// them can be used to log in to anything that accepts them.
//
// Forwarding is off until Forwarding() is given a non-nil agent. The
// returned wish option is a no-op when no agent is configured, mirroring
// the pattern in package auth.
package authfwd

import (
	"crypto"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"unsafe"

	"charm.land/log/v2"
	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Agent is the interface served to clients over the "auth-agent@openssh.com"
// channel. It is re-exported here so callers do not have to import x/crypto/ssh
// just to type an Options field.
type Agent = agent.Agent

// SSHAuthSockKey is the context key under which a per-connection
// local Unix socket path is stashed when an auth-agent channel is
// available. The shell middleware reads it from the session's
// charm.land/ssh.Context and appends "SSH_AUTH_SOCK=<path>" to
// the environment of any shell it spawns, so openssh tools on
// the remote side find a normal local agent.
//
// The key is exported so that other middleware (in particular
// the shell middleware in this repository) can read the value
// without importing any internal type. Setting and reading
// the value is by string comparison; the path is stored as a
// plain string and the empty string means "no agent available".
const SSHAuthSockKey = "wssh.ssh-auth-sock"

// wrappedSignerShape mirrors the private type of the same name in
// golang.org/x/crypto/ssh. The first field must be a crypto.Signer;
// nothing else here matters -- we only need the offset of the signer
// field, which is the first one (offset zero), to read it back out
// of an *ssh.Signer that we know is a *wrappedSigner.
//
// The reflect-based approaches all blow up on Termux because
// reflect.ValueOf on a value whose concrete type is unexported
// ends up dereferencing type-name tables that the runtime does
// not have. Casting to a local type of identical layout works
// because the runtime only resolves the field types at the point
// of access, and crypto.Signer is exported.
type wrappedSignerShape struct {
	signer crypto.Signer
}

// ExtractSigner returns the underlying crypto.Signer that a gossh.Signer
// wraps. The wrapper (wrappedSigner) keeps the inner crypto.Signer in
// an unexported field; reaching in with unsafe is the only way to get
// it out without going through ParsePrivateKey, which discards the
// key material after parsing.
//
// The trick is the only place in the package that depends on the
// private struct layout of golang.org/x/crypto/ssh. If a future
// version of that package changes the field name or type, this
// function will fail with a clear error; the test that uses it
// covers that path.
func ExtractSigner(s gossh.Signer) (crypto.Signer, error) {
	// The interface header of `s` is 16 bytes: the type descriptor
	// of the concrete type, then the value pointer. For a
	// *ssh.wrappedSigner, that value pointer points at a
	// wrappedSigner struct whose first field is a crypto.Signer.
	// We re-interpret the value pointer as a pointer to our
	// shape and read the first field. Going through unsafe.Pointer
	// for the header copy (rather than uintptr) is the rule
	// that keeps go vet happy and is also the more correct
	// pattern: uintptr round-trips can lose the GC's
	// "this pointer is in use" tracking, while unsafe.Pointer
	// does not.
	type ifaceHeader struct {
		_    unsafe.Pointer
		data unsafe.Pointer
	}
	hdr := (*ifaceHeader)(unsafe.Pointer(&s))
	inner := (*wrappedSignerShape)(hdr.data)
	return inner.signer, nil
}

// Keyring builds an in-memory agent.Agent from the given crypto signers.
// The keys are the underlying values: ed25519.PrivateKey, *rsa.PrivateKey,
// *ecdsa.PrivateKey, or any other crypto.Signer. The simplest way to get
// one is to parse a private key file with gossh.ParsePrivateKey and
// type-assert the result to crypto.Signer (which all the standard
// implementations returned by ParsePrivateKey satisfy). nil is returned
// with no error when keys is empty, so callers can use the result
// unconditionally.
func Keyring(keys []crypto.Signer) (Agent, error) {
	if len(keys) == 0 {
		return nil, nil //nolint:nilnil
	}
	ring := agent.NewKeyring()
	for _, k := range keys {
		added := agent.AddedKey{
			PrivateKey: k,
			Comment:    keyType(k),
		}
		if err := ring.Add(added); err != nil {
			return nil, fmt.Errorf("add key: %w", err)
		}
	}
	return ring, nil
}

// keyType picks a human-readable comment for the agent. The agent's
// serialiser only really cares about the PrivateKey, but the comment
// surfaces in `ssh-add -l` on the client and is what makes the keys
// recognisable.
func keyType(k crypto.Signer) string {
	if pub, err := gossh.NewPublicKey(k.Public()); err == nil {
		return pub.Type()
	}
	return "ssh-agent-key"
}

// Install registers the auth-agent channel and request handlers on the
// given server, exposing the supplied agent over a per-session channel
// of type "auth-agent@openssh.com". Pass nil to no-op.
//
// In addition to the channel, Install sets up a per-connection local
// Unix socket that serves the same keyring. The socket path is
// stashed on the per-connection context under SSHAuthSockKey so the
// shell middleware can append it to the session env as
// `SSH_AUTH_SOCK=<path>`. That is what makes `ssh -A` from inside
// the remote side find a working local agent: any program that
// opens SSH_AUTH_SOCK gets the same in-memory keyring the
// client was offered during auth.
//
// The socket is created eagerly on every connection, not lazily
// when the channel opens. The shell may run before the auth-agent
// channel does, and the env has to be set at exec time, so the
// listener has to exist by then. The cost is one Unix socket per
// connection; the benefit is that SSH_AUTH_SOCK is always
// correct, and the listener gets cleaned up at session end
// whether the channel ever opened or not.
func Install(srv *ssh.Server, ring Agent) {
	if ring == nil {
		return
	}
	if srv.RequestHandlers == nil {
		srv.RequestHandlers = map[string]ssh.RequestHandler{}
	}
	srv.RequestHandlers["auth-agent-req@openssh.com"] = func(_ ssh.Context, _ *ssh.Server, _ *gossh.Request) (bool, []byte) {
		return true, nil
	}

	if srv.ChannelHandlers == nil {
		srv.ChannelHandlers = map[string]ssh.ChannelHandler{}
	}
	srv.ChannelHandlers["auth-agent@openssh.com"] = func(_ *ssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, _ ssh.Context) {
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		// agent.ServeAgent drives the protocol on an io.ReadWriter;
		// the SSH channel implements both. In-channel requests (env,
		// shell) are not part of the agent protocol, so they are
		// drained and discarded.
		go drainRequests(reqs)
		go func() {
			defer ch.Close() //nolint:errcheck
			if err := agent.ServeAgent(ring, ch); err != nil && !isExpectedClose(err) {
				log.Debug("agent channel ended", "error", err)
			}
		}()
	}

	// Per-connection local agent socket. The ConnCallback fires
	// once per SSH connection, before auth; the context's
	// SetValue/Value are how we hand the socket path to the
	// shell middleware later. The listener outlives this
	// function call: it is closed by the goroutine that waits
	// on the channel from the same context, and the temp dir
	// is removed when the listener is closed.
	prev := srv.ConnCallback
	srv.ConnCallback = func(ctx ssh.Context, c net.Conn) net.Conn {
		if prev != nil {
			c = prev(ctx, c)
			if c == nil {
				return nil
			}
		}
		path, cleanup, err := listenLocal(ring)
		if err != nil {
			log.Debug("local agent listener: %v", err)
			return c
		}
		ctx.SetValue(SSHAuthSockKey, path)
		// Watch the connection for closure and clean up the
		// socket then. A timer-based sweep would also work,
		// but a context watch is bounded by the same lifetime
		// as the listener, which is what we want.
		go cleanupOnClose(ctx, path, cleanup)
		return c
	}
}

// Forwarding returns a wish option equivalent to Install. Use Install
// when the server is in hand and the option style when wiring from a
// fresh wish.NewServer call. Both close over the same handlers.
func Forwarding(ring Agent) ssh.Option {
	return func(srv *ssh.Server) error {
		Install(srv, ring)
		return nil
	}
}

// drainRequests consumes channel-level requests that are not part of the
// agent protocol. agent.ServeAgent already handles its own message loop;
// any other request that arrives on the channel has nowhere to go.
func drainRequests(reqs <-chan *gossh.Request) {
	for r := range reqs {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}

// isExpectedClose matches the closed-connection errors that bubble up from
// the agent protocol when the SSH channel ends before the agent does. They
// are not worth logging: a client tearing down the channel is the normal
// end of a session.
func isExpectedClose(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	return msg == "EOF" ||
		msg == "io: read/write on closed pipe" ||
		msg == "use of closed network connection" ||
		msg == "channel not open"
}

// listenLocal creates a tempdir, a Unix socket inside it, and a
// goroutine that runs agent.ServeAgent against every accepted
// connection. The returned path is what goes into SSH_AUTH_SOCK;
// the returned cleanup closes the listener and removes the
// tempdir.
func listenLocal(ring Agent) (string, func(), error) {
	dir, err := os.MkdirTemp("", "wssh-agent-")
	if err != nil {
		return "", nil, fmt.Errorf("agent tempdir: %w", err)
	}
	path := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("agent listen: %w", err)
	}
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
				_ = agent.ServeAgent(ring, c)
			}(conn)
		}
	}()
	cleanup := func() {
		_ = ln.Close()
		<-done
		_ = os.RemoveAll(dir)
	}
	return path, cleanup, nil
}

// cleanupOnClose blocks until the SSH connection's context is
// cancelled (i.e., the connection ended) and then calls cleanup.
// A per-connection goroutine like this is fine: connections
// number in the dozens, not the thousands, and the only thing
// it does after the wait is unlink a tempdir and close a
// listener. The charm.land/ssh Context interface embeds
// context.Context, so the Done() method is available without a
// type assertion.
func cleanupOnClose(ctx ssh.Context, _ string, cleanup func()) {
	<-ctx.Done()
	cleanup()
}
