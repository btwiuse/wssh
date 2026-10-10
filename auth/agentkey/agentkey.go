// Package agentkey exposes a fixed set of signing keys to sessions as a
// standard ssh-agent: over the "auth-agent@openssh.com" SSH channel, and over
// a per-connection local socket whose path becomes SSH_AUTH_SOCK. Both serve
// the same keys, so a program in the session signs with them either way.
//
// The direction is what makes this worth spelling out, because it is the
// opposite of OpenSSH's agent forwarding. `ssh -A` hands the remote a copy of
// the *client's* agent, and the risk there is the client choosing to keep
// using it. This hands every session keys the *server* was configured with,
// and the risk is that anyone who can reach the server can sign with them.
// That is a different shape of trust from authorized_keys, where being allowed
// a session is not the same as being allowed to use the key.
//
// Nothing is exposed until Keyring is handed to Install, which is how package
// auth stays inert until it is configured.
//
// There is deliberately no wish.Option wrapper. This package is imported by
// the browser client, and wish pulls in bubbletea, which has no js/wasm build;
// a dependency that only exists to be called from wssh.NewServer is not worth
// that.
package agentkey

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"charm.land/log/v2"
	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Agent is the interface served to sessions. It is re-exported so callers can
// type a field without importing x/crypto/ssh for one interface.
type Agent = agent.Agent

// SSHAuthSockKey is the context key under which the per-connection socket path
// is stashed. The shell middleware reads it off the session's
// charm.land/ssh.Context and puts SSH_AUTH_SOCK in the environment it hands to
// the shell, which is how openssh tools in the session find a local agent
// without being told anything.
//
// It is exported so other middleware can read the path without importing an
// internal type. The value is a plain string; the empty string means no agent
// is available on this connection.
const SSHAuthSockKey = "wssh.ssh-auth-sock"

// errFixed is what every mutating operation on the keyring reports. The keys
// are chosen by whoever starts the server, so a session that could add or drop
// one would be widening its own authority.
var errFixed = errors.New("agentkey: the keyring is fixed at startup")

// Keyring returns an Agent that signs with the given signers and does nothing
// else. An empty slice gives a nil Agent and a nil error, so callers can use
// the result unconditionally.
//
// The signers are what the SSH library already hands back when it parses a
// private key file. There is deliberately no reach for the crypto.Signer
// underneath: the agent protocol signs SSH data, and an ssh.Signer does
// precisely that, so digging the inner value out of the library's wrapper
// would buy nothing but a dependency on its private layout.
func Keyring(signers []gossh.Signer) (Agent, error) {
	keys := make([]Key, len(signers))
	for i, s := range signers {
		keys[i] = Key{Signer: s}
	}
	return KeyringWithComments(keys)
}

// Key is one signing key and the label the agent will carry for it.
//
// The comment is the end of the line in `ssh-add -L` and `ssh-add -l`, and
// it is the only place either can say where a key came from. Whoever builds
// the keyring is the only party that knows: it read the key off a disk, or
// off a page, or out of a wallet. So the comment is supplied here rather
// than guessed at later, and an empty one is honest - it means the builder
// did not know, and nothing is invented in its place.
//
// What must not go in it is the algorithm name. `ssh-add -l` already prints
// that in parentheses after the comment, so a comment that repeats it turns
// every line into the same word twice and tells the reader nothing.
type Key struct {
	Signer  gossh.Signer
	Comment string
}

// KeyringWithComments is Keyring with a label per key, for a caller that
// knows where its keys came from.
func KeyringWithComments(keys []Key) (Agent, error) {
	if len(keys) == 0 {
		return nil, nil //nolint:nilnil
	}
	for i, k := range keys {
		if k.Signer == nil {
			return nil, fmt.Errorf("agentkey: signer %d is nil", i)
		}
	}
	return &keyring{keys: slices.Clone(keys)}, nil
}

// keyring is an agent.Agent over a fixed list of keys.
type keyring struct {
	mu   sync.RWMutex
	keys []Key

	// solana, when set, answers the transaction extension. It is nil on a
	// keyring that cannot sign one, which is the ordinary case and not an
	// error: the extension is simply refused.
	solana *SolanaTx
}

func (r *keyring) List() ([]*agent.Key, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([]*agent.Key, 0, len(r.keys))
	for _, k := range r.keys {
		pub := k.Signer.PublicKey()
		keys = append(keys, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.Comment,
		})
	}
	return keys, nil
}

func (r *keyring) Sign(key gossh.PublicKey, data []byte) (*gossh.Signature, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, k := range r.keys {
		if bytes.Equal(k.Signer.PublicKey().Marshal(), key.Marshal()) {
			return k.Signer.Sign(rand.Reader, data)
		}
	}
	return nil, fmt.Errorf("agentkey: no key matches the requested %s key", key.Type())
}

func (r *keyring) Signers() ([]gossh.Signer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	signers := make([]gossh.Signer, 0, len(r.keys))
	for _, k := range r.keys {
		signers = append(signers, k.Signer)
	}
	return signers, nil
}

// Extension answers the extensions this agent knows about and refuses the rest.
//
// Refusing the rest matters as much as answering this one: an agent that
// answered every extension the same way would be indistinguishable from one
// that had no idea what it was being asked, which is exactly the confusion a
// standard tool would land in.
func (r *keyring) Extension(name string, contents []byte) ([]byte, error) {
	if r.solana == nil {
		return nil, agent.ErrExtensionUnsupported
	}

	r.mu.RLock()
	signers := make([]gossh.Signer, 0, len(r.keys))
	for _, k := range r.keys {
		signers = append(signers, k.Signer)
	}
	r.mu.RUnlock()

	// One wallet is one key, so the extension is answered by the only key
	// there is. With several there is nothing to disambiguate with and
	// guessing would be worse than refusing.
	if len(signers) != 1 {
		return nil, errors.New("this agent holds several keys and cannot tell which one to sign with")
	}

	// The signer itself, not just its key: an agent holding a local key signs
	// with it rather than sending the transaction off to a wallet it does not
	// have.
	return r.solana.ExtensionHandler(signers[0])(name, contents)
}

// SignWithFlags is Sign with no flags. The agent protocol's flags carry RSA
// scheme negotiation, which an ed25519 key has no use for; refusing them is
// more honest than ignoring them.
func (r *keyring) SignWithFlags(key gossh.PublicKey, data []byte, flags agent.SignatureFlags) (*gossh.Signature, error) {
	if flags != 0 {
		return nil, fmt.Errorf("this agent does not sign with flags: %d", flags)
	}
	return r.Sign(key, data)
}

var _ agent.ExtendedAgent = (*keyring)(nil)

func (r *keyring) Add(agent.AddedKey) error     { return errFixed }
func (r *keyring) Remove(gossh.PublicKey) error { return errFixed }
func (r *keyring) RemoveAll() error             { return errFixed }
func (r *keyring) Lock([]byte) error            { return errFixed }
func (r *keyring) Unlock([]byte) error          { return errFixed }

// Install registers the agent handlers on the server: the SSH channel, the
// request that asks for it, and a local socket per connection. A nil agent
// leaves the server untouched.
//
// The socket is created eagerly on every connection rather than when the
// channel opens, because the shell may start before any client thinks to ask
// for the channel and SSH_AUTH_SOCK has to be right at exec time. The cost is
// one Unix socket per connection; the benefit is that the variable is never
// set to a path nothing is listening on.
func Install(srv *ssh.Server, ring Agent) {
	if ring == nil {
		return
	}

	if srv.RequestHandlers == nil {
		srv.RequestHandlers = map[string]ssh.RequestHandler{}
	}
	srv.RequestHandlers["auth-agent-req@openssh.com"] =
		func(_ ssh.Context, _ *ssh.Server, _ *gossh.Request) (bool, []byte) { return true, nil }

	if srv.ChannelHandlers == nil {
		srv.ChannelHandlers = map[string]ssh.ChannelHandler{}
	}
	srv.ChannelHandlers["auth-agent@openssh.com"] =
		func(_ *ssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, _ ssh.Context) {
			ch, reqs, err := newChan.Accept()
			if err != nil {
				return
			}
			// In-channel requests (env, shell) are not part of the agent
			// protocol, so they are answered and dropped.
			go drainRequests(reqs)
			go func() {
				defer ch.Close() //nolint:errcheck
				if err := agent.ServeAgent(ring, ch); err != nil && !isExpectedClose(err) {
					log.Debug("agent channel ended", "error", err)
				}
			}()
		}

	// ConnCallback fires once per connection, before auth, which is the only
	// point early enough to have the socket ready when the shell starts.
	prev := srv.ConnCallback
	srv.ConnCallback = func(ctx ssh.Context, c net.Conn) net.Conn {
		if prev != nil {
			if c = prev(ctx, c); c == nil {
				return nil
			}
		}
		path, cleanup, err := listenLocal(ring)
		if err != nil {
			// No socket is not fatal: the SSH channel still serves the agent.
			log.Debug("local agent listener", "error", err)
			return c
		}
		ctx.SetValue(SSHAuthSockKey, path)
		go func() {
			<-ctx.Done()
			cleanup()
		}()
		return c
	}
}

// drainRequests answers the channel-level requests that are not part of the
// agent protocol. ServeAgent owns the message loop and has nowhere to put
// them, and a request left unanswered stalls the client.
func drainRequests(reqs <-chan *gossh.Request) {
	for r := range reqs {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}

// isExpectedClose matches the errors that come up from the agent protocol when
// the SSH channel ends first. A client hanging up is the ordinary end of a
// session, not something to log.
func isExpectedClose(err error) bool {
	if err == nil {
		return true
	}
	switch err.Error() {
	case "EOF", "io: read/write on closed pipe", "use of closed network connection", "channel not open":
		return true
	default:
		return false
	}
}

// listenLocal opens a Unix socket in a fresh tempdir and serves the agent on
// every connection to it. The returned path is what goes into SSH_AUTH_SOCK;
// the returned cleanup closes the listener and removes the directory.
//
// The directory rather than a bare socket path is deliberate: the socket has to
// be unlinked on the way out, and a path you can unlink needs a directory you
// can remove.
func listenLocal(ring Agent) (string, func(), error) {
	dir, err := os.MkdirTemp("", "wssh-agent-")
	if err != nil {
		return "", nil, fmt.Errorf("agent tempdir: %w", err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "agent.sock"))
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

	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
		_ = os.RemoveAll(dir)
	}, nil
}
