package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"charm.land/log/v2"
	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth"
	"github.com/btwiuse/wssh/auth/authfwd"
	"github.com/btwiuse/wssh/shell"
	"github.com/spf13/cobra"
	"github.com/webteleport/wtf"
)

// DefaultSessionPath is where the browser front end keeps its session
// endpoint. It is a convention rather than a requirement: the page resolves it
// relative to wherever it was loaded from.
const DefaultSessionPath = "/ws"

// sessionPathPlaceholder is replaced in index.html with the configured path.
const sessionPathPlaceholder = "__WSSH_SESSION_PATH__"

// AnyOrigin is the --origins value that turns the browser origin check off.
//
// It exists because "let any page connect" is a real need -- a front end
// served from somewhere else, or a dev machine whose hostname keeps changing
// -- but it should never be reached for by accident. A browser always sends an
// Origin and ssh never does, so this is exactly the switch that lets any page
// a user visits open a session here. Pair it with authentication.
const AnyOrigin = "*"

// serveOptions is everything the server and web subcommands have in common.
// They differ only in whether they also hand out a front end.
type serveOptions struct {
	// Addr is the address to listen on. Empty means take it from $PORT, and
	// failing that :8080.
	Addr string

	// HostKeyPath is the ed25519 host key, generated on first use.
	HostKeyPath string

	// AllowTcpForwarding enables the direct-tcpip channel behind ssh -L/-D.
	AllowTcpForwarding bool

	// Origins restricts which browser origins may open a session. Empty
	// allows any origin that reaches the host, which is fine for ssh(1) and
	// websocat but not a decision for a public deployment.
	Origins []string

	// Assets, when set, is served at / alongside the sessions at /ws.
	Assets fs.FS

	// Auth decides who may connect. The zero value authenticates nobody,
	// which means it accepts everybody, so the startup log says so loudly.
	Auth auth.Config

	// AgentKeys are paths to private keys loaded into the in-memory
	// ssh-agent served over the "auth-agent@openssh.com" channel. Each
	// path is a PEM-encoded private key (encrypted keys are not
	// supported). The same keys are not used for authentication here;
	// they are exposed to clients so they can sign with them.
	AgentKeys []string

	// OpenBrowser points the user's browser at the front end once it is up.
	// Only meaningful for the web command, which is the one with a page.
	OpenBrowser bool

	// SessionPath is the URL path the session endpoint lives on. Empty, the
	// default, serves sessions on any path, which suits a server that has
	// nothing else on it. The browser front end needs it because it also
	// serves static files, and those need the paths left to themselves.
	SessionPath string

	// ShutdownTimeout is how long live sessions get to finish after an
	// interrupt. Zero waits as long as it takes. A shell waits for input, so
	// an interactive session will never end by itself: without a bound, every
	// ^C would sit here until the deadline. A second interrupt gives up.
	ShutdownTimeout time.Duration

	// Relays expose the same handler through remote relays, for reaching a
	// server from a network it cannot be listened on from directly. A relay
	// given as ":8080" is a local listener instead, which is handy for
	// testing and for chaining.
	Relays []string

	// UIOnly serves the front end alone: no /ws and no session server, so the
	// page is a client for a server elsewhere. Authentication, host key and
	// forwarding settings are then meaningless and are ignored.
	UIOnly bool

	// Description labels the listener in the log line.
	Description string
}

// serve runs until interrupted. It owns the socket and the session lifecycle,
// so both subcommands get identical shutdown behaviour for free.
func serve(opts serveOptions) error {
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	if opts.Description == "" {
		opts.Description = "websocket"
	}
	// The flag defaults to any origin, but a container is far more likely to
	// set this through the environment than through a command line, so an
	// explicit ALLOWED_ORIGINS still wins over that default.
	if len(opts.Origins) == 1 && opts.Origins[0] == AnyOrigin {
		if raw := os.Getenv("ALLOWED_ORIGINS"); raw != "" {
			opts.Origins = strings.Split(raw, ",")
		}
	}
	anyOrigin := slices.Contains(opts.Origins, AnyOrigin)

	mux := http.NewServeMux()

	// UIOnly serves the front end and nothing else: no session server, so no
	// /ws, no host key and no shell listening behind this port. The page
	// becomes a client for a wssh server somewhere else, which is what makes
	// the endpoint editable in the first place.
	var sessions *wssh.Server
	if !opts.UIOnly {
		authOpts, err := opts.Auth.Options()
		if err != nil {
			return err //nolint:wrapcheck
		}

		agentRing, err := buildAgent(opts.AgentKeys)
		if err != nil {
			return err
		}

		sessions, err = wssh.NewServer(wssh.Options{
			HostKeyPath:        opts.HostKeyPath,
			Middleware:         []wish.Middleware{shell.Middleware()},
			Pty:                true,
			Path:               opts.SessionPath,
			AllowTcpForwarding: opts.AllowTcpForwarding,
			OriginPatterns:     opts.Origins,
			Agent:              agentRing,
			SSHOptions:         authOpts,
		})
		if err != nil {
			return err //nolint:wrapcheck
		}
		switch {
		case !opts.Auth.Enabled() && anyOrigin:
			// Worth saying out loud, and this is the default configuration:
			// a page the user visits can open a session here, and there is
			// nothing to authenticate it.
			log.Warn("any origin allowed and no authentication: any website the user visits can open a shell on this port")
		case !opts.Auth.Enabled():
			log.Warn("no authentication configured: every connection that reaches this port gets a shell")
		}
		if opts.AllowTcpForwarding {
			log.Warn("TCP forwarding enabled: clients can relay to any host this server can reach")
		}
		if len(opts.Origins) > 0 && !anyOrigin {
			log.Info("restricting origins", "patterns", opts.Origins)
		}
		if len(opts.AgentKeys) > 0 {
			log.Warn("agent forwarding enabled with keys: any client can sign with the loaded keys")
		}
		// An empty path mounts on "/", which in Go's mux is the catch-all:
		// any path opens a session, exactly as a client dialling a bare
		// host and port would expect.
		pattern := opts.SessionPath
		if pattern == "" {
			pattern = "/"
		}
		mux.Handle(pattern, sessions)
	}

	if opts.Assets != nil {
		mux.Handle("/", noCache(frontEnd(opts.Assets, opts.SessionPath)))
	}

	startRelays(opts.Relays, mux)

	addr := opts.Addr
	if addr == "" {
		addr = defaultAddr()
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err //nolint:wrapcheck
	}

	// http.Serve runs on our listener: there is no http.Server value holding
	// configuration or lifecycle state, so closing the listener is what stops
	// the server.
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: an SSH session is a long-lived stream and any
		// write deadline would sever an idle-but-open shell.
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "address", listener.Addr().String(), "scheme", opts.Description)
		serveErr <- server.Serve(listener)
	}()

	if opts.OpenBrowser {
		// The listener is already bound, so connections queue in the backlog
		// until Serve picks them up; the browser will not arrive first.
		openBrowser(browserURL(listener.Addr()))
	}

	// Buffered so a second interrupt is not lost while the first is being
	// handled: it is what lets someone abandon a session that will not end.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case sig := <-signals:
		log.Info("shutting down", "signal", sig.String(), "grace", opts.ShutdownTimeout)
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err //nolint:wrapcheck
		}
	}

	// Stop accepting before draining, so no session starts while we shut down.
	if err := listener.Close(); err != nil {
		log.Debug("could not close listener", "error", err)
	}

	if sessions == nil {
		return nil
	}
	return drain(sessions, signals, opts.ShutdownTimeout)
}

// drain waits for live sessions to finish, but not indefinitely.
//
// This is why there has to be a bound: a shell waits for input, so an
// interactive session never ends by itself, and a drain with no deadline would
// make every interrupt look like a hang. A second signal abandons the rest.
func drain(sessions *wssh.Server, signals <-chan os.Signal, grace time.Duration) error {
	done := make(chan error, 1)
	go func() {
		if grace <= 0 {
			// Zero means "wait as long as it takes", for anyone running this
			// as a service rather than as a tool.
			done <- sessions.Shutdown(context.Background())
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		done <- sessions.Shutdown(ctx)
	}()

	select {
	case err := <-done:
		return err //nolint:wrapcheck
	case sig := <-signals:
		log.Warn("second signal, dropping live sessions", "signal", sig.String())
		return nil
	}
}

// addAuthFlags registers the authentication flags shared by the subcommands.
//
// Authentication is off until one of these is used. That is the right default
// for trying wssh out on a laptop and the wrong one for anything else, so
// serve() logs a warning when it finds nothing configured.
func addAuthFlags(cmd *cobra.Command, cfg *auth.Config) {
	cmd.Flags().StringSliceVar(&cfg.KeyFiles, "authorized-keys", nil,
		`authorized_keys files to accept; "system" means /etc/ssh/authorized_keys and ~/.ssh/authorized_keys`)
	cmd.Flags().StringSliceVar(&cfg.Keys, "authorized-key", nil,
		"an authorized_keys entry given inline, repeatable")
	cmd.Flags().StringVar(&cfg.PasswordFile, "password-file", "",
		"file of accepted passwords, one per line, plaintext or bcrypt")
	cmd.Flags().StringSliceVar(&cfg.Passwords, "password", nil,
		"an accepted password given inline (visible in ps; prefer --password-file)")
}

// addAgentFlags registers the --agent-keys flag shared by the subcommands.
func addAgentFlags(cmd *cobra.Command, paths *[]string) {
	cmd.Flags().StringSliceVar(paths, "agent-keys", nil,
		"private key files to load into the in-memory ssh-agent served over "+
			"the auth-agent channel; repeatable, unencrypted PEM only")
}

// buildAgent loads the given key files into an in-memory ssh-agent. It is
// called with whatever the user passed via --agent-keys; an empty list
// returns a nil agent and no error, so callers can use the result
// unconditionally.
//
// Each file is an unencrypted PEM block. We parse it ourselves rather
// than going through gossh.ParsePrivateKey, because the SSH package
// returns a value whose underlying crypto.Signer is hidden behind a
// private struct field; the agent package needs that crypto.Signer to
// hand the raw key to the agent protocol.
func buildAgent(paths []string) (authfwd.Agent, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	keys := make([]crypto.Signer, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		signer, err := parseUnencryptedKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		keys = append(keys, signer)
	}
	return authfwd.Keyring(keys)
}

// parseUnencryptedKey decodes a PEM block and returns the underlying
// crypto.Signer. Encrypted keys are rejected with an error so a typo
// does not silently load nothing.
func parseUnencryptedKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") || x509.IsEncryptedPEMBlock(block) {
		return nil, errors.New("encrypted keys are not supported by --agent-keys")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not a crypto.Signer: %T", k)
		}
		return s, nil
	case "OPENSSH PRIVATE KEY":
		// openssh-key-v1 -- newer format, what ssh-keygen produces by
		// default. The format is well-specified; we parse it here so we
		// can hand the raw key back to the agent without going through
		// gossh, which wraps the inner crypto.Signer in an unexported
		// field that we cannot extract with reflect (Go refuses to
		// call Interface() on unexported fields).
		return parseOpenSSHKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// parseOpenSSHKey decodes an "openssh-key-v1" payload and returns the
// underlying crypto.Signer. Format reference:
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
//
// Layout:
//
//	"openssh-key-v1\0"
//	ciphername string (ssh-string)
//	kdfname    string (ssh-string)
//	kdfoptions string (ssh-string)
//	number of keys, uint32
//	public key blob (ssh-string)
//	private key blob (ssh-string)
//
// For unencrypted keys ciphername and kdfname are "none" and kdfoptions is
// empty. The private blob is itself a sub-format:
//
//	checkint  uint32
//	(for each key) public part | private part
//
// We support a single key, which is what ssh-keygen produces.
func parseOpenSSHKey(data []byte) (crypto.Signer, error) {
	r := bytes.NewReader(data)
	magic, err := readCString(r)
	if err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if !bytes.Equal(magic, []byte("openssh-key-v1")) {
		return nil, fmt.Errorf("not an openssh-key-v1 blob (got %q)", string(magic))
	}
	cipher, err := readString(r)
	if err != nil {
		return nil, err
	}
	kdf, err := readString(r)
	if err != nil {
		return nil, err
	}
	if _, err := readString(r); err != nil { // kdf options, ignored
		return nil, err
	}
	if string(cipher) != "none" || string(kdf) != "none" {
		return nil, errors.New("encrypted OPENSSH PRIVATE KEY: not supported by --agent-keys")
	}
	var nKeys uint32
	if err := binary.Read(r, binary.BigEndian, &nKeys); err != nil {
		return nil, err
	}
	if nKeys != 1 {
		return nil, fmt.Errorf("expected 1 key, got %d", nKeys)
	}
	pubBlob, err := readString(r)
	if err != nil {
		return nil, err
	}
	privBlob, err := readString(r)
	if err != nil {
		return nil, err
	}
	_ = pubBlob

	// Private blob layout: checkint (uint32), then per-key: type, public,
	// private, comment. The per-key strings are length-prefixed without a
	// trailing NUL (the NUL terminators are only at the top level).
	pr := bytes.NewReader(privBlob)
	// The spec says: uint32 checkint || uint32 checkint. The second copy
	// is a sanity check for decryption: the two values must match. For
	// unencrypted keys both are the same random 32-bit number.
	var checkintA, checkintB uint32
	if err := binary.Read(pr, binary.BigEndian, &checkintA); err != nil {
		return nil, err
	}
	if err := binary.Read(pr, binary.BigEndian, &checkintB); err != nil {
		return nil, err
	}
	if checkintA != checkintB {
		return nil, fmt.Errorf("openssh key: checkints do not match (corrupt or encrypted)")
	}
	keyType, err := readString(pr)
	if err != nil {
		return nil, err
	}
	// The per-key section is: type, public, private, comment. We have
	// the type, and we do not need the public (we already have it as
	// pubBlob above), so skip it.
	if _, err := readString(pr); err != nil {
		return nil, err
	}
	// Private data is the rest of the blob up to the comment.
	switch string(keyType) {
	case "ssh-ed25519":
		privBytes, err := readString(pr)
		if err != nil {
			return nil, err
		}
		if len(privBytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("ed25519 private key: got %d bytes, want %d", len(privBytes), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(privBytes), nil
	case "ssh-rsa":
		// n, e, d, iqmp, p, q, comment -- eight MPINTs followed by a string.
		// Pull each one through crypto/rsa.
		n, err := readString(pr)
		if err != nil {
			return nil, err
		}
		e, err := readString(pr)
		if err != nil {
			return nil, err
		}
		d, err := readString(pr)
		if err != nil {
			return nil, err
		}
		iqmp, err := readString(pr)
		if err != nil {
			return nil, err
		}
		p, err := readString(pr)
		if err != nil {
			return nil, err
		}
		q, err := readString(pr)
		if err != nil {
			return nil, err
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: new(big.Int).SetBytes(n),
				E: int(new(big.Int).SetBytes(e).Int64()),
			},
			D: new(big.Int).SetBytes(d),
		}
		key.Primes = []*big.Int{
			new(big.Int).SetBytes(p),
			new(big.Int).SetBytes(q),
		}
		// d mod (p-1) etc. are recomputed by Validate.
		if err := key.Validate(); err != nil {
			// Try once with explicit CRT values if Validate fails.
			dI := new(big.Int).SetBytes(d)
			pI := new(big.Int).SetBytes(p)
			qI := new(big.Int).SetBytes(q)
			iqmpI := new(big.Int).SetBytes(iqmp)
			key.Precomputed = rsa.PrecomputedValues{
				Dp:   new(big.Int).Mod(dI, new(big.Int).Sub(pI, big.NewInt(1))),
				Dq:   new(big.Int).Mod(dI, new(big.Int).Sub(qI, big.NewInt(1))),
				Qinv: iqmpI,
			}
			if err := key.Validate(); err != nil {
				return nil, fmt.Errorf("rsa key invalid: %w", err)
			}
		}
		return key, nil
	default:
		return nil, fmt.Errorf("openssh key type %q not supported by --agent-keys", keyType)
	}
}

// readCString reads a NUL-terminated string from r.
func readCString(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, one); err != nil {
			return nil, err
		}
		if one[0] == 0 {
			return buf.Bytes(), nil
		}
		buf.WriteByte(one[0])
	}
}

// readString reads a length-prefixed byte string: a uint32 length followed
// by that many bytes. Used inside per-key sections, where there is no
// trailing NUL.
func readString(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > 1<<20 {
		return nil, fmt.Errorf("string length %d looks too large", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// readString reads a length-prefixed byte string: a uint32 length followed
// by that many bytes. Used inside per-key sections, where there is no
// trailing NUL.

// browserURL turns a listen address into something worth pasting into a bar.
// A wildcard bind has no host to show, so localhost stands in for it.
func browserURL(addr net.Addr) string {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "http://" + addr.String() + "/"
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}

// openBrowser opens a URL in the user's default browser. Not being able to is
// not a reason to take the server down, so failures are only logged.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Debug("could not open a browser", "error", err, "url", url)
		return
	}
	go func() { _ = cmd.Wait() }()
}

// frontEnd serves the embedded assets, telling the page where its session
// endpoint is.
//
// The page resolves that relative to wherever it was loaded from rather than
// being handed an absolute address, so the same build is correct on
// localhost, behind a relay, or on a domain, with nothing reconfigured.
func frontEnd(assets fs.FS, sessionPath string) http.Handler {
	files := http.FileServer(http.FS(assets))
	if sessionPath == "" {
		sessionPath = DefaultSessionPath
	}
	page, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		log.Debug("could not read index.html to template it", "error", err)
		return files
	}
	templated := strings.ReplaceAll(string(page), sessionPathPlaceholder, sessionPath)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			files.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, templated)
	})
}

// startRelays exposes the handler through remote relays, which is how a
// server stays reachable from a network it cannot be listened on from
// directly. It is additive: the local listener is unaffected, so the same
// server answers on both.
//
// A relay that fails is logged rather than fatal. A relay going away should
// not take the server with it.
func startRelays(relays []string, handler http.Handler) {
	for _, relay := range relays {
		go func() {
			log.Info("relaying", "relay", relay)
			if err := wtf.Serve(relay, handler); err != nil {
				log.Error("relay stopped", "relay", relay, "error", err)
			}
		}()
	}
}

// noCache keeps the browser from holding on to a stale wasm binary after a
// rebuild, which otherwise shows up as a baffling version mismatch.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// defaultAddr is the listen address when none is given.
//
// Hosted platforms inject the port to bind through the PORT environment
// variable (Railway, Heroku and friends all do this), and a hardcoded port
// would just fail to bind behind their router.
func defaultAddr() string {
	port := os.Getenv("PORT")
	if port == "" {
		return ":8080"
	}
	if strings.HasPrefix(port, ":") {
		return port
	}
	return ":" + port
}

// defaultHostKey is where the server's ed25519 host key lives.
//
// The key is generated on first run and must stay stable: change it and every
// client reports a host key mismatch. On a platform with an ephemeral
// filesystem, point HOST_KEY at a mounted volume.
func defaultHostKey() string {
	if path := os.Getenv("HOST_KEY"); path != "" {
		return path
	}
	return "host_ed25519"
}
