package main

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"charm.land/log/v2"
	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth"
	"github.com/btwiuse/wssh/shell"
	"github.com/spf13/cobra"
)

// shutdownTimeout bounds how long live sessions get to finish.
const shutdownTimeout = 30 * time.Second

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
	if opts.Origins == nil {
		// A single comma separated value, which is how it is configured in
		// practice; an unset variable must not become a pattern matching "".
		if raw := os.Getenv("ALLOWED_ORIGINS"); raw != "" {
			opts.Origins = strings.Split(raw, ",")
		}
	}
	if slices.Contains(opts.Origins, AnyOrigin) {
		log.Warn("allowing ANY browser origin: every website the user visits can open a session against this port")
		if !opts.Auth.Enabled() && !opts.UIOnly {
			log.Warn("and there is no authentication, so that session is a shell for whoever asks")
		}
	}

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

		sessions, err = wssh.NewServer(wssh.Options{
			HostKeyPath:        opts.HostKeyPath,
			Middleware:         []wish.Middleware{shell.Middleware()},
			Pty:                true,
			AllowTcpForwarding: opts.AllowTcpForwarding,
			OriginPatterns:     opts.Origins,
			SSHOptions:         authOpts,
		})
		if err != nil {
			return err //nolint:wrapcheck
		}
		if !opts.Auth.Enabled() {
			log.Warn("no authentication configured: every connection that reaches this port gets a shell")
		}
		if opts.AllowTcpForwarding {
			log.Warn("TCP forwarding enabled: clients can relay to any host this server can reach")
		}
		if len(opts.Origins) > 0 && !slices.Contains(opts.Origins, AnyOrigin) {
			// "*" is not a restriction, and saying it was would be the one
			// time this log line really mattered.
			log.Info("restricting origins", "patterns", opts.Origins)
		}
		mux.Handle("/ws", sessions)
	}

	if opts.Assets != nil {
		mux.Handle("/", noCache(http.FileServer(http.FS(opts.Assets))))
	}

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

	// fang already intercepts signals for its own error reporting, so the
	// second listener here only exists to drive shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err //nolint:wrapcheck
		}
	}

	// Stop accepting before draining, so no session starts while we shut down.
	if err := listener.Close(); err != nil {
		log.Debug("could not close listener", "error", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if sessions != nil {
		if err := sessions.Shutdown(shutdownCtx); err != nil {
			return err //nolint:wrapcheck
		}
	}
	return nil
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
