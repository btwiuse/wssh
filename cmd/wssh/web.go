package main

import (
	"time"

	"embed"
	"io/fs"

	"charm.land/log/v2"
	"github.com/spf13/cobra"
)

// The front end is compiled into the binary so that deploying wssh is
// deploying one file. The wasm binary itself is not committed: build it with
// client/build.sh, or let go:generate / make do it.
//
// The embed covers the directory rather than a list of files, so a build made
// before the wasm exists still compiles and still runs; the page loads, and
// then fails in the worker with a 404. Nothing here can turn that into a
// compile error, which is why the warning below exists.
//
//go:generate bash ../../client/build.sh
//go:embed all:static
var embedded embed.FS

// webAssets returns the embedded front end, stripped of the directory so it
// can be mounted at the root.
func webAssets() fs.FS {
	assets, err := fs.Sub(embedded, "static")
	if err != nil {
		// Unreachable: the embed directive above guarantees the directory.
		panic(err)
	}
	return assets
}

// wasmClientMissing reports whether the browser client is absent from the
// embedded assets. The embed succeeds either way, so this is the only place
// the mistake is still visible before someone opens a terminal.
func wasmClientMissing(assets fs.FS) bool {
	_, err := fs.Stat(assets, "ssh.wasm")
	return err != nil
}

func newWebCmd() *cobra.Command {
	var opts serveOptions
	var uiOnly bool

	cmd := &cobra.Command{
		Use:   "web",
		Short: "Serve a browser terminal and SSH sessions",
		Long: `Serve a browser terminal and SSH sessions.

Serves everything ` + "`wssh server`" + ` does, plus a terminal in the browser
on the same port. The browser never speaks SSH: the page loads a Go program
compiled to WebAssembly which runs a real SSH client and dials the same
WebSocket endpoint. The front end is served from memory, so there is nothing
to deploy alongside the binary.

Open the served address, press Connect, and you have a shell.

With --ui-only, only the page is served and no sessions are. That makes it a
browser SSH client for a server somewhere else, which is why the address in
the toolbar is editable.`,
		Example: `  # Serve the browser front end on :8080
  wssh web

  # Serve only the page, and connect to a wssh server elsewhere
  wssh web --ui-only

  # Bind a fixed port
  wssh web --addr :2222

  # Restrict sessions to your own front end
  wssh web --origins https://ssh.example.com`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			opts.UIOnly = uiOnly
			if opts.SessionPath == "" {
				// The page and its assets share this port, so sessions need
				// a path of their own.
				opts.SessionPath = DefaultSessionPath
			}
			opts.Description = "web only"
			if !uiOnly {
				opts.Description = "websocket + web"
			}
			opts.Assets = webAssets()
			if wasmClientMissing(opts.Assets) {
				log.Warn("no ssh.wasm in the front end: the page will load but " +
					"cannot connect. Build it with 'go generate ./...' or 'make'")
			}
			return serve(opts)
		},
	}

	cmd.Flags().BoolVar(&uiOnly, "ui-only", false,
		"serve only the front end: no /ws and no sessions behind this port")
	cmd.Flags().DurationVar(&opts.ShutdownTimeout, "shutdown-timeout", 5*time.Second,
		"how long live sessions get to finish after an interrupt; 0 waits forever")
	cmd.Flags().BoolVar(&opts.OpenBrowser, "open", false,
		"open the served page in the default browser once it is up")
	cmd.Flags().StringVar(&opts.SessionPath, "path", DefaultSessionPath,
		"URL path sessions are served on; the page is told where to find them")
	cmd.Flags().StringVar(&opts.Addr, "addr", "", "address to listen on (default $PORT or :8080)")
	cmd.Flags().StringVar(&opts.HostKeyPath, "hostkey", defaultHostKey(), "path to the ed25519 host key")
	cmd.Flags().BoolVar(&opts.AllowTcpForwarding, "allow-tcp-forwarding", false,
		"allow ssh -L/-D port forwarding (an open proxy unless restricted)")
	cmd.Flags().StringSliceVar(&opts.Origins, "origins", []string{AnyOrigin},
		"browser origins allowed to open a session; '*' allows any, "+
			"$ALLOWED_ORIGINS sets this too")

	cmd.Flags().StringArrayVar(&opts.Relays, "relay", nil,
		"expose this server through a relay, repeatable; a bare :port "+
			"listens locally, anything else dials a remote relay")

	addAuthFlags(cmd, &opts.Auth)

	return cmd
}
