package main

import (
	"time"

	"embed"
	"io/fs"

	"github.com/spf13/cobra"
)

// The front end is compiled into the binary so that deploying wssh is
// deploying one file. The wasm binary itself is not committed; build it with
// client/build.sh.
//
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
			opts.Description = "web only"
			if !uiOnly {
				opts.Description = "websocket + web"
			}
			opts.Assets = webAssets()
			return serve(opts)
		},
	}

	cmd.Flags().BoolVar(&uiOnly, "ui-only", false,
		"serve only the front end: no /ws and no sessions behind this port")
	cmd.Flags().DurationVar(&opts.ShutdownTimeout, "shutdown-timeout", 5*time.Second,
		"how long live sessions get to finish after an interrupt; 0 waits forever")
	cmd.Flags().StringVar(&opts.Addr, "addr", "", "address to listen on (default $PORT or :8080)")
	cmd.Flags().StringVar(&opts.HostKeyPath, "hostkey", defaultHostKey(), "path to the ed25519 host key")
	cmd.Flags().BoolVar(&opts.AllowTcpForwarding, "allow-tcp-forwarding", false,
		"allow ssh -L/-D port forwarding (an open proxy unless restricted)")
	cmd.Flags().StringSliceVar(&opts.Origins, "origins", nil,
		"browser origins allowed to open a session; same origin always works, "+
			"$ALLOWED_ORIGINS sets this too, and '*' allows any origin")

	cmd.Flags().StringArrayVar(&opts.Relays, "relay", nil,
		"expose this server through a relay, repeatable; a bare :port "+
			"listens locally, anything else dials a remote relay")

	addAuthFlags(cmd, &opts.Auth)

	return cmd
}
