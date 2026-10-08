package main

import (
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

	cmd := &cobra.Command{
		Use:   "web",
		Short: "Serve a browser terminal and SSH sessions",
		Long: `Serve a browser terminal and SSH sessions.

Serves everything ` + "`wssh server`" + ` does, plus a terminal in the browser
on the same port. The browser never speaks SSH: the page loads a Go program
compiled to WebAssembly which runs a real SSH client and dials the same
WebSocket endpoint. The front end is served from memory, so there is nothing
to deploy alongside the binary.

Open the served address, press Connect, and you have a shell.`,
		Example: `  # Serve the browser front end on :8080
  wssh web

  # Bind a fixed port
  wssh web --addr :2222

  # Restrict sessions to your own front end
  wssh web --origins https://ssh.example.com`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			opts.Description = "websocket + web"
			opts.Assets = webAssets()
			return serve(opts)
		},
	}

	cmd.Flags().StringVar(&opts.Addr, "addr", "", "address to listen on (default $PORT or :8080)")
	cmd.Flags().StringVar(&opts.HostKeyPath, "hostkey", defaultHostKey(), "path to the ed25519 host key")
	cmd.Flags().BoolVar(&opts.AllowTcpForwarding, "allow-tcp-forwarding", false,
		"allow ssh -L/-D port forwarding (an open proxy unless restricted)")
	cmd.Flags().StringSliceVar(&opts.Origins, "origins", nil,
		"browser origins allowed to open a session (default any, or $ALLOWED_ORIGINS)")

	addAuthFlags(cmd, &opts.Auth)

	return cmd
}
