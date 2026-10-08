package main

import (
	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	var opts serveOptions

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Serve SSH over a WebSocket",
		Long: `Serve SSH over a WebSocket.

Listens for WebSocket upgrades and serves each one as an SSH session, with
a login shell behind it. No HTTP assets are served; this is the bare
transport, for clients that bring their own terminal.

A stock ssh client reaches it through any WebSocket proxy:

    ssh -o 'ProxyCommand=websocat -b wss://host:port/ws' user@host`,
		Example: `  # Serve on :8080
  wssh server

  # Serve on a fixed port
  wssh server --addr :2222

  # Also allow ssh -L and -D
  wssh server --allow-tcp-forwarding

  # Let only your own front end open sessions
  wssh server --origins https://ssh.example.com`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			opts.Description = "websocket"
			return serve(opts)
		},
	}

	cmd.Flags().StringVar(&opts.Addr, "addr", "", "address to listen on (default $PORT or :8080)")
	cmd.Flags().StringVar(&opts.HostKeyPath, "hostkey", defaultHostKey(), "path to the ed25519 host key")
	cmd.Flags().BoolVar(&opts.AllowTcpForwarding, "allow-tcp-forwarding", false,
		"allow ssh -L/-D port forwarding (an open proxy unless restricted)")
	cmd.Flags().StringSliceVar(&opts.Origins, "origins", nil,
		"browser origins allowed to open a session (default any, or $ALLOWED_ORIGINS)")

	return cmd
}
