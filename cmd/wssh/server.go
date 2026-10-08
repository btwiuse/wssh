package main

import (
	"time"

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

    ssh -o 'ProxyCommand=websocat -b wss://host:port/ws' user@host

With --relay the same server is also published through a relay, so it stays
reachable from networks it cannot be listened on from directly. The relay
prints a public address; append /ws to reach sessions, exactly as you would
for a directly reachable server.`,
		Example: `  # Serve on :8080
  wssh server

  # Serve on a fixed port
  wssh server --addr :2222

  # Also allow ssh -L and -D
  wssh server --allow-tcp-forwarding

  # Publish through a relay as well as listening locally
  wssh server --relay https://pub.webtransport.fun

  # Let only your own front end open sessions
  wssh server --origins https://ssh.example.com`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			opts.Description = "websocket"
			return serve(opts)
		},
	}

	cmd.Flags().StringVar(&opts.SessionPath, "path", "",
		"URL path sessions are served on; empty means any path works")
	cmd.Flags().DurationVar(&opts.ShutdownTimeout, "shutdown-timeout", 5*time.Second,
		"how long live sessions get to finish after an interrupt; 0 waits forever")
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
