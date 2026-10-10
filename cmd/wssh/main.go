// Command wssh reaches an SSH server over a WebSocket.
//
// SSH is a self-contained protocol on a byte stream: key exchange,
// authentication and terminal resizes all travel in-band. So a WebSocket only
// has to be a reliable bidirectional pipe, and neither side has to understand
// the other. That is what lets a stock ssh client work with no extra software
// beyond a WebSocket proxy:
//
//	wssh server
//	ssh -o 'ProxyCommand=websocat -b wss://host:port' user@host
//
// and, in a browser, with nothing installed at all:
//
//	wssh web
package main

import (
	"context"
	"errors"
	"os"

	"charm.land/fang/v2"
	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"
)

// Set with -ldflags at build time.
var (
	version = "dev"
	commit  = ""
)

// debug is set once by the root command's persistent --verbose flag and read
// by whichever subcommand is running.
var debug = new(bool)

func main() {
	root := &cobra.Command{
		Use:   "wssh",
		Short: "SSH over WebSocket",
		Long: `SSH over WebSocket.

Run an SSH server that clients reach through a WebSocket tunnel, and
optionally a browser front end for it.

Because SSH is a byte-stream protocol, a WebSocket is enough to carry a
whole session. That is why a stock ssh client works with no extra software
beyond a WebSocket proxy:

    ssh -o 'ProxyCommand=websocat -b wss://host:port' user@host`,
		Example: `  # Serve SSH over a WebSocket on :8080
  wssh server

  # Serve the same, plus a terminal in the browser
  wssh web

  # Bind a specific port and keep the host key somewhere stable
  wssh server --addr :2222 --hostkey /data/host_ed25519

  # Reach a served instance from this machine
  ssh -o 'ProxyCommand=websocat -b ws://127.0.0.1:8080/ws' user@localhost`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}

	root.PersistentFlags().BoolVar(debug, "verbose", false, "log session-level detail")

	root.AddCommand(newServerCmd(), newWebCmd(), newClientCmd(), newKeygenCmd())

	options := []fang.Option{
		fang.WithVersion(version),
	}
	if commit != "" {
		options = append(options, fang.WithCommit(commit))
	}

	// fang reports the error itself, in its own styled form, so all that is
	// left here is the exit status. A remote command's own status is passed
	// through: reporting "exited 7" and then exiting 1 would make every
	// failure indistinguishable to whatever is calling us.
	if err := fang.Execute(context.Background(), root, options...); err != nil {
		var exitErr *gossh.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitStatus())
		}
		os.Exit(1)
	}
}
