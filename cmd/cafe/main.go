// Command cafe serves RouterCafe: a landing page, an OpenAI-compatible API
// paid for in SOL, and a terminal UI you reach by connecting to the host.
//
// The shape of it is wssh's web subcommand with the shell taken out. Same
// three pieces - an HTTP server, a wish SSH server behind a WebSocket, and the
// same browser front end - and one difference that everything else follows
// from:
//
//	ssh -A router.cafe
//
// opens a full-screen program showing a balance, an API key and a way to
// deposit. It is not a shell, and there is no path by which a connection can
// become one. See package cafe for how that is enforced rather than merely
// intended.
//
// The browser terminal is still here, at /app, with everything it always had.
// It reaches the same sessions, so it shows the same UI - which is the point:
// the thing a person gets is the same whichever way they arrive.
package main

import (
	"context"
	"errors"
	"os"

	"charm.land/fang/v2"
	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"
)

// Set with -ldflags at build time, the same way the other binaries here do, so
// every one of them reports itself the same way.
var (
	version = "dev"
	commit  = ""
)

// debug is set once by the root command's persistent --verbose flag and read by
// whichever subcommand is running.
var debug = new(bool)

func main() {
	options := []fang.Option{
		fang.WithVersion(version),
	}
	if commit != "" {
		options = append(options, fang.WithCommit(commit))
	}

	// fang reports the error itself, in its own styled form, so all that is
	// left here is the exit status.
	if err := fang.Execute(context.Background(), newCafeCmd(), options...); err != nil {
		var exitErr *gossh.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitStatus())
		}
		os.Exit(1)
	}
}

func newCafeCmd() *cobra.Command {
	opts := &serveOptions{}

	cmd := &cobra.Command{
		Use:   "cafe",
		Short: "Serve RouterCafe",
		Long: `Serve RouterCafe: an OpenAI-compatible API, paid for in SOL, reached over SSH.

Three things on one port:

  /        this product's landing page
  /app     a terminal in the browser, running the Go/WASM SSH client
  /ws      SSH over a WebSocket, and the session UI

    ssh -A router.cafe

opens a full-screen program: your balance, your API key, and a way to deposit
SOL. The key it mints works with any OpenAI client:

    export OPENAI_BASE_URL=https://router.cafe/v1
    export OPENAI_API_KEY=rc_abcd...wxyz

**There is no shell here.** A session is a program, not a command line, and
nothing typed at one is ever run: a command sent instead of a shell is refused
by name, subsystems are refused, and ` + "`ssh -L`" + ` and ` + "`ssh -D`" + ` have no channel to
open through. The only thing a connection can cause is a UI, the ledger, and a
signature request to the agent you forwarded with ` + "`ssh -A`" + ` - whose
transaction is checked before it goes anywhere.

Agent forwarding is on by default because it is how a deposit is signed: the
private key stays on your machine and this server asks your agent to sign.`,
		Example: `  # Serve RouterCafe on :8080, depositing into a treasury address
  cafe --treasury 5cyy...qqq --sol-price 180

  # A fixed port, a host key on persistent storage, and a plain SSH port too
  cafe --addr :443 --tcp-addr :22 --hostkey /data/host_ed25519 \
       --treasury 5cyy...qqq

  # Route to a real provider
  cafe --treasury 5cyy...qqq --upstream https://api.openai.com/v1 \
       --upstream-key sk-...

  # Look at it without spending anything: no deposits taken
  cafe --treasury 5cyy...qqq --dry-run-deposits`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
		RunE: func(_ *cobra.Command, _ []string) error {
			if opts.RequireKey {
				opts.AllowAnonymous = false
			}
			return serve(opts)
		},
	}

	addServeFlags(cmd, opts)
	cmd.AddCommand(newUpgradeCmd())
	cmd.AddCommand(newTUICmd())
	return cmd
}
