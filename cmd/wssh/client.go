package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"

	"github.com/btwiuse/wssh/client"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newClientCmd() *cobra.Command {
	var (
		addr       string
		username   string
		cols, rows int
	)

	cmd := &cobra.Command{
		Use:   "client [url] [command...]",
		Short: "Connect to a WebSocket SSH server",
		Long: `Connect to a WebSocket SSH server, the same way ` + "`ssh -o ProxyCommand=...`" + ` does,
without needing a WebSocket proxy on the client side.

Given only a URL, it opens an interactive shell over the tunnel. Given a
command as well, it runs that and exits, exactly as ssh would.

The local terminal is put into raw mode so that programs drawn on the far
side -- vim, htop, less -- get keystrokes one at a time and arrow keys as
keys rather than escape sequences. Resizing the window is forwarded as an
SSH window-change request.`,
		Example: `  # Interactive shell
  wssh client wss://ssh.example.com/ws

  # As a particular user
  wssh client --user deploy wss://ssh.example.com/ws

  # Run one command and exit
  wssh client wss://ssh.example.com/ws -- uptime

  # Take the credentials from environment, like ssh does
  WS_USER=deploy WS_ADDR=wss://ssh.example.com/ws wssh client`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			url := addr
			if url == "" {
				url = args[0]
				args = args[1:]
			}
			if err := runClient(cmd.Context(), url, username, strings.Join(args, " "), cols, rows); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "", "WebSocket address to dial (or pass it as the first argument)")
	cmd.Flags().StringVar(&username, "user", "", "user to authenticate as (default $WS_USER or the current user)")
	cmd.Flags().IntVar(&cols, "cols", 0, "terminal columns to start with (default: detect)")
	cmd.Flags().IntVar(&rows, "rows", 0, "terminal rows to start with (default: detect)")

	return cmd
}

func runClient(ctx context.Context, url, username, command string, cols, rows int) error {
	if !strings.HasPrefix(url, "ws://") && !strings.HasPrefix(url, "wss://") {
		return fmt.Errorf("%q is not a WebSocket address; it should start with ws:// or wss://", url)
	}
	if username == "" {
		username = os.Getenv("WS_USER")
	}
	if username == "" {
		if u, err := user.Current(); err == nil {
			username = u.Username
		}
	}
	if username == "" {
		return errors.New("no user given: pass --user or set WS_USER")
	}

	// Raw mode is what makes the remote side behave like a terminal. It is
	// only meaningful when stdin is one.
	fd := int(os.Stdin.Fd())
	isTTY := term.IsTerminal(fd)
	if isTTY {
		if cols == 0 || rows == 0 {
			w, h, err := term.GetSize(fd)
			if err == nil {
				cols, rows = w, h
			}
		}
		state, err := term.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("put terminal in raw mode: %w", err)
		}
		// The terminal has to be handed back even if the session dies badly,
		// or the user is left with an unusable shell.
		defer func() { _ = term.Restore(fd, state) }()
	}
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	// closed carries the session's own ending, which is what decides when we
	// are done.
	closed := make(chan error, 1)
	session, err := client.Dial(ctx, client.Options{
		URL:     url,
		User:    username,
		Cols:    cols,
		Rows:    rows,
		Command: command,
		OnData: func(p []byte) {
			_, _ = os.Stdout.Write(p)
		},
		OnClose: func(err error) { closed <- err },
	})
	if err != nil {
		return err //nolint:wrapcheck
	}
	defer session.Close() //nolint:errcheck

	// Forward terminal resizes. Without this a resized window leaves
	// full-screen programs drawing to the geometry they started with.
	if isTTY {
		resize := make(chan os.Signal, 1)
		signal.Notify(resize, syscall.SIGWINCH)
		defer signal.Stop(resize)
		go func() {
			for range resize {
				w, h, err := term.GetSize(fd)
				if err != nil {
					continue
				}
				_ = session.Resize(w, h)
			}
		}()
	}

	// Type in until stdin ends. Whether that should also end the session
	// depends on what we are running: a one-shot command has to be left to
	// finish and report its output even though stdin is already at EOF,
	// whereas an interactive shell should exit when its input does.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if werr := session.WriteContext(ctx, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				break
			}
		}
		// End of input is not end of session: send EOF and let the remote
		// side finish and report. Killing the connection here loses whatever
		// it still had buffered to say.
		session.CloseStdin()
	}()

	select {
	case err := <-closed:
		return err
	case <-ctx.Done():
		return nil
	}
}
