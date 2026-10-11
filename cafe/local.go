package cafe

import (
	"context"
	"errors"
	"os"

	tea "charm.land/bubbletea/v2"
)

// The same program, on the terminal it was started from, with no SSH in
// between.
//
// This is not a second implementation: it builds the identical model through
// the identical constructor that an ssh connection goes through, with an empty
// identity. That is the whole design. A local run has proved nothing, exactly
// as a connection that arrived without a key has proved nothing, so both get
// the same first screen and the same rules about what may be done with what.
//
// The difference is entirely in where the agent comes from. Over SSH the
// client forwards one and the server dials it back over a channel; here there
// is no client to forward anything, so it is the agent already running on this
// machine, and nothing has to be set up at all.

// LocalOptions is what a local run is made of.
type LocalOptions struct {
	// Ledger holds the accounts. Required.
	Ledger *Ledger

	// Treasury is where deposits go. Required, for the same reason it is on a
	// server: an account with nowhere to send money cannot be funded.
	Treasury Treasury

	// Catalogue is the routing table. Nil means DefaultCatalogue.
	Catalogue *Catalogue

	// SockPath is the agent to ask for signatures, normally $SSH_AUTH_SOCK.
	// Empty means there is none, and the session can look but not sign.
	SockPath string

	// Version is what the help screen says this is.
	Version string
}

// RunLocal runs the RouterCafe program on the terminal it was called from and
// returns when the session ends.
//
// It does not print anything first. The program is full-screen and owns the
// terminal from the first frame, so a line of banner above it would either be
// scrolled away or would have to be cleared, and the bar at the top already
// says what this is.
func RunLocal(opts LocalOptions) error {
	if opts.Ledger == nil {
		return errors.New("a local run needs a ledger to read accounts from")
	}
	srv, err := New(Options{
		Ledger:         opts.Ledger,
		Treasury:       opts.Treasury,
		Catalogue:      opts.Catalogue,
		AllowAnonymous: true,
		Version:        opts.Version,
	})
	if err != nil {
		return err
	}

	m := srv.modelFor(who{
		sock:  opts.SockPath,
		ctx:   context.Background(),
		local: true,
	})
	// No program options, and that is the point: every screen of this program
	// asks for the alternate screen buffer in its own View, so the terminal is
	// owned from the first frame whichever screen that is, and the shell that
	// launched this is still there afterwards.
	if _, err := tea.NewProgram(m).Run(); err != nil {
		return err
	}
	return nil
}

// LocalAgent is the agent a local run should sign with: whatever this machine
// is already running.
//
// Read from the environment rather than taken as a flag because a flag would
// have to be typed by somebody who already has a working agent, and the whole
// point is that there is nothing to set up. An empty result is not an error -
// it is a session that can look at an account and cannot change one, which is
// the honest state of a machine with no agent.
func LocalAgent() string {
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		return sock
	}
	return ""
}

// ownedView is a full-screen view, and is how every screen in this program
// makes one.
//
// It used to be the account screen alone that asked for the alternate screen
// buffer, which meant a session that arrived with nothing rendered its first
// screen inline and then jumped into the alternate one a keystroke later. Over
// SSH that was a flicker; run locally, where the program starts on the
// terminal it was called from, it would have been the program taking over the
// screen halfway through.
func ownedView(content string) tea.View {
	v := tea.NewView(content)
	v.AltScreen = true
	v.WindowTitle = "RouterCafe"
	return v
}
