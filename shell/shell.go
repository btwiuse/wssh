// Package shell provides a Wish middleware that runs a login shell, the way a
// plain sshd would.
//
// Wish v2 dropped the old shell package, so this is the v2 equivalent. It
// manages the PTY itself rather than going through wish.Command, because a
// usable login shell needs three things wish.Cmd does not do: honour the
// command the client asked for, keep terminal resizes in sync, and enable job
// control so ^C and ^Z reach the foreground job.
package shell

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"charm.land/log/v2"
	"charm.land/ssh"
	"charm.land/wish/v2"
)

// defaultTerm is used when the client did not ask for a PTY, so programs that
// consult TERM still get a sensible terminal type.
const defaultTerm = "xterm-256color"

// Middleware runs the local user's shell for the session.
func Middleware() wish.Middleware {
	return func(next ssh.Handler) ssh.Handler {
		return func(s ssh.Session) {
			// Subsystem requests (sftp, scp) are not shells: let other
			// middleware handle them instead of dropping into a shell.
			if s.Subsystem() != "" {
				next(s)
				return
			}

			pty, _, hasPty := s.Pty()
			log.Debug("session handler",
				"user", s.User(),
				"command", s.RawCommand(),
				"pty", hasPty,
				"term", termOf(pty, hasPty),
			)

			if err := run(s); err != nil {
				// A command that fails is not a server error. Reporting it
				// with the status it actually exited with is what lets
				// scripts and CI see the truth; collapsing everything to 1
				// would make every failure look identical.
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					_ = s.Exit(exitErr.ExitCode())
					return
				}
				wish.Fatalln(s, err)
			}
			next(s)
		}
	}
}

// termOf reports the requested terminal type, if any.
func termOf(pty ssh.Pty, ok bool) string {
	if !ok {
		return ""
	}
	return pty.Term
}

// run executes the shell on the session, allocating a PTY when the client
// asked for one.
func run(s ssh.Session) error {
	name, argv := invocation(s)

	pty, winCh, hasPty := s.Pty()
	if !hasPty {
		// No terminal: wire the session straight to the process, the way
		// ssh host cmd behaves without -t.
		cmd := exec.CommandContext(s.Context(), name, argv...)
		cmd.Env = environ(s, "")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s.Stderr()
		return cmd.Run() //nolint:wrapcheck
	}

	cmd := exec.CommandContext(s.Context(), name, argv...)
	cmd.Env = environ(s, pty.Term)

	// WithJobControl puts the shell in its own session with the PTY as its
	// controlling terminal. Without it bash reports "no job control in this
	// shell" and ^C kills the shell instead of the foreground job.
	if err := pty.Start(cmd, ssh.WithJobControl()); err != nil {
		return err //nolint:wrapcheck
	}

	defer watchWindow(pty, winCh)()
	return cmd.Wait() //nolint:wrapcheck
}

// invocation returns the program and arguments to run: the command the client
// asked for, or a login shell when it just wants a session. The command goes
// through the shell rather than exec'ing it directly so that quoting, pipes
// and redirection work the way they do under sshd.
func invocation(s ssh.Session) (string, []string) {
	if raw := s.RawCommand(); strings.TrimSpace(raw) != "" {
		return path(), []string{"-c", raw}
	}
	return path(), loginArgs()
}

// watchWindow applies SSH window-change requests to the PTY and returns a
// function that stops watching.
//
// Without this the PTY keeps the size it was created with, so after a resize
// full-screen programs (vim, less, top) still draw to the old dimensions. The
// Pty value is a copy, but its master fd is the same one the command is
// running on, so Resize lands on the right PTY.
func watchWindow(pty ssh.Pty, winCh <-chan ssh.Window) (stop func()) {
	if winCh == nil {
		return func() {}
	}

	stopCh := make(chan struct{})
	go func() {
		for {
			select {
			case win, open := <-winCh:
				if !open {
					return
				}
				_ = pty.Resize(win.Width, win.Height)
			case <-stopCh:
				return
			}
		}
	}()

	return func() { close(stopCh) }
}

// path returns the shell to run, honouring $SHELL the way sshd does.
func path() string {
	if runtime.GOOS == "windows" {
		if sh := os.Getenv("COMSPEC"); sh != "" {
			return sh
		}
		return "powershell.exe"
	}
	if sh := os.Getenv("SHELL"); sh != "" {
		return sh
	}
	return "/bin/sh"
}

// loginArgs returns the arguments that make the shell a login shell.
func loginArgs() []string {
	if runtime.GOOS == "windows" {
		if strings.EqualFold(filepath.Base(path()), "powershell.exe") {
			return []string{"-NoLogo"}
		}
		return nil
	}
	return []string{"-l"}
}

// environ builds the child environment from the session, filling in the
// variables a login shell needs but ssh clients do not send.
func environ(s ssh.Session, term string) []string {
	env := s.Environ()

	if term == "" {
		term = defaultTerm
	}
	env = set(env, "TERM", term)
	env = set(env, "SHELL", path())

	if user := s.User(); user != "" {
		env = set(env, "USER", user)
		env = set(env, "LOGNAME", user)
	}
	// ssh(1) forwards neither of these, but a login shell misbehaves without
	// them: wrong history path, wrong config directory.
	if home, err := os.UserHomeDir(); err == nil {
		env = set(env, "HOME", home)
	}
	if pwd, err := os.Getwd(); err == nil {
		env = set(env, "PWD", pwd)
	}

	return env
}

// set replaces key in env, or appends it when absent.
func set(env []string, key, value string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}
