package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"charm.land/log/v2"
	"github.com/btwiuse/wssh/client"
	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// defaultIdentities are tried when no key is named, in the order ssh itself
// would reach for them.
var defaultIdentities = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

func newClientCmd() *cobra.Command {
	var (
		addr            string
		username        string
		identities      []string
		passwordAuth    bool
		passphraseFile  string
		knownHosts      string
		insecureHostKey bool
		agentKey        string
		cols, rows      int
	)

	cmd := &cobra.Command{
		Use:   "client [url] [command...]",
		Short: "Connect to a WebSocket SSH server",
		Long: `Connect to a WebSocket SSH server, the same way ` + "`ssh -o ProxyCommand=...`" + ` does,
without needing a WebSocket proxy on the client side.

Given only a URL, it opens an interactive shell over the tunnel. Given a
command as well, it runs that and exits, exactly as ssh would.

Keys are read from ~/.ssh/id_ed25519 and its neighbours unless -i says
otherwise, and the server's host key is checked against ~/.ssh/known_hosts.
A server seen for the first time is offered for approval rather than trusted
quietly: an unchecked host key makes the login meaningless, because whatever
answers can read whatever is typed.

The local terminal is put into raw mode so that programs drawn on the far
side -- vim, htop, less -- get keystrokes one at a time and arrow keys as
keys rather than escape sequences. Resizing the window is forwarded as an
SSH window-change request.`,
		Example: `  # Interactive shell
  wssh client wss://ssh.example.com/ws

  # A particular key
  wssh client -i ~/.ssh/id_ed25519 wss://ssh.example.com/ws

  # Offer a password as well, prompted for
  wssh client --password-auth wss://ssh.example.com/ws

  # Expose the same key over an in-band ssh-agent channel; the remote
  # shell will see SSH_AUTH_SOCK and can use it for further hops
  wssh client --agent ~/.ssh/id_ed25519 wss://ssh.example.com/ws

  # Run one command and exit
  wssh client wss://ssh.example.com/ws -- uptime`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			url := addr
			if url == "" {
				url = args[0]
				args = args[1:]
			}
			opts, err := clientOptions(url, username, identities, passwordAuth,
				passphraseFile, knownHosts, insecureHostKey, agentKey, cols, rows)
			if err != nil {
				return err
			}
			return runClient(c.Context(), opts, strings.Join(args, " "))
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "", "WebSocket address to dial (or pass it as the first argument)")
	cmd.Flags().StringVar(&username, "user", "", "user to authenticate as (default $WS_USER or the current user)")
	cmd.Flags().StringArrayVarP(&identities, "identity", "i", nil,
		"private key to authenticate with, repeatable (default: ~/.ssh/id_ed25519 and friends)")
	cmd.Flags().BoolVar(&passwordAuth, "password-auth", false,
		"offer a password as well as any keys, prompting for it")
	cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "",
		"read the private key passphrase from this file instead of prompting")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", "",
		"known_hosts file to verify the server against (default ~/.ssh/known_hosts)")
	cmd.Flags().BoolVar(&insecureHostKey, "insecure-host-key", false,
		"do not verify the server's host key at all")
	cmd.Flags().StringVar(&agentKey, "agent", "",
		"unencrypted private key to expose over an in-band ssh-agent "+
			"channel; the same key is offered for pubkey auth and as the "+
			"agent's signing key, so the remote side can use it for further "+
			"hops. Encrypted keys are not supported.")
	cmd.Flags().IntVar(&cols, "cols", 0, "terminal columns to start with (default: detect)")
	cmd.Flags().IntVar(&rows, "rows", 0, "terminal rows to start with (default: detect)")

	return cmd
}

// clientOptions resolves everything that has to be settled before a session
// starts: who to log in as, what to offer, and what to trust.
func clientOptions(url, username string, identities []string, passwordAuth bool,
	passphraseFile, knownHostsPath string, insecureHostKey bool, agentKey string, cols, rows int,
) (*client.Options, error) {

	if !strings.HasPrefix(url, "ws://") && !strings.HasPrefix(url, "wss://") {
		return nil, fmt.Errorf("%q is not a WebSocket address; it should start with ws:// or wss://", url)
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
		return nil, errors.New("no user given: pass --user or set WS_USER")
	}

	// The --agent key also serves as a pubkey auth method. Add
	// it to the identities list so the standard "no keys were
	// found" check does not fire when the user only gave
	// --agent. The client.Dial path recognises the same key
	// path and avoids loading the file twice.
	if agentKey != "" {
		identities = append(identities, agentKey)
	}

	opts := &client.Options{URL: url, User: username, Cols: cols, Rows: rows}

	auth, err := clientAuthMethods(identities, passwordAuth, passphraseFile)
	if err != nil {
		return nil, err
	}
	opts.Auth = auth
	opts.AgentKeyPath = agentKey

	opts.HostKeyCallback, err = clientHostKeyCallback(knownHostsPath, insecureHostKey)
	if err != nil {
		return nil, err
	}
	return opts, nil
}

// clientAuthMethods builds what to offer the server, keys first and the
// password after, which is the order a person would try them in.
func clientAuthMethods(identities []string, passwordAuth bool, passphraseFile string) ([]gossh.AuthMethod, error) {
	paths := identities
	if len(paths) == 0 {
		paths = defaultIdentityPaths()
	}

	var auth []gossh.AuthMethod
	for _, path := range paths {
		signer, err := loadIdentity(path, passphraseFile)
		if err != nil {
			if len(identities) > 0 {
				// A key named on the command line is a mistake worth reporting.
				return nil, err
			}
			continue // a default key simply being absent is normal
		}
		auth = append(auth, gossh.PublicKeys(signer))
		log.Debug("offering key", "path", path)
	}

	if passwordAuth {
		auth = append(auth, gossh.PasswordCallback(promptPassword))
	}
	if len(auth) == 0 {
		return nil, errors.New("nothing to authenticate with: no keys were found and " +
			"--password-auth was not given")
	}
	return auth, nil
}

// defaultIdentityPaths lists the usual private keys that actually exist, so a
// missing one is not mistaken for a broken one.
func defaultIdentityPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var found []string
	for _, name := range defaultIdentities {
		path := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	return found
}

// loadIdentity reads a private key, asking for its passphrase if it has one.
func loadIdentity(path, passphraseFile string) (gossh.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}

	// An unencrypted key needs nothing from the user, which is the common case
	// and should not be interrupted by a prompt.
	if signer, err := gossh.ParsePrivateKey(raw); err == nil {
		return signer, nil
	}

	passphrase, err := secretFrom(passphraseFile,
		fmt.Sprintf("passphrase for %s", filepath.Base(path)))
	if err != nil {
		return nil, err
	}
	signer, err := gossh.ParsePrivateKeyWithPassphrase(raw, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("decrypt key %s: %w", path, err)
	}
	return signer, nil
}

// secretFrom reads a secret from a file when one is configured, and otherwise
// asks for it. Reading from a file is what makes this usable in a container,
// where there is no terminal to ask on.
func secretFrom(path, label string) (string, error) {
	if path == "" {
		return promptSecret(label)
	}
	value, err := readFirstLine(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return value, nil
}

// promptPassword is called by the SSH handshake when the keys were not enough.
// It runs before the terminal goes into raw mode, so it behaves normally.
func promptPassword() (string, error) {
	return promptSecret("password")
}

// clientHostKeyCallback decides how much to trust the far end.
//
// Skipping this is not a small thing: with an unchecked host key, anything on
// the path can present itself as the server and read whatever is typed.
func clientHostKeyCallback(path string, insecure bool) (gossh.HostKeyCallback, error) {
	if insecure {
		log.Warn("not verifying the server's host key: anything on this path could impersonate it")
		return gossh.InsecureIgnoreHostKey(), nil
	}

	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("no home directory to find known_hosts in: %w", err)
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}

	verify, err := knownhosts.New(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		if verify != nil {
			err := verify(hostname, remote, key)
			if err == nil {
				return nil
			}
			var unknown *knownhosts.KeyError
			if !errors.As(err, &unknown) || len(unknown.Want) > 0 {
				// Either the host is known and the key differs, which is the
				// dangerous case, or the check failed for some other reason.
				return err
			}
		}
		return trustUnknownHost(path, hostname, key)
	}, nil
}

// trustUnknownHost asks before believing a host it has not seen, and records
// the answer so the question is only asked once.
func trustUnknownHost(path, hostname string, key gossh.PublicKey) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("host %s is not in %s and there is no terminal to ask on it",
			hostname, path)
	}
	fmt.Fprintf(os.Stderr, "The authenticity of host '%s' can't be established.\n", hostname)
	fmt.Fprintf(os.Stderr, "%s key fingerprint is %s.\n", key.Type(), gossh.FingerprintSHA256(key))
	fmt.Fprint(os.Stderr, "Trust this host and add it to known_hosts? [y/N] ")

	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		return fmt.Errorf("host %s not trusted: %w", hostname, err)
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		return fmt.Errorf("host %s not trusted", hostname)
	}
	if err := appendKnownHost(path, hostname, key); err != nil {
		return err
	}
	log.Info("added host key", "host", hostname, "path", path)
	return nil
}

// appendKnownHost adds a line in the format known_hosts uses. The library
// reads that format but has no way to write it.
func appendKnownHost(path, hostname string, key gossh.PublicKey) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err //nolint:wrapcheck
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	// MarshalAuthorizedKey already renders "type base64", so the line is just
	// the host followed by that.
	_, err = fmt.Fprintf(f, "%s %s\n", hostname, gossh.MarshalAuthorizedKey(key))
	return err //nolint:wrapcheck
}

func runClient(ctx context.Context, opts *client.Options, command string) error {
	if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
		if opts.Cols == 0 {
			opts.Cols = w
		}
		if opts.Rows == 0 {
			opts.Rows = h
		}
	}
	if opts.Cols == 0 {
		opts.Cols = 80
	}
	if opts.Rows == 0 {
		opts.Rows = 24
	}

	closed := make(chan error, 1)
	opts.Command = command
	opts.OnData = func(p []byte) { _, _ = os.Stdout.Write(p) }
	opts.OnClose = func(err error) { closed <- err }

	// Connect before the terminal goes into raw mode: a passphrase or password
	// may still be needed, and it should be asked for on a normal terminal.
	session, err := client.Dial(ctx, *opts)
	if err != nil {
		return err //nolint:wrapcheck
	}
	defer session.Close() //nolint:errcheck

	// Raw mode is what makes the remote side behave like a terminal. It is
	// only meaningful when stdin is one.
	fd := int(os.Stdin.Fd())
	isTTY := term.IsTerminal(fd)
	if isTTY {
		state, err := term.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("put terminal in raw mode: %w", err)
		}
		// The terminal has to be handed back even if the session dies badly,
		// or the user is left with an unusable shell.
		defer func() { _ = term.Restore(fd, state) }()

		// Forward terminal resizes. Without this a resized window leaves
		// full-screen programs drawing to the geometry they started with.
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

	// Type in until stdin ends.
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
		// End of input is not end of session: send EOF and let the remote side
		// finish and report. Killing the connection here loses whatever it
		// still had buffered to say.
		session.CloseStdin()
	}()

	select {
	case err := <-closed:
		return err //nolint:wrapcheck
	case <-ctx.Done():
		return nil
	}
}
