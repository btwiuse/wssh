// Package auth decides who may open an SSH session.
//
// Authentication is optional in the sense that it stays off until you ask for
// it, which is convenient for local development and catastrophic anywhere else.
// A server with no configuration at all accepts every connection, so the
// command that builds one says so out loud rather than leaving it to be
// discovered.
package auth

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"charm.land/log/v2"
	"charm.land/ssh"
	"charm.land/wish/v2"
	"golang.org/x/crypto/bcrypt"
)

// SystemAuthorizedKeys is the value accepted wherever a key file is expected,
// standing for "wherever this machine normally keeps authorized keys".
const SystemAuthorizedKeys = "system"

// Config describes how clients authenticate. The zero value authenticates
// nobody, which means it lets everybody in.
type Config struct {
	// KeyFiles are authorized_keys files. The literal value "system" expands
	// to the machine's usual locations.
	KeyFiles []string

	// Keys are authorized_keys entries given directly, in the same format as
	// a line in an authorized_keys file.
	Keys []string

	// PasswordFile is a file of accepted passwords, one per line. Blank lines
	// and lines starting with # are ignored. An entry beginning with $2 is
	// treated as a bcrypt hash, anything else as a literal password.
	PasswordFile string

	// Passwords are accepted passwords given directly. They end up in the
	// process's argument list, which any local user can read; PasswordFile
	// exists precisely so that this is not necessary.
	Passwords []string
}

// Enabled reports whether any authentication method is configured.
func (c Config) Enabled() bool {
	return len(c.KeyFiles) > 0 || len(c.Keys) > 0 ||
		c.PasswordFile != "" || len(c.Passwords) > 0
}

// Options returns the wish options implementing the configuration.
//
// It returns none at all when nothing is configured, and that is deliberate:
// the SSH server allows unauthenticated connections only while no handler is
// installed, so the difference between "authentication configured" and
// "authentication not configured" is entirely the length of this slice.
func (c Config) Options() ([]ssh.Option, error) {
	var opts []ssh.Option

	if c.hasKeys() {
		keys, err := parseInlineKeys(c.Keys)
		if err != nil {
			return nil, err
		}
		files := expandKeyFiles(c.KeyFiles)
		opts = append(opts, wish.WithPublicKeyAuth(func(_ ssh.Context, key ssh.PublicKey) bool {
			// Files are re-read on every attempt on purpose. Adding a key
			// should not mean restarting the server, which is the whole reason
			// to keep a file rather than a list baked in at startup.
			if matchesAnyFile(files, key) {
				return true
			}
			return matchesAny(keys, key)
		}))
	}

	if c.hasPasswords() {
		file := c.PasswordFile
		opts = append(opts, wish.WithPasswordAuth(func(_ ssh.Context, password string) bool {
			for _, candidate := range c.Passwords {
				if checkSecret(candidate, password) {
					return true
				}
			}
			if file == "" {
				return false
			}
			accepted, err := readPasswords(file)
			if err != nil {
				// A password file we cannot read must never become a way in.
				log.Warn("could not read password file", "path", file, "error", err)
				return false
			}
			for _, candidate := range accepted {
				if checkSecret(candidate, password) {
					return true
				}
			}
			return false
		}))
	}

	return opts, nil
}

func (c Config) hasKeys() bool {
	return len(c.KeyFiles) > 0 || len(c.Keys) > 0
}

func (c Config) hasPasswords() bool {
	return c.PasswordFile != "" || len(c.Passwords) > 0
}

// parseInlineKeys parses authorized_keys entries supplied directly.
func parseInlineKeys(entries []string) ([]ssh.PublicKey, error) {
	keys := make([]ssh.PublicKey, 0, len(entries))
	for i, entry := range entries {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry))
		if err != nil {
			return nil, fmt.Errorf("authorized key #%d: %w", i+1, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// expandKeyFiles turns the "system" shorthand into the authorized_keys files
// that actually exist on this machine.
func expandKeyFiles(paths []string) []string {
	var out []string
	for _, p := range paths {
		if p != SystemAuthorizedKeys {
			out = append(out, p)
			continue
		}
		out = append(out, systemAuthorizedKeyFiles()...)
	}
	return out
}

func systemAuthorizedKeyFiles() []string {
	candidates := []string{"/etc/ssh/authorized_keys"}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".ssh", "authorized_keys"))
	}
	var found []string
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	return found
}

// matchesAnyFile reports whether key appears in any of the given files.
func matchesAnyFile(paths []string, key ssh.PublicKey) bool {
	for _, path := range paths {
		if matchFile(path, key) {
			return true
		}
	}
	return false
}

func matchFile(path string, key ssh.PublicKey) bool {
	f, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warn("could not read authorized keys", "path", path, "error", err)
		}
		return false
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		authorized, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			// One bad line should not lock everyone out, but it is worth
			// saying out loud: it is usually a typo that silently fails open.
			log.Warn("skipping malformed authorized key", "path", path, "error", err)
			continue
		}
		if ssh.KeysEqual(authorized, key) {
			return true
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn("could not read authorized keys", "path", path, "error", err)
	}
	return false
}

func matchesAny(keys []ssh.PublicKey, key ssh.PublicKey) bool {
	for _, k := range keys {
		if ssh.KeysEqual(k, key) {
			return true
		}
	}
	return false
}

// readPasswords loads accepted passwords from a file.
func readPasswords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err //nolint:wrapcheck
	}
	defer f.Close() //nolint:errcheck

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// checkSecret compares an offered password against an accepted entry, which is
// either a bcrypt hash or a literal password.
func checkSecret(accepted, offered string) bool {
	if strings.HasPrefix(accepted, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(accepted), []byte(offered)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(accepted), []byte(offered)) == 1
}
