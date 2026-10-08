package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// errNotATerminal is returned rather than falling back to reading from a pipe:
// a secret typed where it will end up in a shell history is worse than no
// secret at all.
var errNotATerminal = errors.New("standard input is not a terminal")

// promptSecret asks for a secret without echoing it.
//
// Everything that needs one -- key passphrases, server passwords -- goes
// through here, and is asked before the terminal is switched into raw mode for
// the session, so the prompt behaves the way a normal prompt does.
func promptSecret(label string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("cannot prompt for %s: %w", label, errNotATerminal)
	}
	fmt.Fprintf(os.Stderr, "%s: ", label)
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err //nolint:wrapcheck
	}
	return string(secret), nil
}

// readFirstLine reads a line from a file, so a secret can be supplied by
// mounting a file rather than being typed.
func readFirstLine(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err //nolint:wrapcheck
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return value, nil
}
