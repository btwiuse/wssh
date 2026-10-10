package client

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// ErrSignatureDeclined is what a ConfirmingSigner returns when the user says
// no. The agent protocol turns it into a plain failure for the far end, which
// is the right outcome: nothing is signed, and the program that asked finds
// out.
var ErrSignatureDeclined = errors.New("signature declined")

// AskSignature is consulted before every signature. It gets a short summary of
// what is being signed, never the key material, and answers yes or no.
//
// The contract has to be "ask again next time". A ConfirmingSigner that
// remembered a yes would be a standing permission, which is the thing this
// whole type exists to avoid.
type AskSignature func(summary string) (bool, error)

// ConfirmingSigner wraps a signer and asks before it uses it.
//
// This is what makes it reasonable to forward an agent from a browser. The
// private key never leaves, so the obvious worry is that the far end gets to
// sign with it whenever it likes. It does, but not without this asking first.
//
// The cost is that the caller is blocked for as long as the question takes.
// agent.ServeAgent handles one request at a time per channel, so a Sign that
// waits holds up every other agent request behind it, including the List that
// tells a program which keys exist. That is the right way round: a signature
// waiting on a human should queue behind nothing rather than let requests jump
// it, and a user who walks away from the dialog should not wedge the session
// forever, so ask is expected to give up rather than block indefinitely.
type ConfirmingSigner struct {
	inner gossh.Signer
	name  string
	ask   AskSignature
}

// NewConfirmingSigner wraps inner so that ask is consulted before each
// signature. name is what the question refers to the key by.
func NewConfirmingSigner(inner gossh.Signer, name string, ask AskSignature) gossh.Signer {
	return &ConfirmingSigner{inner: inner, name: name, ask: ask}
}

func (c *ConfirmingSigner) PublicKey() gossh.PublicKey { return c.inner.PublicKey() }

func (c *ConfirmingSigner) Sign(rand io.Reader, data []byte) (*gossh.Signature, error) {
	if c.ask == nil {
		// No way to ask is not the same as permission. Wrapping a signer
		// and getting silence back must not turn into a silent signature.
		return nil, errors.New("no way to ask before signing")
	}

	ok, err := c.ask(c.summary(data))
	if err != nil {
		return nil, fmt.Errorf("ask before signing: %w", err)
	}
	if !ok {
		return nil, ErrSignatureDeclined
	}
	return c.inner.Sign(rand, data)
}

// summary describes what is about to be signed. It never includes the key, and
// the data itself is only shown when it looks like something a person would
// recognise; a hex prefix is the honest answer for everything else.
func (c *ConfirmingSigner) summary(data []byte) string {
	what := printable(data)
	if what == "" {
		what = hex.EncodeToString(head(data, 24))
		if len(data) > 24 {
			what += "..."
		}
	}
	return fmt.Sprintf("%s wants to sign %d bytes: %s", c.name, len(data), what)
}

// head returns at most n bytes of b.
func head(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// printable returns data as text if it is short and mostly printable, and the
// empty string otherwise. Guessing wrong here would be worse than showing
// nothing, because the guess is what the user is asked to approve.
func printable(data []byte) string {
	const max = 120
	if len(data) == 0 || len(data) > max {
		return ""
	}
	for _, b := range data {
		if b != '\n' && b != '\t' && (b < 0x20 || b > 0x7e) {
			return ""
		}
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return ""
	}
	return text
}
