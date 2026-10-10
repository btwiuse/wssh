package client

import (
	"errors"
	"fmt"
	"io"

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

	ok, err := c.ask(summarizeSignature(c.name, data))
	if err != nil {
		return nil, fmt.Errorf("ask before signing: %w", err)
	}
	if !ok {
		return nil, ErrSignatureDeclined
	}
	return c.inner.Sign(rand, data)
}

// confirmBeforeSigning is whether a signature should stop and ask.
//
// Turning it off keeps the ordinary case ordinary: without it the session
// never opens an agent channel and the page is never asked anything about
// signing.
func confirmBeforeSigning(forward bool, ask AskSignature) bool {
	return forward && ask != nil
}

// confirmOne is one signer that asks first.
//
// The label comes from the public key rather than from the key material,
// because the wrapping happens after parsing, where the names have been
// dropped. That is a lesser loss than it looks: what the question needs to say
// is which key is asking, and a fingerprint does that.
func confirmOne(signer gossh.Signer, ask AskSignature) gossh.Signer {
	return NewConfirmingSigner(signer, keyLabel(signer), ask)
}

// keyLabel names a key the way a person would recognise it.
func keyLabel(signer gossh.Signer) string {
	pub := signer.PublicKey()
	if fp := gossh.FingerprintSHA256(pub); fp != "" {
		return fmt.Sprintf("%s %s", pub.Type(), fp)
	}
	return pub.Type()
}
