// Package siws is Sign In With Solana: proving control of an account by
// signing a short readable message instead of the binary blob SSH requires.
//
// It is its own package because the browser client needs it and the client is
// compiled for js/wasm, where wish - and through it bubbletea - has no build.
// Nothing here needs a server or a transport; it is text, signatures and an
// allow list.
package siws

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// SIWSAuth accepts a browser that has proved control of a Solana account by
// signing a short readable message, instead of by signing the binary blob that
// SSH authentication requires.
//
// It exists because a wallet will sign text and will not sign binary. That is
// not a wallet quirk to work around but a boundary: SSH's userauth signature
// covers a random session identifier and a packet, so it is binary by
// construction, and no amount of wishing changes the bytes the client has to
// hand back. This path gets the same identity through a message a person can
// read and a wallet can be asked to approve.
//
// The trade is real and worth stating. SSH's binary challenge is harder to
// phish because nobody can show it to a user in a way that looks meaningful; a
// readable message can be shown by a page that is not this server. What makes
// that survivable here is that the domain in the message is this server's, and
// a wallet checks the domain against the page it was asked from. Everything the
// server hands the wallet - domain, uri, statement, nonce, times - is generated
// server-side and never taken from the request.
type SIWSAuth struct {
	// Addresses is the allow list, as raw ed25519 public keys. Anything not on
	// it is refused, so connecting this at all is opt-in per account rather
	// than opt-in per server.
	Addresses [][]byte

	// URI is what the message is about. Left empty it is omitted, which is
	// what a wallet does when it is not given one.
	URI string

	// Statement is one line of human-readable text shown above the request.
	Statement string

	// Lifetime is how long a sign-in stays usable. It is short because a
	// signed message is a bearer credential for that window.
	Lifetime time.Duration

	// Now, when set, is the clock. Tests set it; production leaves it nil.
	Now func() time.Time
}

func (c SIWSAuth) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c SIWSAuth) lifetime() time.Duration {
	if c.Lifetime > 0 {
		return c.Lifetime
	}
	return siwsLifetime
}

const siwsLifetime = 60 * time.Second

// Enabled reports whether there is anything to accept.
func (c SIWSAuth) Enabled() bool { return len(c.Addresses) > 0 }

// Challenge is the sign-in request handed to a wallet.
func (c SIWSAuth) Challenge(domain string) (SIWSInput, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return SIWSInput{}, fmt.Errorf("nonce: %w", err)
	}

	now := c.now()
	return SIWSInput{
		Domain:    domain,
		URI:       c.URI,
		Statement: c.Statement,
		Version:   SIWSDefaultVersion,
		ChainID:   SIWSDefaultChainID,
		Nonce:     hex.EncodeToString(nonce),
		// UTC, like the wallets that produce these. A local offset would
		// parse back fine but reads as a different time to anyone comparing
		// two sign-ins by eye.
		IssuedAt:  now.UTC().Format(time.RFC3339),
		ExpiresAt: now.Add(c.lifetime()).UTC().Format(time.RFC3339),
	}, nil
}

// Verify checks a wallet's answer to a challenge.
//
// The account the message names is checked against the allow list, the domain
// against the one this connection actually arrived at, the expiry against the
// clock, and the signature against the account - in that order, so the most
// useful refusal is the first one reached.
//
// domain is per connection rather than per server because it is whatever host
// the client reached, and one server can be reachable under more than one.
//
// The address is returned as the wallet wrote it, read back out of the message
// it signed, rather than re-encoded here.
func (c SIWSAuth) Verify(message, signature []byte, domain string) (ed25519.PublicKey, string, error) {
	parsed, err := VerifySIWS(message, signature, domain, c.Addresses, c.now())
	if err != nil {
		return nil, "", err
	}
	key, err := base58Decode(parsed.Address)
	if err != nil {
		return nil, "", err
	}
	return ed25519.PublicKey(key), parsed.Address, nil
}

// ParseAuthorizedAddresses reads an allow list.
//
// Both forms a Solana user is likely to have are accepted: an SSH public key,
// which is what a wallet's key or ssh-add -L produces, and the bare hex of the
// key. A base58 address is not handled here on purpose - decoding that alphabet
// inside an authentication path is a bad trade, and a caller who has one can
// send hex instead.
func ParseAuthorizedAddresses(entries []string) ([][]byte, error) {
	var keys [][]byte
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(entry)); err == nil {
			crypto, ok := pub.(gossh.CryptoPublicKey)
			if !ok {
				return nil, fmt.Errorf("%q is not a crypto key", entry)
			}
			raw, ok := crypto.CryptoPublicKey().(ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("%q is not an ed25519 key", entry)
			}
			keys = append(keys, raw)
			continue
		}
		raw, err := hex.DecodeString(entry)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%q is neither an SSH ed25519 public key nor a hex key", entry)
		}
		keys = append(keys, raw)
	}
	return keys, nil
}
