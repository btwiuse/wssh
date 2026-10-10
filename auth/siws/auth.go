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
	// than opt-in per server. Empty is meaningless on its own: see Open.
	Addresses [][]byte

	// Open accepts any account that can sign, which is what `*` on the command
	// line means. It is the dapp model - holding a wallet proves you are
	// someone, not who.
	//
	// Worth being clear about what that costs, because the name suggests less
	// than it does. The username in an SSH session is chosen by the client, so
	// an open wallet sign-in is not a way to be told apart from another wallet
	// holder: it is a way for anyone holding any wallet at all to reach the
	// shell this server offers. That is what `*` means everywhere else in this
	// program too.
	Open bool

	// MaxAge is how old a sign-in may be before it stops being accepted.
	MaxAge time.Duration

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
func (c SIWSAuth) Enabled() bool { return c.Open || len(c.Addresses) > 0 }

// Policy is the check this configuration performs.
func (c SIWSAuth) Policy() Policy {
	return Policy{Allowed: c.Addresses, Open: c.Open, MaxAge: c.MaxAge}
}

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
func (c SIWSAuth) Verify(message, signature []byte, domain string) (string, error) {
	parsed, _, err := VerifySIWS(message, signature, domain, c.Policy(), c.now())
	if parsed.Address != "" {
		return parsed.Address, err
	}
	return "", err
}

// AnyAddress is the --authorized-addresses value that accepts every account.
// It is a star for the same reason --origins takes one.
const AnyAddress = "*"

// ParseAuthorizedAddresses reads an allow list.
//
// Three forms name one account, and all three are accepted because the same
// account turns up in all three and asking anyone to convert one they already
// have is a pointless step: a Solana address in base58, an SSH ed25519 public
// key, and the bare hex of the key. All three are the same 32 bytes, and none
// is normalised into another; each is read in its own encoding and compared as
// bytes.
//
// `*` accepts every account, which is a different thing entirely from naming
// none, and returns open rather than an empty list so the two cannot be
// confused.
func ParseAuthorizedAddresses(entries []string) (addresses [][]byte, open bool, err error) {
	for _, entry := range entries {
		if strings.TrimSpace(entry) == AnyAddress {
			return nil, true, nil
		}
	}

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(entry)); err == nil {
			crypto, ok := pub.(gossh.CryptoPublicKey)
			if !ok {
				return nil, false, fmt.Errorf("%q is not a crypto key", entry)
			}
			raw, ok := crypto.CryptoPublicKey().(ed25519.PublicKey)
			if !ok {
				return nil, false, fmt.Errorf("%q is not an ed25519 key", entry)
			}
			addresses = append(addresses, raw)
			continue
		}
		if raw, err := hex.DecodeString(entry); err == nil && len(raw) == ed25519.PublicKeySize {
			addresses = append(addresses, raw)
			continue
		}
		// An address, which is what a person reads. A miss is a refusal rather
		// than a fallback: guessing at an account is the last thing an allow
		// list should do.
		raw, err := Base58Decode(entry)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, false, fmt.Errorf(
				"%q is not an ed25519 public key, a Solana address, a 64-character hex key, or %q",
				entry, AnyAddress)
		}
		addresses = append(addresses, raw)
	}
	return addresses, false, nil
}
