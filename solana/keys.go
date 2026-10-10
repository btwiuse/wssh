package solana

// Naming what an agent holds.
//
// A Solana account address is an ed25519 public key written in base58. That
// is the whole correspondence, and it is worth being blunt about because it is
// easy to assume otherwise: an ed25519 SSH key is not turned into an address,
// hashed, derived, or looked up anywhere. It already is one. Every other kind
// of key has no address at all, which is a fact to say out loud rather than
// leave as a blank column beside an RSA key.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/btwiuse/wssh/auth/siws"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AgentKey is one key the agent says it holds, and the account it names.
type AgentKey struct {
	// Public is the key in the form ssh-add prints it. It is nil when the
	// agent sent something this could not parse, which is not a reason to
	// end the listing: the keys it did send are still worth showing.
	Public gossh.PublicKey

	// Address is the account this key signs for, base58. Empty when there is
	// none.
	Address string

	// Reason is why Address is empty, in words worth putting in front of a
	// person. A line reading "solana  (none: a ssh-rsa key is not an
	// ed25519 public key...)" is informative; the same line reading
	// "solana" with nothing after it looks like a bug.
	Reason string

	// Comment is the label the agent carries with the key, the one
	// ssh-add -L puts at the end of the line. It is whatever the agent said,
	// kept verbatim.
	//
	// Who decides it is the point. An OpenSSH agent sends what was in the
	// key file - `user@host`. This repository's own keyring is handed a
	// comment by whoever built it, because that is the only place that
	// knows where a key came from: the file it was read from, the page
	// that imported it, the wallet it belongs to. This field reports that
	// and adds nothing of its own, so what a line says about a key's
	// origin is something an agent actually claimed.
	Comment string
}

// AuthorizedKey is the line ssh-add -L prints for this key: the
// authorized_keys line, then the agent's comment. Or "" when the key could
// not be parsed and there is no line to print.
func (k AgentKey) AuthorizedKey() string {
	if k.Public == nil {
		return ""
	}
	line := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(k.Public)))
	if k.Comment == "" {
		return line
	}
	return line + " " + k.Comment
}

// Type is the algorithm name as the agent protocol spells it.
func (k AgentKey) Type() string {
	if k.Public == nil {
		return "unknown"
	}
	return k.Public.Type()
}

// AddressFor names the account a public key signs for.
//
// The result is exactly the key, in base58: an ed25519 public key is 32 bytes
// and an account address is those 32 bytes written differently, so the two
// can be compared byte for byte and always will be. That is also why the
// address here is the string sol-tx wants as --signer for this key to sign the
// fee - it is not a derived name that has to be resolved back.
//
// Anything else is refused with the reason attached, rather than quietly
// reduced to something that is not an address. A certificate is followed to
// the key inside it, because a certificate names the same key the account
// would be and showing the outer algorithm would say nothing useful.
func AddressFor(pub gossh.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("there is no key to name")
	}
	if cert, ok := pub.(*gossh.Certificate); ok {
		return AddressFor(cert.Key) //nolint:wrapcheck
	}
	if pub.Type() != gossh.KeyAlgoED25519 {
		return "", fmt.Errorf("a %s key is not an ed25519 public key, and an account address is exactly that",
			pub.Type())
	}
	curve, ok := pub.(gossh.CryptoPublicKey)
	if !ok {
		return "", fmt.Errorf("a %s key here exposes no curve to read", pub.Type())
	}
	raw, ok := curve.CryptoPublicKey().(ed25519.PublicKey)
	if !ok || len(raw) != ed25519.PublicKeySize {
		return "", fmt.Errorf("a %s key here is not %d bytes of public key", pub.Type(), ed25519.PublicKeySize)
	}
	return siws.Base58Encode(raw), nil
}

// ListAgentKeys asks the agent what keys it holds.
//
// A key that cannot be read becomes an entry with no address rather than an
// error, because one odd key should not hide the four that parsed. A key that
// parsed but is not ed25519 is reported the same way, with the reason
// distinguishing the two.
func ListAgentKeys(conn agent.ExtendedAgent) ([]AgentKey, error) {
	held, err := conn.List()
	if err != nil {
		return nil, fmt.Errorf("ask the agent what keys it holds: %w", err)
	}
	keys := make([]AgentKey, 0, len(held))
	for _, one := range held {
		key := AgentKey{}
		pub, err := gossh.ParsePublicKey(one.Blob)
		if err != nil {
			key.Reason = fmt.Sprintf("the agent sent a key this could not read: %v", err)
			keys = append(keys, key)
			continue
		}
		key.Public = pub
		key.Comment = one.Comment
		key.Address, key.Reason = addressAndReason(pub)
		keys = append(keys, key)
	}
	return keys, nil
}

// addressAndReason is AddressFor shaped for a listing, where a key that names
// no account is information rather than a failure.
func addressAndReason(pub gossh.PublicKey) (string, string) {
	address, err := AddressFor(pub)
	if err != nil {
		return "", err.Error()
	}
	return address, ""
}

// listTimeout bounds the listing. Unlike signing, nothing here waits on a
// person, so the bound can be short: a forwarded agent answers in the time it
// takes to cross the session, and one that has not answered by now is not
// going to.
const listTimeout = 30 * time.Second

// ListAgentKeysAt lists the keys held by the agent listening on sockPath.
//
// An empty path means $SSH_AUTH_SOCK, which is the socket a wssh session
// points everything that wants a signature at - including this.
func ListAgentKeysAt(ctx context.Context, sockPath string) ([]AgentKey, error) {
	if sockPath == "" {
		sockPath = os.Getenv("SSH_AUTH_SOCK")
	}
	if sockPath == "" {
		return nil, errors.New("no agent: SSH_AUTH_SOCK is not set, so there is nothing to list")
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("reach the agent at %s: %w", filepath.Base(sockPath), err)
	}
	defer conn.Close() //nolint:errcheck

	if deadline, ok := ctx.Deadline(); !ok || deadline.Before(time.Now().Add(listTimeout)) {
		if err := conn.SetDeadline(time.Now().Add(listTimeout)); err != nil {
			return nil, fmt.Errorf("bound the listing: %w", err)
		}
	}

	return ListAgentKeys(agent.NewClient(conn))
}
