package siws

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Sign-In With Solana.
//
// A wallet is asked to sign a short piece of readable English rather than a
// blob of binary, because that is the only kind of thing wallets reliably sign.
// A Solana signature is a plain ed25519 signature over the message's bytes, so
// the server verifies it the same way it would verify anything else: with
// ed25519.Verify, over the exact bytes that were signed.
//
// The message is built by the wallet from the fields in SIWSInput, and this
// package has to reproduce it byte for byte to check it. Getting a byte wrong
// does not weaken anything - the signature simply will not verify against the
// text a human reads - which is why Format and Parse are written to be exact
// inverses and tested as such.

// skewTolerance is how far ahead of us a message may claim to have been issued.
// Sign-in messages carry the client's clock, and browsers and servers disagree
// by a few seconds; a minute absorbs that without letting anything be from the
// future in any meaningful sense.
const skewTolerance = time.Minute

// containsKey reports whether want is one of keys.
func containsKey(keys [][]byte, want []byte) bool {
	for _, key := range keys {
		if len(key) == len(want) && string(key) == string(want) {
			return true
		}
	}
	return false
}

// SIWSDefaultVersion and SIWSDefaultChainID are what a wallet uses when the
// request leaves them out.
const (
	SIWSDefaultVersion = "1"
	SIWSDefaultChainID = "solana:mainnet"
)

// siwsHeader introduces the message. It is fixed text in every SIWS message,
// and it is the first thing a person reads.
const siwsHeader = "wants you to sign in with your Solana account:"

// ErrNotAuthorized means the account that signed is not on the allow list.
//
// It is a distinct error rather than only a message because it is the one
// people hit, and the one where the fix is obvious: add the account. Callers
// use it to answer that differently from a sign-in that failed for any other
// reason.
var ErrNotAuthorized = errors.New("account is not authorized")

// SIWSInput is the request handed to a wallet's signIn.
//
// Every field except the address is chosen by the server. The address is the
// one the wallet itself reports, and the server never supplies it: a server
// that chose which account to claim would be asking the wallet to prove
// something other than who is asking.
type SIWSInput struct {
	// Domain is the host the request came from. It must come from the
	// server, never from the page: a page that could set this could ask a
	// wallet to sign a message naming someone else's domain.
	Domain string `json:"domain"`

	// URI is what the message is about, usually the page's own address.
	URI string `json:"uri"`

	// Address is the base58 account the wallet is being asked about. It is
	// reported back rather than requested.
	Address string `json:"address"`

	Statement string `json:"statement"`
	Version   string `json:"version"`
	ChainID   string `json:"chainId"`
	Nonce     string `json:"nonce"`
	IssuedAt  string `json:"issuedAt"`

	// ExpiresAt, when set, is written into the message as an expiry so a
	// captured message stops being usable on its own.
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// Format renders the message exactly as a wallet renders it.
//
// Field order is the wallet's, not the specification's: URI, Version, Chain
// ID, Nonce, Issued At. An empty optional field is left out entirely rather
// than written as an empty line, because a wallet that omits a field and a
// wallet that writes "Expiration Time: " produce different bytes and only one
// of them is the message a person actually saw.
func (i SIWSInput) Format() string {
	// An empty field contributes no line at all. A wallet omits a field it was
	// not given rather than writing its label with nothing after it, so leaving
	// a blank line behind would be a byte the wallet never wrote.
	lines := []string{
		fmt.Sprintf("%s %s", i.Domain, siwsHeader),
		i.Address,
		"",
	}
	if i.Statement != "" {
		lines = append(lines, i.Statement, "")
	}
	for _, field := range [][2]string{
		{"URI", i.URI},
		{"Version", firstNonEmpty(i.Version, SIWSDefaultVersion)},
		{"Chain ID", firstNonEmpty(i.ChainID, SIWSDefaultChainID)},
		{"Nonce", i.Nonce},
		{"Issued At", i.IssuedAt},
		{"Expiration Time", i.ExpiresAt},
	} {
		if field[1] != "" {
			lines = append(lines, field[0]+": "+field[1])
		}
	}

	// No trailing newline: a wallet that ends the message with one signs
	// different bytes from one that does, and this has to match the wallet that
	// will actually produce it.
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// siwsFieldLabels are the labels a message may carry, in the order they appear.
// Anything else means this is not a message we issued.
var siwsFieldLabels = []string{
	"URI", "Version", "Chain ID", "Nonce", "Issued At", "Expiration Time",
}

// ParseSIWS reads a signed message back into its fields.
//
// Strict on purpose. This text is what a person approved, so a parser that
// tolerates anything is a parser that can be shown one thing and used for
// another. Every line has to be a known label, and the header has to be the one
// a Solana wallet writes.
func ParseSIWS(message []byte) (SIWSInput, error) {
	text := string(message)
	if strings.Contains(text, "\r") {
		return SIWSInput{}, errors.New("message contains carriage returns")
	}

	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 2 {
		return SIWSInput{}, errors.New("message is too short to be a sign-in")
	}

	header := strings.TrimSuffix(lines[0], " ")
	if !strings.HasSuffix(header, " "+siwsHeader) {
		return SIWSInput{}, errors.New("message does not start with a Solana sign-in header")
	}
	in := SIWSInput{Domain: strings.TrimSuffix(header, " "+siwsHeader)}

	in.Address = lines[1]
	if in.Address == "" {
		return SIWSInput{}, errors.New("message names no account")
	}

	// What is left is an optional statement, then the labelled fields. The
	// blank line separating the account from the statement comes first, so
	// blanks are skipped before deciding whether a statement is there at all.
	rest := lines[2:]
	for len(rest) > 0 && rest[0] == "" {
		rest = rest[1:]
	}
	if len(rest) > 0 && !isSIWSField(rest[0]) {
		in.Statement = rest[0]
		rest = rest[1:]
		for len(rest) > 0 && rest[0] == "" {
			rest = rest[1:]
		}
	}
	for _, line := range rest {
		if line == "" {
			continue
		}
		label, value, found := strings.Cut(line, ": ")
		if !found || !isSIWSLabel(label) {
			return SIWSInput{}, fmt.Errorf("message contains an unrecognised line %q", line)
		}
		switch label {
		case "URI":
			in.URI = value
		case "Version":
			in.Version = value
		case "Chain ID":
			in.ChainID = value
		case "Nonce":
			in.Nonce = value
		case "Issued At":
			in.IssuedAt = value
		case "Expiration Time":
			in.ExpiresAt = value
		}
		if value == "" {
			// A label with nothing after it is not something a wallet
			// writes; leaving it writable would let two fields be smuggled
			// into one line, where only the first would be read.
			return SIWSInput{}, fmt.Errorf("field %q has no value", label)
		}
		// Same reason, for a value that carries a second label. No field a
		// wallet writes here contains a colon followed by a space: URIs and
		// timestamps have colons, but never one before a space. A statement
		// is free-form and is not a field, so this does not constrain it.
		if strings.Contains(value, ": ") {
			return SIWSInput{}, fmt.Errorf("field %q carries more than one label", label)
		}
	}

	if in.Nonce == "" {
		return SIWSInput{}, errors.New("message carries no nonce")
	}
	if in.IssuedAt == "" {
		return SIWSInput{}, errors.New("message carries no issue time")
	}
	return in, nil
}

// isSIWSField reports whether a whole line is one of the labelled fields.
//
// It takes the line rather than a bare label because that is what the caller
// has: deciding this wrongly turns "Version: 1" into a statement.
func isSIWSField(line string) bool {
	for _, known := range siwsFieldLabels {
		if strings.HasPrefix(line, known+": ") {
			return true
		}
	}
	return false
}

func isSIWSLabel(label string) bool {
	for _, known := range siwsFieldLabels {
		if label == known {
			return true
		}
	}
	return false
}

// Policy says which accounts may sign in.
//
// It is a type rather than a bare list because "any account" has to be
// something the caller asked for explicitly. An empty list and an open list
// look identical in a [][]byte, and the difference between them is whether
// anyone with a wallet gets in.
type Policy struct {
	// Allowed is the list of accounts, as raw ed25519 public keys.
	Allowed [][]byte

	// Open accepts any account that can sign. It is the dapp model: connecting
	// proves you hold a wallet, not that you are on a list.
	Open bool

	// MaxAge is how old a sign-in may be. It is what bounds replay, because a
	// wallet does not necessarily carry the expiry the challenge asked for:
	// one observed in the wild rendered the message with no expiry line at
	// all, so a message that carries none would otherwise never expire.
	MaxAge time.Duration
}

// DefaultMaxAge is how old a sign-in is allowed to be.
const DefaultMaxAge = 5 * time.Minute

func (p Policy) maxAge() time.Duration {
	if p.MaxAge > 0 {
		return p.MaxAge
	}
	return DefaultMaxAge
}

// VerifySIWS checks a wallet's answer to a sign-in request.
//
// The account the message names is checked against the policy, the domain
// against the one this connection actually arrived at, the expiry against the
// clock, and the signature against the account - in that order, so the most
// useful refusal is the first one reached.
//
// The parsed message comes back even when the check fails, because the account
// is readable from it and a refusal that cannot say which account was refused is
// a refusal nobody can act on.
func VerifySIWS(message, signature []byte, expectedDomain string,
	policy Policy, now time.Time) (SIWSInput, ed25519.PublicKey, error) {

	if len(signature) != ed25519.SignatureSize {
		return SIWSInput{}, nil,
			fmt.Errorf("signature is %d bytes, want %d", len(signature), ed25519.SignatureSize)
	}

	parsed, err := ParseSIWS(message)
	if err != nil {
		return SIWSInput{}, nil, err
	}

	// The account, read before anything else so a refusal can name it.
	named, err := Base58Decode(parsed.Address)
	if err != nil {
		return parsed, nil, fmt.Errorf("the account named in the message is unreadable: %w", err)
	}
	if len(named) != ed25519.PublicKeySize {
		return parsed, nil, fmt.Errorf("the message names a %d byte account", len(named))
	}

	if !strings.EqualFold(parsed.Domain, expectedDomain) {
		return parsed, nil, fmt.Errorf("message is for domain %q, not %q", parsed.Domain, expectedDomain)
	}

	if !policy.Open && !containsKey(policy.Allowed, named) {
		return parsed, nil, fmt.Errorf("%w: %s", ErrNotAuthorized, parsed.Address)
	}

	issued, err := time.Parse(time.RFC3339, parsed.IssuedAt)
	if err != nil {
		return parsed, nil, fmt.Errorf("issue time is unreadable: %w", err)
	}
	// Allow a little clock skew, but not a message issued in the future. A
	// message from the future is either a replay or a badly set clock, and
	// neither is a reason to accept it.
	if issued.After(now.Add(skewTolerance)) {
		return parsed, nil, fmt.Errorf("this sign-in claims to have been issued at %s",
			issued.Format(time.RFC3339))
	}

	// And not one that is old. The expiry in the message is the better check
	// where the wallet carried it, but one in the wild did not, so age is
	// bounded here rather than trusted to arrive.
	if age := now.Sub(issued); age > policy.maxAge() {
		return parsed, nil, fmt.Errorf("this sign-in was issued %s ago; the limit is %s",
			age.Round(time.Second), policy.maxAge())
	}

	if parsed.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, parsed.ExpiresAt)
		if err != nil {
			return parsed, nil, fmt.Errorf("expiry is unreadable: %w", err)
		}
		if !expires.After(now) {
			return parsed, nil, fmt.Errorf("this sign-in expired at %s", expires.Format(time.RFC3339))
		}
	}

	// The signature covers the account the message names. Checking it last
	// means everything cheap and specific has already been said.
	if !ed25519.Verify(ed25519.PublicKey(named), message, signature) {
		return parsed, nil, errors.New("the signature does not match the account it names")
	}
	return parsed, ed25519.PublicKey(named), nil
}

// EncodeSIWS packs a wallet's answer into one string, so it can travel in the
// URL of the WebSocket that follows; a browser cannot set headers on one.
func EncodeSIWS(message, signature []byte) string {
	// Two length prefixes, then the parts. Length-prefixed rather than
	// delimited because the message is attacker-supplied.
	out := []byte{byte(len(message) >> 8), byte(len(message))}
	out = append(out, message...)
	out = append(out, signature...)
	return base64.RawURLEncoding.EncodeToString(out)
}

// DecodeSIWS unpacks what EncodeSIWS produced.
func DecodeSIWS(token string) (message, signature []byte, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, nil, fmt.Errorf("not a valid sign-in: %w", err)
	}
	if len(raw) < 2 {
		return nil, nil, errors.New("sign-in is too short")
	}
	n := int(raw[0])<<8 | int(raw[1])
	if len(raw) != 2+n+ed25519.SignatureSize {
		return nil, nil, errors.New("sign-in has the wrong length")
	}
	return raw[2 : 2+n], raw[2+n:], nil
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Decode reads a Solana address.
//
// This is only ever used on text that came out of a signed message, and only to
// compare the result against an allow list of exact 32-byte keys. A mistake
// here therefore fails closed: wrong bytes match nothing. It is still written
// defensively, and pinned by tests against a real address.
// Base58Decode reads a Solana address. It is exported because the agent
// and the sign-in path both speak base58, and one tested decoder is better
// than two.
func Base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty")
	}

	n := new(big.Int)
	radix, mod := big.NewInt(58), new(big.Int)
	for _, r := range s {
		i := strings.IndexRune(base58Alphabet, r)
		if i < 0 {
			return nil, fmt.Errorf("character %q is not in the base58 alphabet", r)
		}
		n.Mul(n, radix)
		n.Add(n, mod.SetInt64(int64(i)))
	}

	// A leading '1' means a leading zero byte, and big.Int drops those. The
	// System Program's address is all of them, so this is not an edge case:
	// refusing it would refuse every transfer.
	leading := 0
	for leading < len(s) && s[leading] == base58Alphabet[0] {
		leading++
	}
	raw := n.Bytes()
	if leading+len(raw) > 1024 {
		return nil, errors.New("address is out of range")
	}
	return append(make([]byte, leading), raw...), nil
}

// Base58Encode writes bytes the way a wallet names an account: the same bytes in
// an alphabet with no 0, O, I or l, so a mistyped address cannot be read as a
// different one. It is the inverse of base58Decode.
func Base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	radix, mod := big.NewInt(58), new(big.Int)

	out := make([]byte, 0, len(b)*138/100+1)
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, base58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
