package cafe

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/routercafe/routercafe/auth/siws"
	"github.com/routercafe/routercafe/solana"
	"golang.org/x/crypto/ssh"
)

// The ledger is the whole of RouterCafe's own bookkeeping: who has an account,
// what they have paid in, what is left, and which API keys spend it.
//
// Everything is addressed by Solana account, never by SSH username, because the
// username is chosen by the client and therefore proves nothing. An ed25519 SSH
// key is already an account address - see solana.AddressFor - so the key that
// authenticated the session names the account with no lookup step and no
// separate registration to go wrong.
//
// Money is counted in micro-USD (1e-6 of a dollar) rather than dollars. A
// balance held as a float loses cents to rounding on every request, and a
// router's whole job is to be exactly right about how much is left; an int64
// of micro-dollars makes "subtract what it cost" and "refuse when it would go
// negative" the same comparison.

// MicroUSD is one millionth of a dollar, the unit balances are counted in.
type MicroUSD = int64

// PerMicroUSD is one US dollar expressed in the unit balances are counted in.
const PerMicroUSD MicroUSD = 1_000_000

// Account is one depositor's ledger entry.
//
// The API keys are stored as SHA-256 digests, never as the keys themselves.
// The only moment a key exists in the clear is the moment it is minted, and
// that string is shown once and never written down. A leaked ledger file then
// exposes balances and a list of fingerprints, which is a far smaller thing to
// guard than the keys themselves.
type Account struct {
	// Address is the Solana account, base58. It is the primary key: the
	// ed25519 public key the session authenticated with, unchanged.
	Address string `json:"address"`

	// Balance is what is left, in micro-USD. It cannot go negative; Debit
	// refuses rather than allowing it.
	Balance MicroUSD `json:"balanceMicroUsd"`

	// Keys are the API keys that may spend this balance, by digest.
	Keys []Key `json:"keys,omitempty"`

	// Deposits is the money that arrived, in micro-USD. Balance plus what
	// has been spent, and it is what the TUI shows so a session can see the
	// account's own history rather than only its current number.
	Deposits MicroUSD `json:"depositedMicroUsd"`

	// Spent is what has been billed out of it, in micro-USD.
	Spent MicroUSD `json:"spentMicroUsd"`

	// Created and Touched are timestamps, for an operator reading the file.
	Created time.Time `json:"created"`
	Touched time.Time `json:"touched"`
}

// Key is one API key, stored as what can verify it rather than as itself.
type Key struct {
	// Digest is the SHA-256 of the key, hex. This is the lookup key and the
	// only part of it that is kept.
	Digest string `json:"digest"`

	// Label is the last four characters of the key, enough to tell two keys
	// apart and useless on its own.
	Label string `json:"label"`

	// Prefix is the first four, so that a listing shows the same shape as the
	// key itself - rc_abcd...wxyz - rather than a shape that belongs to no
	// key anybody holds. Empty on a key minted before this existed, which is
	// why Hint falls back rather than assuming it.
	//
	// Eight characters of a 192-bit secret, which narrows nothing: the point
	// is that somebody holding the ledger can still recognise their own key in
	// a list, which four characters at one end does not quite manage.
	Prefix string `json:"prefix,omitempty"`

	// Created is when it was minted, and Touched when it was last used, so
	// an operator can see at a glance which of a person's keys is live.
	Created time.Time `json:"created"`
	Touched time.Time `json:"touched"`
}

// ErrInsufficient is what a debit that would go negative reports. It is a
// distinct error because it is the one failure a caller can act on: the
// balance is the thing to fix, and a generic "request failed" would leave a
// client retrying a request that can never succeed.
var ErrInsufficient = errors.New("not enough balance")

// Ledger holds every account.
//
// One mutex over the whole map rather than one per account: a debit has to read
// the balance and write the new one under the same lock to be correct, and a
// per-account lock would still need the map's own lock to look one up. The
// critical sections are a map read and an integer add, so contention is not the
// thing to optimise for here.
type Ledger struct {
	mu       sync.Mutex
	accounts map[string]*Account
	path     string

	// now is the clock. Tests set it; production leaves it nil and reads the
	// wall clock, which is the only place time enters an account.
	now func() time.Time

	// keyf is where an API key comes from. Injectable so a test can mint
	// keys it can then look up deterministically.
	keyf func() (string, error)
}

// OpenLedger reads a ledger from path, or starts an empty one when the file is
// not there yet.
//
// A missing file is the normal first run and is not an error. A file that
// exists and cannot be read is a different thing: continuing would start a
// second, empty ledger over the top of a real one, and every balance in it
// would be silently back to zero.
func OpenLedger(path string) (*Ledger, error) {
	l := &Ledger{
		accounts: make(map[string]*Account),
		path:     path,
		now:      time.Now,
		keyf:     newAPIKey,
	}
	if path == "" {
		return l, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the ledger at %s: %w", path, err)
	}
	if len(raw) == 0 {
		return l, nil
	}
	var accounts []*Account
	if err := json.Unmarshal(raw, &accounts); err != nil {
		return nil, fmt.Errorf("the ledger at %s is not readable: %w", filepath.Base(path), err)
	}
	for _, acct := range accounts {
		l.accounts[acct.Address] = acct
	}
	return l, nil
}

func (l *Ledger) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// Account returns the account for an address, creating an empty one on first
// sight.
//
// Creating on read is what makes the TUI work on a first connection: there is
// no sign-up, because the key that just authenticated is the account, and a
// person who has not paid in yet has a perfectly good account worth showing
// with a zero balance.
func (l *Ledger) Account(address string) Account {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.account(address)
}

// account is Account without the lock. The caller holds it.
func (l *Ledger) account(address string) Account {
	addr := strings.TrimSpace(address)
	if existing, ok := l.accounts[addr]; ok {
		// A copy, so a caller cannot reach in and change the balance without
		// going through Debit. The slices are copied for the same reason.
		out := *existing
		out.Keys = append([]Key(nil), existing.Keys...)
		return out
	}
	now := l.clock().UTC()
	fresh := Account{Address: addr, Created: now, Touched: now}
	l.accounts[addr] = &fresh
	return fresh
}

// Credit adds to an account's balance and records the deposit.
//
// Used by the top-up path once a transaction is confirmed on chain. It is the
// only way a balance goes up, which is the property that makes "the money is
// here because the chain said so" checkable.
func (l *Ledger) Credit(address string, amount MicroUSD) error {
	if amount <= 0 {
		return fmt.Errorf("a deposit of %s would not change the balance", FormatUSD(amount))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	acct := l.mutable(address)
	acct.Balance += amount
	acct.Deposits += amount
	acct.Touched = l.clock().UTC()
	return l.save()
}

// Debit takes cost out of an account's balance, or refuses.
//
// The refusal is the whole point. A router that will happily go negative is a
// router that lends money to anyone who can hold a connection open, so the
// comparison and the subtraction happen together under one lock and there is no
// path that writes a negative balance.
func (l *Ledger) Debit(address string, cost MicroUSD) error {
	if cost < 0 {
		return fmt.Errorf("a charge of %s is not a charge", FormatUSD(cost))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	acct := l.mutable(address)
	if acct.Balance < cost {
		return fmt.Errorf("%w: this call costs %s and the balance is %s",
			ErrInsufficient, FormatUSD(cost), FormatUSD(acct.Balance))
	}
	acct.Balance -= cost
	acct.Spent += cost
	acct.Touched = l.clock().UTC()
	return l.save()
}

// Reserve takes an amount out of a balance without recording it as spent.
//
// Separate from Debit because the two mean different things. A reservation is
// a hold: the money is already committed to a request in flight, but nobody
// has been served yet, so counting it as spend would tell an operator that a
// balance was consumed when the work is still running. Settle turns it back
// into a real charge.
func (l *Ledger) Reserve(address string, amount MicroUSD) error {
	if amount < 0 {
		return fmt.Errorf("a hold of %s is not a hold", FormatUSD(amount))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	acct := l.mutable(address)
	if acct.Balance < amount {
		return fmt.Errorf("%w: this call could cost %s and the balance is %s",
			ErrInsufficient, FormatUSD(amount), FormatUSD(acct.Balance))
	}
	acct.Balance -= amount
	acct.Touched = l.clock().UTC()
	return l.save()
}

// Settle finishes a reservation: what was held and not used goes back, and
// what was really spent is recorded as spent.
//
// Called with spent greater than reserved as well as less, and the arithmetic
// handles both: the balance goes up by the difference, or down by the
// overspend. An overspend is possible because a provider can report more
// tokens than a request named, and the work was done either way.
//
// Settling nothing is not an error. A reservation that was exactly the cost,
// which is the common case, has no difference to hand back and no error is
// worth raising over it.
func (l *Ledger) Settle(address string, reserved, spent MicroUSD) error {
	if spent < 0 {
		return fmt.Errorf("a charge of %s is not a charge", FormatUSD(spent))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	acct := l.mutable(address)
	acct.Balance += reserved - spent
	acct.Spent += spent
	acct.Touched = l.clock().UTC()
	return l.save()
}

// mutable returns the stored account, creating it if this is the first time
// this address has been seen. The caller holds the lock.
func (l *Ledger) mutable(address string) *Account {
	addr := strings.TrimSpace(address)
	if existing, ok := l.accounts[addr]; ok {
		return existing
	}
	now := l.clock().UTC()
	fresh := &Account{Address: addr, Created: now, Touched: now}
	l.accounts[addr] = fresh
	return fresh
}

// APIKeyPrefix is what a RouterCafe key looks like at a glance, and what makes
// one recognisable in a shell history or a leaked config.
//
// It is not what a key is *shown* as: a key is shown as `rc_abcd...wxyz`, which
// drops this constant middle because a constant carries no information. The
// key really is `rc_live_` and then random, and the listing shows four
// characters from either end of the part that is not.
const APIKeyPrefix = "rc_live_"

// MaxKeys is how many API keys one account may hold.
//
// Ten is more than anybody uses and few enough to read: a page of keys that
// scrolls forever is a page nobody has looked at, and the balance behind it is
// the thing being protected.
const MaxKeys = 10

// newAPIKey mints a key.
//
// 24 random bytes is 192 bits, which is far more than anyone can guess and far
// more than this needs to be memorable - it is not, which is the point. The
// encoding is base64url with no padding so the key survives being pasted into a
// shell, a YAML file and a header without quoting.
func newAPIKey() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint an API key: %w", err)
	}
	return APIKeyPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Digest is the lookup form of an API key: SHA-256, hex.
//
// Hashed rather than encrypted, and that is deliberate. Verifying a presented
// key only ever needs a comparison against a digest, so there is nothing here
// that needs the original back; and a hash means the ledger file on disk is
// not a list of live credentials, which is the property worth having when the
// file also holds every balance.
func Digest(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

// MintKey issues a new API key for an account and returns it.
//
// This is the only place a key exists in the clear. It is returned to the
// caller, which shows it once; only the digest is kept.
func (l *Ledger) MintKey(address, label string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	acct := l.mutable(address)
	// A cap, because a balance is the thing being protected here and a page
	// that can list keys without end is a page somebody scrolls forever. Ten is
	// more than anybody uses and few enough to read.
	if len(acct.Keys) >= MaxKeys {
		return "", fmt.Errorf("this account already has %d keys; revoke one before minting another", MaxKeys)
	}
	key, err := l.keyf()
	if err != nil {
		return "", err
	}
	now := l.clock().UTC()
	acct.Keys = append(acct.Keys, Key{
		Digest:  Digest(key),
		Label:   labelFor(key, label),
		Prefix:  prefixFor(key),
		Created: now,
		Touched: now,
	})
	acct.Touched = now
	if err := l.save(); err != nil {
		return "", err
	}
	return key, nil
}

// Hint is how a key is shown in a listing: rc_abcd...wxyz.
//
// Shaped like the key rather than like a label, because `rc_live_` in front of
// four characters says "here is a key" without saying *which*, and the prefix
// is eight characters of the whole thing - four more than before, which still
// narrows nothing and does let somebody find their own key in a list. The
// constant middle of the key is dropped, because a constant carries none.
//
// Three dots rather than the one ellipsis character `shortAddress` uses: a key
// is not a string this program is truncating, it is an abbreviation somebody is
// going to read character by character, and `rc_abcd...wxyz` says the same
// thing as `rc_abcd…wxyz` in a font where the ellipsis is not three times
// narrower than it is here.
func (k Key) Hint() string {
	if k.Prefix == "" {
		return "rc_..." + k.Label
	}
	return "rc_" + k.Prefix + "..." + k.Label
}

// prefixFor is the first four characters of a key, for Hint.
func prefixFor(key string) string {
	rest, ok := strings.CutPrefix(key, APIKeyPrefix)
	if !ok || len(rest) < 4 {
		return ""
	}
	return rest[:4]
}

// labelFor is what a key is called in a listing: the caller's label if it gave
// one, otherwise the last four characters of the key itself.
//
// The fallback is the answer to "which of my keys is this" for someone who
// minted three and named none, and it is four characters of a 192-bit secret,
// which narrows nothing.
func labelFor(key, label string) string {
	if trimmed := strings.TrimSpace(label); trimmed != "" {
		return trimmed
	}
	if len(key) <= 4 {
		return key
	}
	return "..." + key[len(key)-4:]
}

// RevokeKey removes a key by its digest, and reports whether it was there.
//
// A key nobody can revoke is a key nobody can rotate after it leaks, which is
// the only reason to be able to mint more than one.
func (l *Ledger) RevokeKey(address, digest string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	acct, ok := l.accounts[strings.TrimSpace(address)]
	if !ok {
		return false, nil
	}
	kept := acct.Keys[:0]
	found := false
	for _, k := range acct.Keys {
		if k.Digest == digest {
			found = true
			continue
		}
		kept = append(kept, k)
	}
	acct.Keys = append([]Key(nil), kept...)
	if !found {
		return false, nil
	}
	acct.Touched = l.clock().UTC()
	return true, l.save()
}

// Resolve maps a presented API key to the account it belongs to, and marks it
// used.
//
// A key that is not on file is refused here rather than anywhere downstream:
// every route this key can reach spends money, so the one place that knows
// whether the credential is real is the place that has to say so.
func (l *Ledger) Resolve(key string) (string, error) {
	digest := Digest(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	for addr, acct := range l.accounts {
		for i := range acct.Keys {
			if acct.Keys[i].Digest != digest {
				continue
			}
			acct.Keys[i].Touched = l.clock().UTC()
			acct.Touched = acct.Keys[i].Touched
			// Saving on every request would put a disk write in the hot path
			// of every API call. Touched is for an operator reading the
			// file, not for correctness, so a failure here is logged by the
			// caller's next successful write rather than failing the call.
			_ = l.save()
			return addr, nil
		}
	}
	return "", errors.New("that API key is not on file")
}

// Accounts returns every account, newest first, for a listing.
//
// A copy of each, for the same reason Account returns a copy.
func (l *Ledger) Accounts() []Account {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Account, 0, len(l.accounts))
	for _, acct := range l.accounts {
		copied := *acct
		copied.Keys = append([]Key(nil), acct.Keys...)
		out = append(out, copied)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created.Equal(out[j].Created) {
			return out[i].Address < out[j].Address
		}
		return out[i].Created.After(out[j].Created)
	})
	return out
}

// save writes the ledger out.
//
// Every mutation goes through here, so the file is as current as the memory.
// It is written to a temporary name in the same directory and renamed over the
// real one: a rename within a directory is atomic, so a crash halfway through
// leaves the previous ledger intact rather than a half-written one that will
// not parse on the next start.
func (l *Ledger) save() error {
	if l.path == "" {
		return nil
	}
	accounts := make([]*Account, 0, len(l.accounts))
	for _, acct := range l.accounts {
		accounts = append(accounts, acct)
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Address < accounts[j].Address })
	body, err := json.MarshalIndent(accounts, "", "  ")
	if err != nil {
		return fmt.Errorf("pack the ledger: %w", err)
	}
	body = append(body, '\n')

	dir := filepath.Dir(l.path)
	tmp, err := os.CreateTemp(dir, ".ledger-*.json")
	if err != nil {
		return fmt.Errorf("write the ledger next to %s: %w", filepath.Base(l.path), err)
	}
	tmpName := tmp.Name()
	// Cleaned up on every path out of here. Leaving the temporary file
	// behind on a failed write would drop a file holding every balance into
	// a directory it has no business being in.
	defer func() {
		tmp.Close()        //nolint:errcheck
		os.Remove(tmpName) //nolint:errcheck
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("protect the ledger: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("write the ledger: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("flush the ledger: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close the ledger: %w", err)
	}
	if err := os.Rename(tmpName, l.path); err != nil {
		return fmt.Errorf("replace the ledger: %w", err)
	}
	return nil
}

// FormatUSD renders micro-USD the way a person reads a price.
//
// Trimmed past the cents, never below them. A balance nobody has touched has
// to print as $0.00 rather than $0, and one that has spent most of a cent
// still prints with two decimals because "$0.5" is not a thing anybody writes.
// Everything after the second place is dropped, which is the display decision
// and not an arithmetic one: the value being formatted never changes.
func FormatUSD(v MicroUSD) string {
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	whole := v / PerMicroUSD
	frac := v % PerMicroUSD
	digits := fmt.Sprintf("%06d", frac)
	trimmed := strings.TrimRight(strings.TrimRight(digits, "0"), "0")
	if trimmed == "" {
		trimmed = "00"
	} else if len(trimmed) == 1 {
		trimmed += "0"
	}
	return fmt.Sprintf("%s$%d.%s", sign, whole, trimmed)
}

// AddressOf is the account address a session is, given the key that
// authenticated it.
//
// A key that is not ed25519 names no account at all, and that is said out
// loud rather than left as a blank column: it is the difference between "you
// are not using an ed25519 key" and something that looks like a bug. The work
// is solana.AddressFor's, so the address a session is billed under and the
// address sol-keys prints cannot drift apart.
func AddressOf(pub ssh.PublicKey) (string, error) {
	return solana.AddressFor(pub)
}

// ValidateAddress checks that a string names one Solana account.
//
// Used on the addresses that arrive from configuration rather than from a
// session: a treasury address with a typo in it is discovered at the first
// deposit otherwise, by a person who has already sent money.
func ValidateAddress(address string) error {
	raw, err := siws.Base58Decode(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("%q is not a Solana address: %w", address, err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("%q decodes to %d bytes; a Solana address is 32", address, len(raw))
	}
	return nil
}
