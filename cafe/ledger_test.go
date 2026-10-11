package cafe

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLedger(t *testing.T) *Ledger {
	t.Helper()
	l, err := OpenLedger("")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	return l
}

func TestCreditAndDebit(t *testing.T) {
	l := testLedger(t)

	if err := l.Credit("acct", 5*PerMicroUSD); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	if got := l.Account("acct").Balance; got != 5*PerMicroUSD {
		t.Fatalf("balance after credit = %d, want %d", got, 5*PerMicroUSD)
	}
	if err := l.Debit("acct", 2*PerMicroUSD); err != nil {
		t.Fatalf("Debit: %v", err)
	}
	acct := l.Account("acct")
	if acct.Balance != 3*PerMicroUSD {
		t.Errorf("balance = %d, want %d", acct.Balance, 3*PerMicroUSD)
	}
	if acct.Deposits != 5*PerMicroUSD {
		t.Errorf("deposits = %d, want %d", acct.Deposits, 5*PerMicroUSD)
	}
	if acct.Spent != 2*PerMicroUSD {
		t.Errorf("spent = %d, want %d", acct.Spent, 2*PerMicroUSD)
	}
}

// A debit that would go negative has to refuse. A router that will happily go
// negative is a router that lends money to anyone who can hold a connection
// open, so this is the property the whole reservation scheme in proxy.go rests
// on.
func TestDebitRefusesRatherThanGoingNegative(t *testing.T) {
	l := testLedger(t)
	if err := l.Credit("acct", 1000); err != nil {
		t.Fatalf("Credit: %v", err)
	}

	err := l.Debit("acct", 1001)
	if !errors.Is(err, ErrInsufficient) {
		t.Fatalf("Debit past the balance = %v, want ErrInsufficient", err)
	}
	// The message has to carry the two numbers, or a caller cannot act on it.
	for _, want := range []string{"$0.001001", "$0.001"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not mention %s", err, want)
		}
	}
	if got := l.Account("acct").Balance; got != 1000 {
		t.Fatalf("a refused debit changed the balance to %d", got)
	}
}

func TestDebitOfNothingAndCreditOfNothing(t *testing.T) {
	l := testLedger(t)
	if err := l.Debit("acct", 0); err != nil {
		t.Errorf("a debit of zero should be allowed, got %v", err)
	}
	if err := l.Credit("acct", 0); err == nil {
		t.Error("a credit of zero should be refused: it would create an account that took money")
	}
	if err := l.Credit("acct", -1); err == nil {
		t.Error("a negative credit should be refused")
	}
}

// API keys are stored as digests. The only test that matters is the one that
// proves the plaintext is not in the file.
func TestMintResolveRevoke(t *testing.T) {
	l := testLedger(t)

	key, err := l.MintKey("acct", "")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	if !strings.HasPrefix(key, APIKeyPrefix) {
		t.Errorf("key %q does not start with %q", key, APIKeyPrefix)
	}
	if len(key) < 24 {
		t.Errorf("key %q is shorter than the entropy it claims", key)
	}

	addr, err := l.Resolve(key)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if addr != "acct" {
		t.Errorf("Resolve gave account %q, want acct", addr)
	}

	if _, err := l.Resolve("rc_not-a-real-key"); err == nil {
		t.Error("an unknown key resolved; that is the whole thing the check is for")
	}

	acct := l.Account("acct")
	if len(acct.Keys) != 1 {
		t.Fatalf("account has %d keys, want 1", len(acct.Keys))
	}
	if acct.Keys[0].Digest == key {
		t.Error("the key was stored in the clear")
	}
	if acct.Keys[0].Digest != Digest(key) {
		t.Errorf("stored digest is not the digest of the key")
	}

	ok, err := l.RevokeKey("acct", acct.Keys[0].Digest)
	if err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if !ok {
		t.Error("RevokeKey reported the key was not there")
	}
	if _, err := l.Resolve(key); err == nil {
		t.Error("a revoked key still resolves")
	}
}

// Minted keys are distinct, and the cap does not make them not: it is a cap on
// how many an account holds, not on how many can be minted. So this revokes
// between mints rather than minting past the cap and failing.
func TestKeysAreDistinct(t *testing.T) {
	l := testLedger(t)
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		key, err := l.MintKey("acct", "")
		if err == nil && seen[key] {
			t.Fatalf("minted the same key twice: %s", key)
		}
		for _, held := range l.Account("acct").Keys {
			if _, err := l.RevokeKey("acct", held.Digest); err != nil {
				t.Fatalf("RevokeKey: %v", err)
			}
		}
		seen[key] = true
	}
}

func TestLedgerPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")

	l, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if err := l.Credit("alice", 3*PerMicroUSD); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	key, err := l.MintKey("alice", "laptop")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	if err := l.Debit("alice", PerMicroUSD); err != nil {
		t.Fatalf("Debit: %v", err)
	}

	// The file is the one thing an operator backs up, and it holds balances.
	// 0600 because it is the one file here that must not be world readable.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("ledger mode is %o, want 600", perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), key) {
		t.Error("the ledger file contains the API key in the clear")
	}

	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	acct := reopened.Account("alice")
	if acct.Balance != 2*PerMicroUSD {
		t.Errorf("reopened balance = %d, want %d", acct.Balance, 2*PerMicroUSD)
	}
	if acct.Spent != PerMicroUSD {
		t.Errorf("reopened spent = %d, want %d", acct.Spent, PerMicroUSD)
	}
	if len(acct.Keys) != 1 || acct.Keys[0].Label != "laptop" {
		t.Errorf("reopened keys = %+v, want one labelled laptop", acct.Keys)
	}
	addr, err := reopened.Resolve(key)
	if err != nil || addr != "alice" {
		t.Errorf("a key minted before the restart no longer resolves: %v %q", err, addr)
	}
}

func TestOpenLedgerMissingFileIsNotAnError(t *testing.T) {
	l, err := OpenLedger(filepath.Join(t.TempDir(), "not-there.json"))
	if err != nil {
		t.Fatalf("a first run should start an empty ledger, got %v", err)
	}
	if got := len(l.Accounts()); got != 0 {
		t.Errorf("a fresh ledger has %d accounts, want 0", got)
	}
}

// A ledger that exists and cannot be parsed must stop the server. Carrying on
// would start an empty one over the top of a real one, and every balance in it
// would be silently back to zero.
func TestOpenLedgerRefusesAnUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := OpenLedger(path); err == nil {
		t.Fatal("an unreadable ledger was accepted; every balance would go back to zero")
	}
}

// Account returns a copy, so a caller cannot reach in and move money without
// going through Debit.
func TestAccountReturnsACopy(t *testing.T) {
	l := testLedger(t)
	if err := l.Credit("acct", PerMicroUSD); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	got := l.Account("acct")
	got.Balance = 999 * PerMicroUSD
	if again := l.Account("acct"); again.Balance != PerMicroUSD {
		t.Fatalf("mutating the returned account changed the ledger: %d", again.Balance)
	}
}

func TestFormatUSD(t *testing.T) {
	cases := []struct {
		in   MicroUSD
		want string
	}{
		{0, "$0.00"},
		{1, "$0.000001"},
		{PerMicroUSD, "$1.00"},
		{PerMicroUSD + 1, "$1.000001"},
		{1_500_000, "$1.50"},
		{1_500_001, "$1.500001"},
		{-2_500_000, "-$2.50"},
		{12_345_600, "$12.3456"},
	}
	for _, c := range cases {
		if got := FormatUSD(c.in); got != c.want {
			t.Errorf("FormatUSD(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateAddress(t *testing.T) {
	const valid = "11111111111111111111111111111111"
	if err := ValidateAddress(valid); err != nil {
		t.Errorf("ValidateAddress(%q) = %v, want nil", valid, err)
	}
	for _, bad := range []string{"", "not-an-address", "1111111111111111111111111111"} {
		if err := ValidateAddress(bad); err == nil {
			t.Errorf("ValidateAddress(%q) = nil, want an error", bad)
		}
	}
}

func TestAccountsNewestFirst(t *testing.T) {
	l := errLedger(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := 0
	l.now = func() time.Time { n++; return base.Add(time.Duration(n) * time.Minute) }

	l.Account("first")
	l.Account("second")
	l.Account("third")

	got := l.Accounts()
	if len(got) != 3 {
		t.Fatalf("got %d accounts, want 3", len(got))
	}
	if got[0].Address != "third" || got[2].Address != "first" {
		t.Errorf("accounts are in the wrong order: %s ... %s", got[0].Address, got[2].Address)
	}
}

func errLedger(t *testing.T) *Ledger {
	t.Helper()
	l := testLedger(t)
	l.now = time.Now
	return l
}
