package siws

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The address and key below are a real pair taken from a wallet: the key is
// what ssh-add -L printed inside a wssh session, and the address is the same 32
// bytes in base58. Pinning both means a change to the decoder cannot pass
// unnoticed.
const (
	knownKeyHex = "44a6815795e5c35909318e36848c95a470d31ee022aa4db8dd627971c3dc271a"
	knownAddr   = "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"
)

func TestBase58DecodesARealAddress(t *testing.T) {
	got, err := base58Decode(knownAddr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != ed25519.PublicKeySize {
		t.Fatalf("decoded %d bytes, want %d", len(got), ed25519.PublicKeySize)
	}
	if hex.EncodeToString(got) != knownKeyHex {
		t.Fatalf("decoded to %x, want %s", got, knownKeyHex)
	}
}

func TestBase58RejectsWhatItCannotRead(t *testing.T) {
	// 0, O, I and l are deliberately not in the alphabet: a mistyped address
	// has to be refused, not quietly resolved to some other account.
	for _, bad := range []string{"", "0OIl", "abc0def", "not-an-address"} {
		if _, err := base58Decode(bad); err == nil {
			t.Errorf("base58Decode(%q) should have failed", bad)
		}
	}
}

// The whole point of formatting is matching what the wallet produced, so this
// is the message Phantom returned byte for byte, not a fixture written by the
// same code that reads it back.
//
// Two things about it were only knowable by looking: there is no URI line when
// no URI is asked for, and the message does not end with a newline. Getting
// either wrong produces a signature that will not verify, which shows up as a
// sign-in that never works rather than as anything less obvious.
func TestFormatMatchesAWalletsMessage(t *testing.T) {
	in := SIWSInput{
		Domain:    "inputleaf.anasvhora.tech",
		Address:   knownAddr,
		Statement: "Test Solana Sign In (SIWS) from DevTools.",
		Nonce:     "d8c3428714334f1f9596ee17423cdd3c",
		IssuedAt:  "2026-10-10T06:16:42.525Z",
		Version:   "1",
		ChainID:   "solana:mainnet",
	}
	got := in.Format()

	const want = "inputleaf.anasvhora.tech wants you to sign in with your Solana account:\n" +
		"5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5\n" +
		"\n" +
		"Test Solana Sign In (SIWS) from DevTools.\n" +
		"\n" +
		"Version: 1\n" +
		"Chain ID: solana:mainnet\n" +
		"Nonce: d8c3428714334f1f9596ee17423cdd3c\n" +
		"Issued At: 2026-10-10T06:16:42.525Z"

	if got != want {
		t.Errorf("formatted message differs from the wallet's:\n got %q\nwant %q", got, want)
	}
	if len(got) != 272 {
		t.Errorf("message is %d bytes; the wallet produced 272", len(got))
	}
}

// A URI the server does ask for has to appear, or a message that names one
// would verify against a different message than the person read.
func TestFormatIncludesAURIWhenThereIsOne(t *testing.T) {
	got := SIWSInput{
		Domain: "wssh.example", Address: knownAddr, Nonce: "abc",
		IssuedAt: "2026-10-10T06:00:00Z", URI: "https://wssh.example/login",
	}.Format()
	if !strings.Contains(got, "\nURI: https://wssh.example/login\n") {
		t.Errorf("URI line missing or misplaced:\n%q", got)
	}
	parsed, err := ParseSIWS([]byte(got))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.URI != "https://wssh.example/login" {
		t.Errorf("URI came back as %q", parsed.URI)
	}
}

func TestFormatAndParseAreInverses(t *testing.T) {
	for name, in := range map[string]SIWSInput{
		"full": {
			Domain: "wssh.example", URI: "https://wssh.example",
			Address: knownAddr, Statement: "Sign in", Nonce: "abc123",
			IssuedAt: "2026-10-10T05:54:40Z", Version: "1", ChainID: "solana:mainnet",
			ExpiresAt: "2026-10-10T06:54:40Z",
		},
		"no statement": {
			Domain: "wssh.example", Address: knownAddr, Nonce: "abc123",
			IssuedAt: "2026-10-10T05:54:40Z",
		},
		"defaults filled in": {
			Domain: "wssh.example", Address: knownAddr, Nonce: "abc123",
			IssuedAt: "2026-10-10T05:54:40Z",
		},
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseSIWS([]byte(in.Format()))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if parsed.Domain != in.Domain || parsed.Address != in.Address ||
				parsed.URI != in.URI || parsed.Statement != in.Statement ||
				parsed.Nonce != in.Nonce || parsed.IssuedAt != in.IssuedAt ||
				parsed.ExpiresAt != in.ExpiresAt {
				t.Fatalf("round trip changed the message:\n got %+v\nwant %+v", parsed, in)
			}
			if parsed.Version == "" {
				t.Error("version should always come back")
			}
			if parsed.ChainID == "" {
				t.Error("chain id should always come back")
			}
		})
	}
}

// A message a person approved has to be the message that gets checked. Anything
// ambiguous is a way to be shown one thing and used for another.
func TestParseRejectsAnythingItCannotReadExactly(t *testing.T) {
	// Built from lines rather than patched as a string, because the message has
	// no trailing newline and surgery on that is easy to get subtly wrong.
	header := "wssh.example wants you to sign in with your Solana account:"
	join := func(lines ...string) string { return strings.Join(lines, "\n") }

	bad := map[string]string{
		"carriage returns":      join(header, knownAddr, "", "Nonce: abc", "Issued At: 2026-10-10T05:00:00Z") + "\r",
		"not a sign-in":         join("hello there", ""),
		"no header":             join(knownAddr, "", "Nonce: abc", "Issued At: 2026-10-10T05:00:00Z"),
		"no account":            join(header, "", "", "Nonce: abc", "Issued At: 2026-10-10T05:00:00Z"),
		"no nonce":              join(header, knownAddr, "", "Issued At: 2026-10-10T05:00:00Z"),
		"no issue time":         join(header, knownAddr, "", "Nonce: abc"),
		"an unknown field":      join(header, knownAddr, "", "Nonce: abc", "Issued At: 2026-10-10T05:00:00Z", "Favourite Colour: blue"),
		"two fields on a line":  join(header, knownAddr, "", "Nonce: abc Favourite Colour: blue", "Issued At: 2026-10-10T05:00:00Z"),
		"a label with no value": join(header, knownAddr, "", "Nonce: abc", "Issued At:", ""),
		"empty":                 "",
	}
	for name, text := range bad {
		if _, err := ParseSIWS([]byte(text)); err == nil {
			t.Errorf("%s should not have parsed", name)
		}
	}
}

// The full path a browser takes: a wallet signs, the server checks the answer,
// and every way that can go wrong is reported as itself.
func TestVerifySIWSAcceptsAGoodAnswer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	address := encodeBase58ForTest(t, pub)

	issued := time.Date(2026, 10, 10, 5, 54, 40, 0, time.UTC)
	in := SIWSInput{
		Domain: "wssh.example", URI: "https://wssh.example", Address: address,
		Statement: "Sign in to wssh", Nonce: "abc123", IssuedAt: issued.Format(time.RFC3339),
	}
	message := []byte(in.Format())
	sig := ed25519.Sign(priv, message)

	parsed, err := VerifySIWS(message, sig, "wssh.example", [][]byte{pub}, issued.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.Address != address {
		t.Errorf("got address %q, want %q", parsed.Address, address)
	}
}

func TestVerifySIWSRejectsEverythingElse(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	strangerPub, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	now := time.Date(2026, 10, 10, 6, 0, 0, 0, time.UTC)
	message := []byte(SIWSInput{
		Domain: "wssh.example", Address: encodeBase58ForTest(t, pub),
		Nonce: "abc123", IssuedAt: now.Format(time.RFC3339),
	}.Format())
	sig := ed25519.Sign(priv, message)

	tests := map[string]struct {
		message []byte
		sig     []byte
		domain  string
		allowed [][]byte
	}{
		"a different domain":                {message, sig, "evil.example", [][]byte{pub}},
		"an account not on the list":        {message, sig, "wssh.example", [][]byte{strangerPub}},
		"a signature from another key":      {message, ed25519.Sign(strangerPriv, message), "wssh.example", [][]byte{pub}},
		"a truncated signature":             {message, sig[:32], "wssh.example", [][]byte{pub}},
		"a message that is not one of ours": {[]byte("please sign in"), sig, "wssh.example", [][]byte{pub}},
	}
	for name, tt := range tests {
		if _, err := VerifySIWS(tt.message, tt.sig, tt.domain, tt.allowed, now); err == nil {
			t.Errorf("%s should not have verified", name)
		}
	}
}

func TestVerifySIWSRefusesAnExpiredMessage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	issued := time.Date(2026, 10, 10, 5, 0, 0, 0, time.UTC)
	expires := issued.Add(time.Minute)

	message := []byte(SIWSInput{
		Domain: "wssh.example", Address: encodeBase58ForTest(t, pub),
		Nonce: "abc123", IssuedAt: issued.Format(time.RFC3339),
		ExpiresAt: expires.Format(time.RFC3339),
	}.Format())

	if _, err := VerifySIWS(message, ed25519.Sign(priv, message),
		"wssh.example", [][]byte{pub}, expires.Add(-time.Second)); err != nil {
		t.Fatalf("should still be valid before expiry: %v", err)
	}
	if _, err := VerifySIWS(message, ed25519.Sign(priv, message),
		"wssh.example", [][]byte{pub}, expires.Add(time.Second)); err == nil {
		t.Fatal("an expired message should not verify")
	}
}

// The token has to survive a trip through a URL and come back unchanged, or a
// signature that verified locally would fail on the wire.
func TestSIWSTokenRoundTrips(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	message := []byte(SIWSInput{
		Domain: "wssh.example", Address: encodeBase58ForTest(t, pub),
		Nonce: "abc123", IssuedAt: "2026-10-10T05:00:00Z",
	}.Format())
	sig := ed25519.Sign(priv, message)

	// The message is arbitrary attacker-influenced text, so it has to survive
	// packing intact including any bytes that look like a length.
	for _, tricky := range []string{"\x00\x01\x02", "a: b\nc: d", "é中文"} {
		payload := append([]byte(tricky), message...)
		gotMsg, gotSig, err := DecodeSIWS(EncodeSIWS(payload, sig))
		if err != nil {
			t.Fatalf("decode %q: %v", tricky, err)
		}
		if string(gotMsg) != string(payload) {
			t.Errorf("message %q came back as %q", payload, gotMsg)
		}
		if !equalBytes(gotSig, sig) {
			t.Errorf("signature changed for %q", tricky)
		}
	}
}

func TestDecodeSIWSRejectsRubbish(t *testing.T) {
	for _, bad := range []string{"", "!!!", base64.RawURLEncoding.EncodeToString([]byte{0, 1, 2})} {
		if _, _, err := DecodeSIWS(bad); err == nil {
			t.Errorf("DecodeSIWS(%q) should have failed", bad)
		}
	}
}

// encodeBase58ForTest produces an address the way a wallet would. Encoding is
// easier to get right than decoding and is not on the verification path, so it
// lives in the tests rather than in the package.
func encodeBase58ForTest(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	n := new(big.Int).SetBytes(pub)
	out := make([]byte, 0, 44)
	radix, mod := big.NewInt(58), new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for _, b := range pub {
		if b != 0 {
			break
		}
		out = append(out, alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
