package solana

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// The fee payer has to be read out of a transaction that is genuinely
// versioned, because that is what a wallet produces. Building one here by
// hand is the only way to be sure the walk is over the right layout rather
// than the one that happened to be in front of us.
func TestFeePayerReadsAVersionedTransaction(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)

	message := versionedMessage(pub)
	signed := signFor(message, priv)

	got, err := FeePayer(signed)
	if err != nil {
		t.Fatalf("FeePayer: %v", err)
	}
	if want := base58Of(t, pub); got != want {
		t.Errorf("FeePayer = %q, want the first account key %q", got, want)
	}
}

// A legacy transaction has three length-prefixed counts where a versioned
// one has a version byte and one. Reading the wrong one finds a plausible
// looking key that is not the payer, which is why this is tested separately
// rather than assumed to follow from the versioned case.
func TestFeePayerReadsALegacyTransaction(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)

	message := legacyMessage(pub)
	signed := signFor(message, priv)

	got, err := FeePayer(signed)
	if err != nil {
		t.Fatalf("FeePayer: %v", err)
	}
	if got != base58Of(t, pub) {
		t.Errorf("FeePayer = %q, want %q", got, base58Of(t, pub))
	}
}

func TestFeePayerRefusesWhatItCannotRead(t *testing.T) {
	for name, body := range map[string][]byte{
		"nothing":                nil,
		"a signature count only": {1},
		"claiming more signatures than it carries": {0x05, 1, 2, 3, 4, 5},
		"signatures but no message":                append(compact(1), make([]byte, 64)...),
	} {
		if _, err := FeePayer(body); err == nil {
			t.Errorf("%s should have been refused", name)
		}
	}
}
