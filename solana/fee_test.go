package solana

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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
		t.Fatalf("FeeSigner: %v", err)
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
		t.Fatalf("FeeSigner: %v", err)
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

// The same transaction the Deno reader is pinned to in
// scripts/sol-tx/fee_test.ts: bytes this package's own builder produced. It
// is here so the two readers cannot drift apart, and it is real rather than
// written out because a fixture authored next to the reader agrees with it by
// construction - which is how a one-byte v0 header passed as a three-byte one
// in the first place.
func TestFeePayerOnATransactionBothReadersShare(t *testing.T) {
	signed, err := hex.DecodeString("01923ce4dc70fae15fb746adbf6ab5998dd8257e94e932aad17b3314e489882bb4fe9294c5a0505a993b5d10cfe8a12fd2063fd1c315107b283f24b1bcf1cdb00580010001021c497d4515909b72923389c97f7424e9631cf38b7f1a4c9969aea635058d077f054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d94ade940a9e7622557a136e1d923a513bb7dd43254d6b91fba3f50a26b04176201010006046558672d2f00")
	if err != nil {
		t.Fatalf("the fixture is not hex: %v", err)
	}
	got, err := FeePayer(signed)
	if err != nil {
		t.Fatalf("FeePayer: %v", err)
	}
	if want := "2uRQmq8fQXKLmm8fSdUqkHr8UbwpyEA687Jgut16DJrJ"; got != want {
		t.Errorf("fee payer is %q, want %q", got, want)
	}
}
