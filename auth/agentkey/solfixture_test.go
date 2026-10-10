package agentkey

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/btwiuse/wssh/auth/siws"
)

// Real transactions, produced by the Solana library in a browser and signed.
//
// They are here because the seam between what that library builds and what
// this package reads is where the bugs were. A blockhash handed over as an
// object instead of text, instructions under a name that only looks right,
// account keys that are objects rather than strings: each produced a
// transaction that looked fine and failed somewhere further on, always in a
// browser, where the only symptom was a signature that never arrived.
//
// A fixture pins that seam. If the library changes what it serialises, or if
// this package starts reading it wrongly again, it fails here instead.
//
// The wallet fixture's key is known, so its signature is checked rather than
// merely counted. The session fixture's signer is not known here - and does
// not need to be, because what is worth pinning is that a key which is not a
// wallet's looks exactly the same on the wire.
const (
	// Signed by a wallet, whose key this is.
	fixtureWalletKey = "44a6815795e5c35909318e36848c95a470d31ee022aa4db8dd627971c3dc271a"

	fixtureWalletTx = "9tb3eCpe8TTJ6HTRoSbgPWL9pqDDw28gg6vUbhxx4GjAcahK8Wv9vRkxTaRAcB77p8HutwfRhazYH7r" +
		"Qx5kHfPDRKWf2qn8xMvb21NhXqAqGWsecaAvPBsjcsbe3CsrgJyVa2C4C863mFEqSHYZ7GQSBgY55q" +
		"oqQwLerKvWemaQFHPPZZuXmuLmQgxEUm12PmBVMeXpQcFqxPjKSMzSFct5zPF2n5Px3Dw7sNmPwc3Q5r" +
		"Ag7j1VGUCoEYCGeFtyvDAU8R2Npyt4w1GVqz3pBg8NNg85GZ9YcQXsGw7p3HK4JNEpzrpRtcShyfMzP"

	// Signed by a session key rather than a wallet.
	fixtureSessionTx = "9AaSZXZ7QHpLoaHdy4V7rmwj2nAAF8j863zsQJ12n2Zdp37oivwwmtdy2Hj8trz8e5BKrGCwXUct" +
		"fZskokwbzh8Gp16YVg8gMxj2jUvGFZ4DiBHTYos3rpuNFrcooS1EFCimw9wbvqGcAjA6TvS8wcYdxXm" +
		"o4TimxU1VteeMmkxeYvJwT6HFxejAUP1PT7ddGL4qRsfp2XiF3dDCn1ARVox7Au2AjmHPawEzDbfWLRy" +
		"2bSZoxsgzT"
)

// splitFixture reads a real transaction apart the way the extension handler does.
func splitFixture(t *testing.T, encoded string) SolanaTxResponse {
	t.Helper()

	raw, err := siws.Base58Decode(encoded)
	if err != nil {
		t.Fatalf("fixture is not base58: %v", err)
	}
	if siws.Base58Encode(raw) != encoded {
		t.Fatal("fixture does not survive a base58 round trip")
	}

	signatures, message, err := splitSolanaTransaction(raw)
	if err != nil {
		t.Fatalf("fixture does not split: %v", err)
	}
	if len(signatures) != 1 {
		t.Fatalf("fixture carries %d signatures, want 1", len(signatures))
	}
	return SolanaTxResponse{
		Signature:         signatures[0],
		SignedTransaction: raw,
		message:           message,
	}
}

// A transaction the library really produced, signed really, verifies here.
func TestRealWalletTransactionVerifies(t *testing.T) {
	pub, err := hex.DecodeString(fixtureWalletKey)
	if err != nil {
		t.Fatalf("fixture key: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("fixture key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}

	fixture := splitFixture(t, fixtureWalletTx)
	if len(fixture.message) == 0 {
		t.Fatal("the transaction covers nothing")
	}
	if err := VerifySolanaTx(fixture, ed25519.PublicKey(pub)); err != nil {
		t.Fatalf("a real transaction did not verify: %v", err)
	}

	// The signature covers the message and nothing else. Appending a byte is
	// the smallest possible lie, and it has to be caught, or the split is
	// merely plausible rather than right.
	tampered := SolanaTxResponse{
		Signature:         fixture.Signature,
		SignedTransaction: append(append([]byte{}, fixture.SignedTransaction...), 0),
	}
	if err := VerifySolanaTx(tampered, ed25519.PublicKey(pub)); err == nil {
		t.Error("a transaction with an extra byte still verified")
	}
}

// One signed by a session key has the same shape as one signed by a wallet,
// which is the property the whole thing rests on: an ed25519 key is an
// ed25519 key whatever it was made for.
func TestRealSessionTransactionHasTheSameShape(t *testing.T) {
	fixture := splitFixture(t, fixtureSessionTx)

	if len(fixture.Signature) != ed25519.SignatureSize {
		t.Errorf("signature is %d bytes, want %d", len(fixture.Signature), ed25519.SignatureSize)
	}
	if len(fixture.message) == 0 {
		t.Error("the transaction covers nothing")
	}

	// Both were built the same way, so both have to split the same way.
	wallet := splitFixture(t, fixtureWalletTx)
	if len(wallet.Signature) != len(fixture.Signature) {
		t.Errorf("wallet and session signatures differ in size: %d and %d",
			len(wallet.Signature), len(fixture.Signature))
	}
}
