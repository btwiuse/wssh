package solana

import (
	"crypto/ed25519"
	"testing"

	"github.com/btwiuse/wssh/auth/siws"
)

// compact encodes n as Solana's compact-u16. Only 0..127 is produced here,
// which is one byte, and every fixture below is small.
func compact(n int) []byte { return []byte{byte(n)} }

// versionedMessage builds the message of a v0 transaction with one account.
// The header is three separate bytes - required signatures, readonly
// signatures, readonly unsigned - and only then a count of the static keys.
// Reading the header as one packed byte leaves everything after it out of
// position, and what comes back is a plausible looking account that is not
// the payer.
func versionedMessage(pub ed25519.PublicKey) []byte {
	out := []byte{0x80}              // version 0, top bit set
	out = append(out, 0x01)          // numRequiredSignatures
	out = append(out, 0x00)          // numReadonlySignedAccounts
	out = append(out, 0x00)          // numReadonlyUnsignedAccounts
	out = append(out, compact(1)...) // one static account key
	return append(out, pub...)
}

// legacyMessage builds the message of a legacy transaction with one account.
// Unlike the versioned form there is no count of account keys here: the
// number is the header's own counts added together, so a reader that expects
// one finds a plausible key that is not the payer.
func legacyMessage(pub ed25519.PublicKey) []byte {
	out := compact(1)                // required signatures
	out = append(out, compact(0)...) // readonly signed
	out = append(out, compact(0)...) // readonly unsigned
	return append(out, pub...)       // one account key, unprefixed
}

// signFor produces the wire shape a wallet returns: a compact-u16 count,
// that many 64-byte signatures, then the message.
func signFor(message []byte, priv ed25519.PrivateKey) []byte {
	out := compact(1)
	out = append(out, make([]byte, ed25519.SignatureSize)...)
	return append(out, message...)
}

func base58Of(t *testing.T, b []byte) string {
	t.Helper()
	return siws.Base58Encode(b)
}
