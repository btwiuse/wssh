package solana

import (
	"errors"
	"fmt"

	"github.com/btwiuse/wssh/auth/siws"
)

// FeePayer is the account a signed transaction was actually paid by, read
// back out of the signed bytes.
//
// Reading it back is the point. The request may name a payer, or name none
// and leave the wallet to choose, and in neither case is the session certain
// what the wallet did until it has the transaction. The answer here comes
// from the same bytes the wallet signed, so it is the account that paid
// rather than a claim about which one was asked to.
//
// The layout is shallow and fixed: a compact-u16 signature count, that many
// 64-byte signatures, then the message. The message opens with a header and
// its account keys, and the first key is the fee payer - which is why this
// has to walk the two length-prefixed forms rather than just take 32 bytes
// after the signatures.
func FeePayer(signed []byte) (string, error) {
	rest, err := afterSignatures(signed)
	if err != nil {
		return "", err
	}

	// A versioned message starts with a byte whose top bit is set and whose
	// low seven bits are the version. A legacy one starts with the header,
	// which counts signatures and can never have that bit set.
	versioned := len(rest) > 0 && rest[0]&0x80 != 0
	if versioned {
		rest = rest[1:]
	}

	// The header is three separate bytes, not one packed byte: required
	// signatures, readonly signatures, readonly unsigned. Reading it as a
	// single byte puts everything after it one position out of true, which
	// returns a plausible account that is not the payer.
	if len(rest) < 3 {
		return "", errors.New("the signed transaction ends inside its header")
	}
	rest = rest[3:]

	if versioned {
		// A versioned message then counts its static keys.
		_, n, err := readCompactU16(rest)
		if err != nil {
			return "", fmt.Errorf("the account count is not readable: %w", err)
		}
		rest = rest[n:]
	}
	// A legacy message has no count of its own: the three header counts
	// just read imply how many accounts follow.

	if len(rest) < 32 {
		return "", errors.New("the signed transaction carries no fee payer")
	}
	return siws.Base58Encode(rest[:32]), nil
}

// afterSignatures skips the signature section and returns the message that
// the signatures cover.
func afterSignatures(signed []byte) ([]byte, error) {
	count, n, err := readCompactU16(signed)
	if err != nil {
		return nil, fmt.Errorf("the signature count is not readable: %w", err)
	}
	need := count * 64
	rest := signed[n:]
	if len(rest) < need {
		return nil, fmt.Errorf("the transaction claims %d signatures but is %d bytes",
			count, len(signed))
	}
	return rest[need:], nil
}

// readCompactU16 is Solana's compact-u16: seven bits per byte, low first,
// with the high bit marking continuation. Three bytes is the most one can
// be, so a longer run is refused rather than read into something it is not.
func readCompactU16(b []byte) (value int, length int, err error) {
	for i := range 3 {
		if i >= len(b) {
			return 0, 0, errors.New("the value ends before it does")
		}
		value |= int(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			return value, i + 1, nil
		}
	}
	return 0, 0, errors.New("the value is longer than a compact-u16 can be")
}
