package client

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// AskWallet is consulted for every signature a wallet-backed signer is asked
// for. It gets a short summary of what is being signed and returns the raw
// signature bytes, or an error if the user declined.
type AskWallet func(summary string, data []byte) ([]byte, error)

// WalletSigner signs with a key that lives somewhere else, typically a browser
// wallet extension, by asking it to sign.
//
// The point is that the key never exists in this process. What travels is the
// bytes to be signed and the signature that comes back, which is exactly the
// shape of the agent protocol and is why the SSH half needs to know nothing
// about where the key is.
//
// Both returned values are checked before anything is handed on: a signature of
// the wrong length means the wallet is not signing the raw message, and a
// signature that does not verify against the wallet's own public key means
// something is wrong. Either way the signature is refused rather than passed
// on, because a wrong answer here fails much later and much less clearly.
type WalletSigner struct {
	pub  ed25519.PublicKey
	ask  AskWallet
	name string
}

// NewWalletSigner wraps a key held elsewhere. pub is that key's 32-byte
// ed25519 public key, and ask is how to reach whoever holds the private half.
//
// address is the name the holder of that key calls itself, if it has one. For a
// Solana wallet that is the account address, which is the same 32 bytes written
// in a different alphabet: the key never crosses, so the address never either.
func NewWalletSigner(pub ed25519.PublicKey, address string, ask AskWallet) (gossh.Signer, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wallet public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if ask == nil {
		// Nothing to ask means nothing to sign with. A signer that cannot
		// reach its key must refuse rather than pretend.
		return nil, errors.New("no wallet connected")
	}
	return &WalletSigner{pub: pub, ask: ask, name: WalletLabel(address, pub)}, nil
}

// WalletLabel is how a key is named in a signing question.
//
// The address comes first and is never shortened: this is the string a person
// is being asked to recognise, and a prompt that shows half an identifier is
// worse than no prompt at all. The SSH fingerprint is only a fallback for a
// wallet that reports no address, and it is the same key seen from the other
// side.
func WalletLabel(address string, pub ed25519.PublicKey) string {
	if address != "" {
		return address
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		return "the connected wallet"
	}
	if fp := gossh.FingerprintSHA256(sshPub); fp != "" {
		return "wallet " + fp
	}
	return "the connected wallet"
}

func (w *WalletSigner) PublicKey() gossh.PublicKey {
	pub, err := gossh.NewPublicKey(w.pub)
	if err != nil {
		// Unreachable: w.pub is length-checked in the constructor, and
		// ed25519 is a type gossh knows how to wrap.
		panic(err)
	}
	return pub
}

func (w *WalletSigner) Sign(_ io.Reader, data []byte) (*gossh.Signature, error) {
	sig, err := w.ask(summarizeSignature(w.name, data), data)
	if err != nil {
		return nil, fmt.Errorf("wallet declined to sign: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"wallet returned a %d byte signature, want %d: the wallet is not signing the raw message",
			len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(w.pub, data, sig) {
		return nil, errors.New("the wallet's signature does not verify against its own public key")
	}

	return &gossh.Signature{Format: gossh.KeyAlgoED25519, Blob: sig}, nil
}

// summarizeSignature describes what is about to be signed. It never includes the
// key, and the data is only shown as text when it looks like something a person
// would recognise; a hex prefix is the honest answer for everything else.
func summarizeSignature(name string, data []byte) string {
	what := printableText(data)
	if what == "" {
		what = hex.EncodeToString(headBytes(data, 24))
		if len(data) > 24 {
			what += "..."
		}
	}
	return fmt.Sprintf("%s wants to sign %d bytes: %s", name, len(data), what)
}

// headBytes returns at most n bytes of b.
func headBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// printableText returns data as text if it is short and mostly printable, and
// the empty string otherwise. Guessing wrong here would be worse than showing
// nothing, because the guess is what the user is approving.
func printableText(data []byte) string {
	const max = 120
	if len(data) == 0 || len(data) > max {
		return ""
	}
	for _, b := range data {
		if b != '\n' && b != '\t' && (b < 0x20 || b > 0x7e) {
			return ""
		}
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return ""
	}
	return text
}
