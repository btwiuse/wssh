//go:build js && wasm

package client

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"syscall/js"

	gossh "golang.org/x/crypto/ssh"
)

// walletSignHook is the global worker.js installs for asking a browser wallet
// to sign. It is reached through the worker and on to the page, because a
// worker's globals are not the page's and the wallet lives on the page.
const walletSignHook = "__websshSignWithWallet"

// errNoWallet and errSignatureRefused are ordinary answers rather than
// faults: the user may have no wallet open, or may say no. Either way nothing
// is signed and the far end is told so.
var (
	errNoWallet         = errors.New("no wallet connected")
	errSignatureRefused = errors.New("refused by the user")
)

// walletSigner builds a signer backed by a browser wallet, given that wallet's
// ed25519 public key as hex.
//
// Everything crosses as hex because the prompt bridge carries strings: a
// signature is 64 bytes and what gets signed is an SSH packet, and neither is
// text. Passing js.Value instead would mean releasing by hand on a path where a
// mistake costs the whole runtime.
func walletSigner(publicKeyHex, address string) (gossh.Signer, error) {
	raw, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("wallet public key is not hex: %w", err)
	}

	hook := js.Global().Get(walletSignHook)
	if hook.Type() != js.TypeFunction {
		return nil, errNoWallet
	}

	return NewWalletSigner(ed25519.PublicKey(raw), address,
		func(summary string, data []byte) ([]byte, error) {
			answer, err := awaitStringTimeout(hook, []string{summary, hex.EncodeToString(data)}, signatureTimeout)
			if err != nil {
				return nil, err
			}
			if answer == "" {
				return nil, errSignatureRefused
			}
			return hex.DecodeString(answer)
		})
}
