//go:build js && wasm

package client

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"syscall/js"
	"time"

	"github.com/btwiuse/wssh/auth/siws"
)

// walletSignInHook is the global worker.js installs for asking the page's
// wallet to sign a sign-in request.
//
// The exchange lives in Go because the message has to come from the server and
// be signed over exactly as it arrived. All the page does is hold the wallet
// and show the message: one round trip, and a boolean back.
func walletSignerFn() SIWSSigner {
	hook := js.Global().Get(walletSignInHook)
	if hook.Type() != js.TypeFunction {
		return nil
	}
	return func(challenge siws.SIWSInput) ([]byte, []byte, error) {
		// The page is given the exact text rather than the fields, so what it
		// signs cannot differ from what the server sent.
		answer, err := awaitSignIn(hook, challenge.Format())
		if err != nil {
			return nil, nil, err
		}
		return answer.message, answer.signature, nil
	}
}

const walletSignInHook = "__websshWalletSignIn"

// signInTimeout is how long a wallet prompt may stay open. It is generous,
// because refusing is the wallet's business, and a timeout here would be a
// decline the person never made.
const signInTimeout = 5 * time.Minute

// walletAnswer is what the page hands back: the message the wallet approved,
// and its signature over those bytes.
//
// The message comes back as well as being signed, so that a page which altered
// it cannot hand over a signature over something the server never sent.
type walletAnswer struct {
	message   []byte
	signature []byte
}

func awaitSignIn(hook js.Value, message string) (walletAnswer, error) {
	var answer walletAnswer

	// Hex on both sides: the message is arbitrary UTF-8 and the signature is
	// binary, and neither survives a string cleanly.
	text, err := awaitStringTimeout(hook, []string{message}, signInTimeout)
	if err != nil {
		return answer, err
	}

	messageHex, signatureHex, found := strings.Cut(text, ":")
	if !found {
		return answer, errors.New("the wallet's answer was not readable")
	}
	if answer.message, err = hex.DecodeString(messageHex); err != nil {
		return answer, fmt.Errorf("the signed message is unreadable: %w", err)
	}
	if answer.signature, err = hex.DecodeString(signatureHex); err != nil {
		return answer, fmt.Errorf("the signature is unreadable: %w", err)
	}
	if len(answer.signature) != ed25519.SignatureSize {
		return answer, fmt.Errorf("the wallet returned a %d byte signature", len(answer.signature))
	}
	return answer, nil
}
