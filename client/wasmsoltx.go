//go:build js && wasm

package client

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"
	"time"

	"github.com/btwiuse/wssh/auth/agentkey"
)

// The Solana half of the agent, on the browser side.
//
// Nothing here builds a transaction. Serialising one is the kind of thing that
// has to track the chain's format changes, and the library meant to track them
// runs on this side anyway, where the wallet is. What this does is carry the
// request over, check that what comes back is a genuine signature over the
// message that was signed, and hand the reason for a refusal back intact.

// walletSolTxHook is the global worker.js installs for asking the page to sign
// a transaction.
const walletSolTxHook = "__websshSolanaTx"

// solTxTimeout bounds one request. It is generous because a person may be
// reading the transaction before they approve it.
const solTxTimeout = 5 * time.Minute

// solTxAnswer is what the page hands back.
//
// Refusal is separate from the bytes because a decline is an answer, not a
// failure, and the agent protocol has nowhere to put the reason on an error
// path. PublicKey comes back rather than being assumed, so the Go side can
// check the signature against the key the page claims to have used.
//
// Unsigned is what comes back when the page has no wallet: the transaction is
// still built here, because that is where the serialisation lives, and it goes
// back for the session's own key to sign. An ed25519 key is an ed25519 key
// whatever it was made for.
type solTxAnswer struct {
	Refusal string `json:"refusal,omitempty"`

	PublicKey         string `json:"publicKey,omitempty"`
	Signature         string `json:"signature,omitempty"`
	SignedTransaction string `json:"signedTransaction,omitempty"`

	Unsigned string `json:"unsigned,omitempty"`
}

// solanaBuilder returns a way to have the page build a transaction without
// signing it, for an agent whose key is local.
//
// It goes through the page even though the key is not there, because the
// serialisation belongs to the library that tracks Solana's format and that
// library is on the page. What comes back is signed here instead.
func solanaBuilder() agentkey.SolanaBuild {
	hook := js.Global().Get(walletSolTxHook)
	if hook.Type() != js.TypeFunction {
		return nil
	}
	return func(req agentkey.SolanaTxRequest) ([]byte, error) {
		body, err := json.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("pack the request: %w", err)
		}
		text, err := awaitStringTimeout(hook, []string{string(body), "build"}, solTxTimeout)
		if err != nil {
			return nil, err
		}
		var answer solTxAnswer
		if err := json.Unmarshal([]byte(text), &answer); err != nil {
			return nil, fmt.Errorf("the answer is not readable: %w", err)
		}
		if answer.Refusal != "" {
			return nil, errors.New(answer.Refusal)
		}
		return decodeHex(answer.Unsigned, "transaction")
	}
}

// solanaAsker returns a way to reach the page's wallet, or nil if there is not
// one, in which case the agent signs with the key it already holds.
func solanaAsker() agentkey.SolanaAsk {
	hook := js.Global().Get(walletSolTxHook)
	if hook.Type() != js.TypeFunction {
		return nil
	}

	return func(req agentkey.SolanaTxRequest) (agentkey.SolanaTxResponse, ed25519.PublicKey, error) {
		body, err := json.Marshal(req)
		if err != nil {
			return agentkey.SolanaTxResponse{}, nil, fmt.Errorf("pack the request: %w", err)
		}

		text, err := awaitStringTimeout(hook, []string{string(body), "sign"}, solTxTimeout)
		if err != nil {
			return agentkey.SolanaTxResponse{}, nil, err
		}

		var answer solTxAnswer
		if err := json.Unmarshal([]byte(text), &answer); err != nil {
			return agentkey.SolanaTxResponse{}, nil, fmt.Errorf("the wallet's answer is not readable: %w", err)
		}
		if answer.Refusal != "" {
			return agentkey.SolanaTxResponse{}, nil, errors.New(answer.Refusal)
		}
		if answer.Unsigned != "" {
			raw, err := decodeHex(answer.Unsigned, "transaction")
			if err != nil {
				return agentkey.SolanaTxResponse{}, nil, err
			}
			return agentkey.SolanaTxResponse{Unsigned: raw}, nil, nil
		}

		pub, sig, signed, err := decodeSolTxAnswer(answer)
		if err != nil {
			return agentkey.SolanaTxResponse{}, nil, err
		}
		return agentkey.SolanaTxResponse{
			Signature:         sig,
			SignedTransaction: signed,
		}, pub, nil
	}
}

func decodeSolTxAnswer(answer solTxAnswer) (ed25519.PublicKey, []byte, []byte, error) {
	var (
		pub    ed25519.PublicKey
		sig    []byte
		signed []byte
		err    error
	)

	if pub, err = decodeHex(answer.PublicKey, "public key"); err != nil {
		return nil, nil, nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, nil, nil, fmt.Errorf("the wallet reported a %d byte key, want %d",
			len(pub), ed25519.PublicKeySize)
	}
	if sig, err = decodeHex(answer.Signature, "signature"); err != nil {
		return nil, nil, nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, nil, nil, fmt.Errorf("the wallet returned a %d byte signature, want %d",
			len(sig), ed25519.SignatureSize)
	}
	if signed, err = decodeHex(answer.SignedTransaction, "signed transaction"); err != nil {
		return nil, nil, nil, err
	}
	return pub, sig, signed, nil
}

func decodeHex(s, what string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("the wallet returned no %s", what)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the %s is not readable: %w", what, err)
	}
	return raw, nil
}
