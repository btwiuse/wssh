package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	gossh "golang.org/x/crypto/ssh"

	"github.com/btwiuse/wssh/auth/siws"
	"github.com/coder/websocket"
)

// SIWSSigner answers a server's sign-in request with a message and a
// signature over it.
//
// It is a callback rather than a key because the key is not always ours to
// hold. A command line client has a file and can sign the bytes itself; a
// browser has a wallet extension that has to be asked, across a bridge, while
// the person holding it reads what they are approving. Both are the same call
// from here.
type SIWSSigner func(challenge siws.SIWSInput) (message, signature []byte, err error)

// doSignIn runs the exchange over an open WebSocket, before any SSH byte is
// sent.
//
// It returns false when the client has nothing to say, which is the ordinary
// case for a client that did not ask to sign in: the exchange has to be able
// to be absent, or a server with no wallet sign-in configured would leave every
// client waiting for a question that never comes.
func doSignIn(ctx context.Context, conn *websocket.Conn, signer SIWSSigner) (bool, error) {
	challenge, err := readSIWSFrame(ctx, conn, siwsFrameTimeout)
	if err != nil {
		return false, err
	}

	switch challenge.Kind {
	case siwsKindReady:
		return true, nil

	case siwsKindError:
		return false, errors.New(challenge.Reason)

	case siwsKindChallenge:
		// Fall through to answer it.

	default:
		return false, fmt.Errorf("the server sent %q where a sign-in request was expected", challenge.Kind)
	}

	if challenge.Challenge == nil {
		return false, errors.New("the server sent an empty sign-in request")
	}
	if signer == nil {
		// The server asked and this client cannot answer. Say so rather than
		// going quiet, which would leave it waiting out the whole exchange
		// before finding out what was obvious to both sides at the start.
		_ = writeSIWSFrame(ctx, conn, siwsFrame{
			Kind:   siwsKindError,
			Reason: "this client has no wallet to sign in with",
		})
		return false, errors.New("this client has no wallet to sign in with")
	}
	input := *challenge.Challenge

	message, signature, err := signer(input)
	if err != nil {
		// Say why on the socket rather than just hanging up: the server can
		// then log it against the address it was asking about.
		_ = writeSIWSFrame(ctx, conn, siwsFrame{
			Kind:   siwsKindError,
			Reason: "the wallet did not sign: " + err.Error(),
		})
		return false, err
	}

	if err := writeSIWSFrame(ctx, conn, siwsFrame{
		Kind:      siwsKindSignIn,
		Message:   message,
		Signature: signature,
	}); err != nil {
		return false, err
	}

	answer, err := readSIWSFrame(ctx, conn, siwsFrameTimeout+siwsFrameTimeout)
	if err != nil {
		return false, err
	}
	switch answer.Kind {
	case siwsKindReady:
		return true, nil
	case siwsKindError:
		return false, errors.New(answer.Reason)
	default:
		return false, fmt.Errorf("the server answered a sign-in with %q", answer.Kind)
	}
}

// SIWSSignIn returns a signer backed by a key this process holds.
func SIWSSignIn(key ed25519.PrivateKey) SIWSSigner {
	return func(challenge siws.SIWSInput) ([]byte, []byte, error) {
		if challenge.Domain == "" || challenge.Nonce == "" {
			return nil, nil, errors.New("the server sent an incomplete sign-in request")
		}
		// The account is named here rather than asked for: a server that chose
		// it would be asking a wallet to prove something other than who is
		// asking.
		challenge.Address = siws.Base58Encode(key.Public().(ed25519.PublicKey))

		message := []byte(challenge.Format())
		return message, ed25519.Sign(key, message), nil
	}
}

// LoadSignInKey reads an ed25519 private key for signing in.
//
// Three shapes are accepted, because the same account turns up in all three:
// what wssh keygen writes, the raw 64-byte secret a Solana wallet exports, and
// the JSON array that export is usually pasted as. Refusing any of them would
// mean asking someone to convert a file they already have.
func LoadSignInKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read the sign-in key: %w", err)
	}

	if len(raw) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(raw), nil
	}
	if len(raw) > 2 && raw[0] == '[' && raw[len(raw)-1] == ']' {
		return keyFromJSONArray(raw, path)
	}

	// ParseRawPrivateKey rather than ParsePrivateKey: the first returns the key
	// itself, and the second returns a signer that keeps it in an unexported
	// field. A sign-in has to sign plain bytes, which a signer can do but
	// nothing can take back out.
	parsed, err := gossh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not a private key: %w", path, err)
	}
	key, ok := parsed.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s holds a %T; a sign-in key has to be ed25519", path, parsed)
	}
	return *key, nil
}

func keyFromJSONArray(raw []byte, path string) (ed25519.PrivateKey, error) {
	var numbers []int
	if err := json.Unmarshal(raw, &numbers); err != nil {
		return nil, fmt.Errorf("%s looks like a key but does not parse: %w", path, err)
	}
	if len(numbers) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s holds %d numbers, want %d",
			path, len(numbers), ed25519.PrivateKeySize)
	}
	key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for i, n := range numbers {
		if n < 0 || n > 255 {
			return nil, fmt.Errorf("%s has a value that is not a byte", path)
		}
		key[i] = byte(n)
	}
	return key, nil
}
