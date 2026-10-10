package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/btwiuse/wssh/auth/siws"
)

// DefaultSIWSChallengePath is where a wssh server publishes the sign-in request
// it wants a wallet to sign.
//
// It is a convention rather than something negotiated. A client that cannot
// fetch it has no way to learn the domain, the nonce or the deadline, and those
// are exactly the parts that have to come from the server.
const DefaultSIWSChallengePath = "/auth/siws"

// siwsChallengeTimeout bounds the fetch. A server slow enough to take longer has
// already spent part of the challenge's lifetime, and the caller is about to
// have to answer a wallet prompt on top of that.
const siwsChallengeTimeout = 10 * time.Second

// SIWSSignIn fetches a sign-in request, answers it with an ed25519 key, and
// returns a token to present to the server.
//
// The key never leaves this process. What comes back is a message and a
// signature over it; what goes out is a signed message, which is all the
// server needs and all the wallet was asked for.
//
// The challenge is fetched rather than composed. Domain, nonce and deadline have
// to be the server's: a client that picked its own domain would be asking a
// wallet to vouch for whichever host it liked.
func SIWSSignIn(serverURL, challengePath string, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("sign-in key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	if challengePath == "" {
		challengePath = DefaultSIWSChallengePath
	}

	endpoint, err := httpOrigin(serverURL, challengePath)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), siwsChallengeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build the challenge request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch the sign-in challenge: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the server answered the sign-in challenge with %s", resp.Status)
	}

	var input siws.SIWSInput
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&input); err != nil {
		return "", fmt.Errorf("read the sign-in challenge: %w", err)
	}
	if input.Domain == "" || input.Nonce == "" {
		return "", fmt.Errorf("the server sent a sign-in challenge with no domain or nonce")
	}

	// The account is filled in here, not asked for: the server that chose it
	// would be asking a wallet to prove something other than who is asking.
	input.Address = siws.Base58Encode(key.Public().(ed25519.PublicKey))

	message := []byte(input.Format())
	return siws.EncodeSIWS(message, ed25519.Sign(key, message)), nil
}

// httpOrigin turns a WebSocket address into an HTTP one for a given path.
//
// Only the scheme changes. A ws:// or wss:// address names the same host the
// sign-in message will be checked against, and replacing it with anything else
// would change what the message has to say.
func httpOrigin(wsURL, path string) (string, error) {
	parsed, err := url.Parse(wsURL)
	if err != nil {
		return "", fmt.Errorf("the server address is not a URL: %w", err)
	}
	switch parsed.Scheme {
	case "ws", "http":
		parsed.Scheme = "http"
	case "wss", "https":
		parsed.Scheme = "https"
	default:
		return "", fmt.Errorf("cannot fetch a sign-in challenge from a %q address", parsed.Scheme)
	}
	parsed.Path = path
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
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
