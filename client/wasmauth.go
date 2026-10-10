//go:build js && wasm

package client

import (
	"errors"
	"fmt"
	"strings"
	"syscall/js"

	"github.com/charmbracelet/keygen"
	gossh "golang.org/x/crypto/ssh"

	"github.com/btwiuse/wssh/auth/agentkey"
)

// errNoPassword is returned when the page declines to supply a password. It
// is not an error to report: declining is a legitimate answer.
var errNoPassword = errors.New("no password given")

// errNoFunction is returned when the page has not installed a prompt hook.
var errNoFunction = errors.New("no prompt hook installed")

// credentials is what the page hands over when connecting.
type credentials struct {
	// Keys are private keys, each with an optional passphrase already filled
	// in if the user typed one.
	Keys []keyMaterial `json:"keys"`

	// Passwords are offered after the keys, if the user has any.
	Passwords []string `json:"passwords"`

	// WalletPublicKey is the connected browser wallet's ed25519 public key as
	// hex. When set, the wallet is offered alongside the keys above: the
	// private half stays in the wallet extension and only signatures come
	// back.
	WalletPublicKey string `json:"walletPublicKey"`

	// WalletAddress is the connected wallet's account address, used to name
	// the key in a signing question. Optional: without it the question falls
	// back to the key's fingerprint.
	WalletAddress string `json:"walletAddress"`

	// SignIn asks for the session to be authenticated by the connected
	// wallet. What the wallet signs is decided by the server and arrives on
	// the socket; all this says is that the page is willing to ask it.
	SignIn bool `json:"signIn"`

	// ForwardAgent turns the keys above into an agent the session can ask to
	// sign with. It is the browser's `ssh -A`: the keys stay here, and only
	// signatures come back. Off unless the user asked for it.
	ForwardAgent bool `json:"forwardAgent"`
}

// keyMaterial is one private key and, when it is encrypted, the passphrase that
// opens it.
type keyMaterial struct {
	Name       string `json:"name"`
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase"`

	// PassphraseAsked records that the user already typed this passphrase, so a
	// retry after a wrong guess asks again rather than silently reusing it.
	PassphraseAsked bool `json:"passphraseAsked"`
}

// buildAuth turns what the page supplied into the methods to offer the server:
// keys first, in the order given, and the password after them.
//
// The signers come back alongside because the caller may want them for
// something else - forwarding an agent - and parsing a key twice to get at
// them twice would mean asking for a passphrase twice.
func buildAuth(creds credentials, askPassword func() (string, error),
	askKeyPassphrase func(name string) (string, error)) ([]gossh.AuthMethod, []agentkey.Key, error) {
	var auth []gossh.AuthMethod
	var keys []agentkey.Key

	for _, key := range creds.Keys {
		signer, err := signerFor(key, askKeyPassphrase)
		if err != nil {
			return nil, nil, err
		}
		if signer != nil {
			auth = append(auth, gossh.PublicKeys(signer))
			// The name the page gave this key is what a session will see
			// at the end of every `ssh-add -l` line and in sol-keys. It is
			// the only description of the key that exists anywhere: the
			// private key is a blob with nothing in it to read, and without
			// the name two imported keys are indistinguishable in a listing
			// that cannot tell them apart any other way.
			keys = append(keys, agentkey.Key{Signer: signer, Comment: keyComment(key)})
		}
	}

	// A saved password is offered without asking. With none saved, the method
	// is still offered but asks the page when the handshake reaches for it, so
	// a server that wants a password gets one instead of a silent refusal.
	if askPassword != nil {
		saved := append([]string(nil), creds.Passwords...)
		asked := false
		auth = append(auth, gossh.PasswordCallback(func() (string, error) {
			if len(saved) > 0 {
				// Only the first is tried: the handshake asks once, so a list
				// is a convenience for the usual case rather than a search.
				return saved[0], nil
			}
			if asked {
				return "", errNoPassword
			}
			asked = true
			return askPassword()
		}))
	}
	return auth, keys, nil
}

// SolanaComment labels a key as the Solana account it is.
//
// The prefix carries information precisely because ed25519 is not Solana's:
// Sui and Near wallets are on the same curve, so a 32-byte key and a base58
// string of it are what any of them looks like. The address alone therefore
// does not say which chain's encoding it is, and saying so is the whole
// reason this is a prefix and not just the address.
const SolanaComment = "solana:"

// walletComment is what the connected wallet is called in a session.
//
// The address goes in the comment, and so does the fact that it is a Solana
// address: a key pasted into authorized_keys keeps its comment and loses
// everything else this listing knows, so the part worth keeping has to be in
// the comment.
//
// With no address there is nothing to name and a bare prefix would say
// nothing, so the source is what is left.
func walletComment(creds credentials) string {
	if addr := strings.TrimSpace(creds.WalletAddress); addr != "" {
		// SolanaComment is duplicated from auth/agentkey's
		// WalletCommentPrefix until the routing that reads it lands.
		return "solana:" + addr
	}
	return "wallet"
}

// keyComment is what an imported key is called in a session.
//
// The page names every key it stores, so the name is used when there is one.
// When there is not, the fallback is the algorithm rather than nothing: a
// label of `ssh-ed25519` at the end of a line is harmless, whereas an empty
// one leaves two keys in a listing with nothing to tell them apart. It is not
// this package's job to invent a better name, because only the page knows
// what the user called it.
func keyComment(key keyMaterial) string {
	if name := strings.TrimSpace(key.Name); name != "" {
		return name
	}
	return gossh.KeyAlgoED25519
}

// signerFor opens one private key, asking the page for a passphrase if it needs
// one. A key that cannot be opened at all is skipped rather than fatal: a
// half-imported key should not stop the others from being tried.
func signerFor(key keyMaterial, ask func(name string) (string, error)) (gossh.Signer, error) {
	raw := []byte(strings.TrimSpace(key.PrivateKey))
	if len(raw) == 0 {
		return nil, nil //nolint:nilnil
	}

	// The common case: a key that is not encrypted needs nothing from anyone.
	if signer, err := gossh.ParsePrivateKey(raw); err == nil {
		return signer, nil
	}

	passphrase := key.Passphrase
	if passphrase == "" && ask != nil {
		given, err := ask(key.Name)
		if err != nil {
			return nil, err
		}
		passphrase = given
	}
	if passphrase == "" {
		return nil, fmt.Errorf("%s is encrypted and no passphrase was given", nameOf(key))
	}

	signer, err := gossh.ParsePrivateKeyWithPassphrase(raw, []byte(passphrase))
	if err != nil {
		// A wrong passphrase is the common mistake here and the message from
		// the parser does not always say so.
		if strings.Contains(err.Error(), "decrypt") || strings.Contains(err.Error(), "passphrase") {
			return nil, fmt.Errorf("wrong passphrase for %s", nameOf(key))
		}
		return nil, fmt.Errorf("%s: %w", nameOf(key), err)
	}
	return signer, nil
}

func nameOf(key keyMaterial) string {
	if key.Name != "" {
		return key.Name
	}
	return "private key"
}

// jsGenerateKey creates a key pair in the browser. Nothing is written to disk:
// the page decides whether to keep the result.
func jsGenerateKey(_ js.Value, args []js.Value) any {
	kind := "ed25519"
	if len(args) > 0 && args[0].Type() == js.TypeString {
		kind = args[0].String()
	}
	bits := 0
	if len(args) > 1 && args[1].Type() == js.TypeNumber {
		bits = args[1].Int()
	}

	var keyType keygen.KeyType
	switch strings.ToLower(kind) {
	case "", "ed25519":
		keyType = keygen.Ed25519
	case "rsa":
		keyType = keygen.RSA
		if bits <= 0 {
			bits = 4096
		}
	case "ecdsa":
		keyType = keygen.ECDSA
	default:
		post(map[string]any{"type": "error", "message": "unknown key type: " + kind})
		return nil
	}

	// No WithWrite: there is no filesystem here, and the page is the only
	// thing that should decide where a key lives.
	opts := []keygen.Option{keygen.WithKeyType(keyType)}
	if keyType == keygen.RSA {
		opts = append(opts, keygen.WithBitSize(bits))
	}
	pair, err := keygen.New("", opts...)
	if err != nil {
		post(map[string]any{"type": "error", "message": "generate key: " + err.Error()})
		return nil
	}

	post(map[string]any{
		"type":       "generatedKey",
		"publicKey":  pair.AuthorizedKey(),
		"privateKey": string(pair.RawPrivateKey()),
	})
	return nil
}

// jsKeyInfo reports what a pasted private key is, so the page can label it
// before it is stored: its type, its fingerprint, and whether it is encrypted.
func jsKeyInfo(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return nil
	}
	raw := strings.TrimSpace(args[0].String())

	info := map[string]any{"encrypted": false}
	if raw == "" {
		info["error"] = "empty"
		post(map[string]any{"type": "keyInfo", "info": info})
		return nil
	}

	if _, err := gossh.ParsePrivateKey([]byte(raw)); err == nil {
		info["encrypted"] = false
	} else {
		// Anything that is not an openable plain key is treated as encrypted:
		// that is the only other thing an authorized_keys user can paste, and
		// claiming otherwise would just fail later at connect time.
		info["encrypted"] = true
	}

	// The public half can be read without the passphrase for most formats,
	// which is what makes a fingerprint possible before anything is opened.
	if pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(raw)); err == nil {
		info["type"] = pub.Type()
		info["fingerprint"] = gossh.FingerprintSHA256(pub)
		info["publicKey"] = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))
	} else if signer, err := gossh.ParsePrivateKey([]byte(raw)); err == nil {
		info["type"] = signer.PublicKey().Type()
		info["fingerprint"] = gossh.FingerprintSHA256(signer.PublicKey())
		info["publicKey"] = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	}

	post(map[string]any{"type": "keyInfo", "info": info})
	return nil
}
