package wssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth"
	"github.com/btwiuse/wssh/auth/siws"
	"github.com/btwiuse/wssh/client"
	"github.com/btwiuse/wssh/shell"
	gossh "golang.org/x/crypto/ssh"
)

// standInForAWallet is a signer that answers the way a wallet would, without a
// wallet.
//
// Everything here is the same arithmetic a wallet does: fill in the account,
// build the message from the fields the server asked for, sign it. The only
// thing missing is the popup.
func standInForAWallet(priv ed25519.PrivateKey) client.SIWSSigner {
	return func(in siws.SIWSInput) ([]byte, []byte, error) {
		address, err := addressOf(priv)
		if err != nil {
			return nil, nil, err
		}
		in.Address = address

		message := []byte(in.Format())
		return message, ed25519.Sign(priv, message), nil
	}
}

// The point of the whole thing: a client that owns a Solana account can reach a
// server that requires authentication, without the private key ever leaving the
// client and without the client signing anything binary.
func TestWalletSignInAuthenticates(t *testing.T) {
	authorized := newAuthorizedAccount(t)
	server := startWalletServer(t, [][]byte{authorized.pub})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var out strings.Builder
	sess, err := client.Dial(ctx, client.Options{
		URL:        server.url,
		User:       "tester",
		SIWSSigner: standInForAWallet(authorized.priv),
		OnData: func(p []byte) {
			out.Write(p)
		},
		OnClose: func(error) {},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close() //nolint:errcheck

	if err := sess.Write([]byte("echo WALLET_SIGNED_IN_OK\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if strings.Contains(out.String(), "WALLET_SIGNED_IN_OK") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out; output=%q", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Without a sign-in, the same server refuses the same client. This is what
// proves the sign-in is doing the work rather than the server having quietly
// stopped requiring anything.
func TestWalletSignInIsRequiredWhenConfigured(t *testing.T) {
	authorized := newAuthorizedAccount(t)
	server := startWalletServer(t, [][]byte{authorized.pub})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// No token at all.
	if _, err := client.Dial(ctx, client.Options{
		URL: server.url, User: "tester",
		OnData: func([]byte) {}, OnClose: func(error) {},
	}); err == nil {
		t.Error("a client with no sign-in should not have connected")
	}

	// An account that is not on the list, refused with the reason rather than
	// a closed connection.
	stranger := newAuthorizedAccount(t)
	_, err := client.Dial(ctx, client.Options{
		URL: server.url, User: "tester", SIWSSigner: standInForAWallet(stranger.priv),
		OnData: func([]byte) {}, OnClose: func(error) {},
	})
	if err == nil {
		t.Error("an unauthorized account should not have connected")
	} else if !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("the refusal should say why, got %v", err)
	}
}

// A sign-in for one host must not work on another. This is the difference
// between a readable message being usable or not: SSH's binary challenge cannot
// be shown to anyone, and this can.
func TestWalletSignInIsBoundToTheDomain(t *testing.T) {
	authorized := newAuthorizedAccount(t)
	server := startWalletServer(t, [][]byte{authorized.pub})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// The message names somewhere else. A wallet would have refused to sign
	// it; one that signs it anyway still must not get in.
	_, err := client.Dial(ctx, client.Options{
		URL: server.url, User: "tester",
		SIWSSigner: func(in siws.SIWSInput) ([]byte, []byte, error) {
			in.Domain = "somewhere-else.example"
			return standInForAWallet(authorized.priv)(in)
		},
		OnData: func([]byte) {}, OnClose: func(error) {},
	})
	if err == nil {
		t.Error("a sign-in naming another domain should not have connected")
	} else if !strings.Contains(err.Error(), "domain") {
		t.Errorf("the refusal should name the domain, got %v", err)
	}
}

// An expired sign-in is refused, so one captured from a log or a history bar is
// not a standing credential.
func TestWalletSignInExpires(t *testing.T) {
	authorized := newAuthorizedAccount(t)
	server := startWalletServer(t, [][]byte{authorized.pub})

	issued := time.Now().Add(-2 * time.Hour)
	server.config.Now = func() time.Time { return issued }

	// The server's clock moves on; the message does not.
	server.config.Now = func() time.Time { return time.Now() }
	server.config.Lifetime = 0

	// The server's clock moves on; the message is built when the challenge
	// arrives, so the only thing that can make this old is the clock inside
	// the signer, which is what a captured sign-in looks like.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := client.Dial(ctx, client.Options{
		URL: server.url, User: "tester",
		SIWSSigner: func(in siws.SIWSInput) ([]byte, []byte, error) {
			in.IssuedAt = issued.Format(time.RFC3339)
			return standInForAWallet(authorized.priv)(in)
		},
		OnData: func([]byte) {}, OnClose: func(error) {},
	})
	if err == nil {
		t.Error("an expired sign-in should not have connected")
	} else if !strings.Contains(err.Error(), "issued") {
		t.Errorf("the refusal should say it was old, got %v", err)
	}
}

// walletServer is a wssh that accepts wallet sign-ins, plus the challenge it
// hands out.
type walletServer struct {
	url    string
	host   string
	config *siws.SIWSAuth
}

type walletAccount struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newAuthorizedAccount(t *testing.T) walletAccount {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return walletAccount{pub: pub, priv: priv}
}

func startWalletServer(t *testing.T, authorized [][]byte) *walletServer {
	return startWalletServerWith(t, authorized, nil)
}

func startWalletServerWith(t *testing.T, authorized [][]byte, extraKey ed25519.PublicKey) *walletServer {
	t.Helper()

	dir := t.TempDir()
	script := filepath.Join(dir, "fake-shell")
	body := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-c\" ]; then exec /bin/sh -c \"$2\"; fi\n" +
		"while IFS= read -r line; do eval \"$line\"; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake shell: %v", err)
	}
	t.Setenv("SHELL", script)

	cfg := &siws.SIWSAuth{
		Addresses: authorized,
		Statement: "Sign in to wssh",
	}

	// A key nobody here holds, so the server really does require something.
	// Without it wish allows every connection, and a test that a client with
	// no sign-in is refused would pass for the wrong reason.
	lockout, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keys := []string{keyLine(t, lockout)}
	if extraKey != nil {
		keys = append(keys, keyLine(t, extraKey))
	}
	authOpts, err := (&auth.Config{Keys: keys}).Options()
	if err != nil {
		t.Fatalf("auth options: %v", err)
	}

	server, err := wssh.NewServer(wssh.Options{
		HostKeyPath: filepath.Join(dir, "host_ed25519"),
		Middleware:  []wish.Middleware{shell.Middleware()},
		Pty:         true,
		WalletAuth:  cfg,
		SSHOptions:  authOpts,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/ws", server)
	go func() { _ = http.Serve(ln, mux) }()
	t.Cleanup(func() { _ = ln.Close() })

	return &walletServer{url: "ws://" + ln.Addr().String() + "/ws", host: ln.Addr().String(), config: cfg}
}

func (s *walletServer) challenge(t *testing.T) siws.SIWSInput {
	t.Helper()
	in, err := s.config.Challenge(s.host)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	return in
}

// addressOf renders a public key the way a wallet names an account. It lives in
// the test because the package deliberately has no encoder: everything it needs
// is read back out of the message a wallet signed.
func addressOf(priv ed25519.PrivateKey) (string, error) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	pub := ed25519.PublicKey(priv[32:])
	n := new(big.Int).SetBytes(pub)
	out := make([]byte, 0, 44)
	radix, mod := big.NewInt(58), new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for _, b := range pub {
		if b != 0 {
			break
		}
		out = append(out, alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

// keyLine renders a public key the way an authorized_keys file would.
func keyLine(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap public: %v", err)
	}
	return string(gossh.MarshalAuthorizedKey(sshPub))
}

// A server can accept a wallet and a key at once, and a client carrying only a
// key must get in on it.
//
// The wallet sign-in is offered by a subprotocol, and a client used to offer it
// whether or not it had a wallet - so a client with a perfectly good key
// announced that it would answer a challenge, then refused it for having no
// wallet to answer with. The key was never offered a chance.
func TestKeyClientReachesAServerThatAlsoAcceptsWallets(t *testing.T) {
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	server := startWalletServerWith(t, [][]byte{newAuthorizedAccount(t).pub}, clientPub)

	signer, err := gossh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var out strings.Builder
	sess, err := client.Dial(ctx, client.Options{
		URL:     server.url,
		User:    "tester",
		Auth:    []gossh.AuthMethod{gossh.PublicKeys(signer)},
		OnData:  func(p []byte) { out.Write(p) },
		OnClose: func(error) {},
	})
	if err != nil {
		t.Fatalf("a key-only client should not have been pushed into a wallet sign-in: %v", err)
	}
	defer sess.Close() //nolint:errcheck

	if err := sess.Write([]byte("echo KEY_ONLY_OK\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if strings.Contains(out.String(), "KEY_ONLY_OK") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out; output=%q", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}
