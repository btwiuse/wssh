package solana

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// fixtureAuthorizedKey and fixtureAddress are pinned rather than recomputed,
// so a change in the base58 alphabet, in how the key body is located inside
// the wire blob, or in which bytes get treated as the public key shows up as
// a failing test instead of as a different string that nothing compares
// against anything.
//
// The key behind them has no meaning - the seed is a run of bytes - but it is
// a real ed25519 point, which is the part that matters. Thirty-two made-up
// bytes would decode to a plausible address and prove nothing.
const (
	fixtureAuthorizedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
	fixtureAddress       = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF"
)

// fixturePublic is fixtureAuthorizedKey's public half, in the form an agent
// sends it back.
func fixturePublic(t *testing.T) gossh.PublicKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	pub, err := gossh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if got := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub))); got != fixtureAuthorizedKey {
		t.Fatalf("the fixture is %q, want %q", got, fixtureAuthorizedKey)
	}
	return pub
}

// The correspondence is meant to be exact: an ed25519 key's address is the
// key, and decoding the address has to give back the very bytes that went in.
// This is the case a wrong answer would be most expensive for, so it is
// checked against both a pinned string and a round trip.
func TestAddressForIsTheKeyItself(t *testing.T) {
	pub := fixturePublic(t)

	address, err := AddressFor(pub)
	if err != nil {
		t.Fatalf("name: %v", err)
	}
	if address != fixtureAddress {
		t.Fatalf("address is %q, want %q", address, fixtureAddress)
	}

	raw := pub.(gossh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	back, err := siws.Base58Decode(address)
	if err != nil {
		t.Fatalf("an address this code produced does not decode: %v", err)
	}
	if len(back) != ed25519.PublicKeySize {
		t.Fatalf("the address is %d bytes, an account is %d", len(back), ed25519.PublicKeySize)
	}
	if sha256.Sum256(back) != sha256.Sum256(raw) {
		t.Errorf("the address decodes to %x, want the key %x", back, raw)
	}
}

// A key of another kind is refused, and the refusal names the kind. Printing
// nothing would leave a person deciding between a broken listing and a broken
// agent, which is the question one line of output should answer.
func TestAddressForRefusesWhatCannotBeAnAccount(t *testing.T) {
	address, err := AddressFor(mustRSAPublic(t))
	if err == nil {
		t.Fatalf("an rsa key named an account, %q", address)
	}
	if address != "" {
		t.Errorf("the failure still returned an address, %q", address)
	}
	if !strings.Contains(err.Error(), gossh.KeyAlgoRSA) {
		t.Errorf("the reason does not name the key type: %v", err)
	}
}

// A certificate names the key inside it, so it names the same account. The
// outer algorithm is a different string entirely, and reporting that would
// say a certificate signs for nothing when it plainly does.
func TestAddressForFollowsACertificateToItsKey(t *testing.T) {
	_, priv := mustEdKey(t)
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cert := &gossh.Certificate{
		Key:         fixturePublic(t),
		Serial:      1,
		CertType:    gossh.HostCert,
		KeyId:       "wssh-test",
		ValidBefore: gossh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("sign the certificate: %v", err)
	}

	address, err := AddressFor(cert)
	if err != nil {
		t.Fatalf("name: %v", err)
	}
	if address != fixtureAddress {
		t.Errorf("a certificate named %q, want the address of the key inside it, %q",
			address, fixtureAddress)
	}
}

// No key at all is not an error worth carrying a nil through for, but it must
// still be refused: naming nothing a nil address would look exactly like a key
// that names no account.
func TestAddressForWithNoKey(t *testing.T) {
	if address, err := AddressFor(nil); err == nil {
		t.Errorf("nothing named an account, %q", address)
	}
}

// The whole point of the listing: every key the agent holds comes back, every
// ed25519 one carries its address, and the others say why they have none.
// Against a real agent on a real socket, because the thing being tested is the
// conversation.
func TestListAgentKeysNamesEveryKeyTheAgentHolds(t *testing.T) {
	edOne, signerOne := mustEdKey(t)
	edTwo, signerTwo := mustEdKey(t)
	ring, err := agentkey.Keyring([]gossh.Signer{
		mustSigner(t, signerOne),
		mustSigner(t, signerTwo),
		mustRSASigner(t),
	})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	keys, err := ListAgentKeysAt(context.Background(), serveForTest(t, ring))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}

	// Which address belongs to which key is settled by comparing the
	// address, never by position: an agent answers in whatever order it
	// likes, and a listing that assumed an order would be wrong the first
	// time one did not.
	for _, raw := range []ed25519.PublicKey{edOne, edTwo} {
		if !listsAddress(keys, siws.Base58Encode(raw)) {
			t.Errorf("no key named %s", siws.Base58Encode(raw))
		}
	}
	if !listsReason(keys, gossh.KeyAlgoRSA) {
		t.Error("the rsa key was not reported as naming no account")
	}

	// Every address printed belongs to a key that was actually held. This
	// is the check that catches a body being read at the wrong offset,
	// which is otherwise a very quiet way to print a plausible wrong
	// address.
	for _, key := range keys {
		if key.Address == "" {
			continue
		}
		if !anyKeyIs(keys, mustDecode(t, key.Address)) {
			t.Errorf("address %s belongs to no key that was listed", key.Address)
		}
		if key.AuthorizedKey() == "" {
			t.Errorf("key %s has an address but no line to print", key.Type())
		}
	}
}

// The comment the agent carries comes back verbatim, because it is the only
// thing on the line that says where the key came from and only the agent
// knows. A label the agent was given - a key file's name, a wallet's address -
// has to survive the trip or the listing says nothing about any of them.
func TestListAgentKeysKeepsTheAgentsComment(t *testing.T) {
	const comment = "wallet@FRucBU2bikra3LVBGfuxgwrtHka7qiQUCUWH4A2kHFRz"

	_, priv := mustEdKey(t)
	ring, err := agentkey.KeyringWithComments([]agentkey.Key{{
		Signer:  mustSigner(t, priv),
		Comment: comment,
	}})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	keys, err := ListAgentKeysAt(context.Background(), serveForTest(t, ring))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].Comment != comment {
		t.Errorf("comment is %q, want %q", keys[0].Comment, comment)
	}
	// And it lands where a reader will see it: at the end of the line.
	if !strings.HasSuffix(keys[0].AuthorizedKey(), comment) {
		t.Errorf("the line does not end in the comment: %q", keys[0].AuthorizedKey())
	}
}

// An agent that says nothing gets nothing added. This repository's keyring
// used to fill the field with the algorithm name, which made every line read
// `ssh-ed25519 AAAA... ssh-ed25519` and told a session nothing it could not
// already see from the type.
func TestListAgentKeysInventsNoComment(t *testing.T) {
	_, priv := mustEdKey(t)
	ring, err := agentkey.Keyring([]gossh.Signer{mustSigner(t, priv)})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	keys, err := ListAgentKeysAt(context.Background(), serveForTest(t, ring))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].Comment != "" {
		t.Errorf("comment is %q, want nothing rather than an invented label", keys[0].Comment)
	}
	if line := keys[0].AuthorizedKey(); strings.HasSuffix(line, keys[0].Type()) {
		t.Errorf("the algorithm name is standing in for a comment: %q", line)
	}
}

// An empty agent is an answer, not a failure: the agent worked and holds
// nothing. Treating that as an error would make a script fail on the machine
// where the key simply has not been added yet.
func TestListAgentKeysOnAnEmptyAgent(t *testing.T) {
	// A live agent that holds nothing. This is the ordinary state on a machine
	// where no key has been added yet, and after `ssh-add -D` has emptied one.
	ring := agent.NewKeyring()

	keys, err := ListAgentKeysAt(context.Background(), serveForTest(t, ring))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("an empty agent listed %d keys", len(keys))
	}
}

// SSH_AUTH_SOCK is the default because that is the socket everything else
// that wants a signature is already pointed at. Getting this wrong means
// asking a socket the session is not using, which is how a command ends up
// listing an agent from somewhere else entirely.
func TestListAgentKeysAtReadsSSHAuthSock(t *testing.T) {
	_, priv := mustEdKey(t)
	ring, err := agentkey.Keyring([]gossh.Signer{mustSigner(t, priv)})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", serveForTest(t, ring))

	keys, err := ListAgentKeysAt(context.Background(), "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
}

// No environment and no flag is a question with no answer, and the message
// says which piece is missing rather than reporting a dial that failed for a
// reason nobody can act on.
func TestListAgentKeysAtWithNoAgentAtAll(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err := ListAgentKeysAt(context.Background(), "")
	if err == nil {
		t.Fatal("listing with no agent should have been refused")
	}
	if !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Errorf("the refusal does not name what is missing: %v", err)
	}
}

// A path nothing is listening on is a different failure from no path at all,
// and it has a different cause: a SSH_AUTH_SOCK left pointing at a session
// that has ended. The name is in the message so that is recognisable.
func TestListAgentKeysAtOnAStaleSocket(t *testing.T) {
	stale := filepath.Join(t.TempDir(), "agent.sock")
	_, err := ListAgentKeysAt(context.Background(), stale)
	if err == nil {
		t.Fatal("a socket with nothing behind it should have been refused")
	}
	if !strings.Contains(err.Error(), "agent.sock") {
		t.Errorf("the refusal does not name the socket: %v", err)
	}
}

func listsAddress(keys []AgentKey, address string) bool {
	for _, key := range keys {
		if key.Address == address {
			return true
		}
	}
	return false
}

func listsReason(keys []AgentKey, fragment string) bool {
	for _, key := range keys {
		if key.Reason != "" && strings.Contains(key.Reason, fragment) {
			return true
		}
	}
	return false
}

// anyKeyIs reports whether any listed key really is the given public key.
func anyKeyIs(keys []AgentKey, raw ed25519.PublicKey) bool {
	for _, key := range keys {
		curve, ok := key.Public.(gossh.CryptoPublicKey)
		if !ok {
			continue
		}
		got, ok := curve.CryptoPublicKey().(ed25519.PublicKey)
		if ok && string(got) == string(raw) {
			return true
		}
	}
	return false
}

func mustDecode(t *testing.T, address string) ed25519.PublicKey {
	t.Helper()
	raw, err := siws.Base58Decode(address)
	if err != nil {
		t.Fatalf("decode %s: %v", address, err)
	}
	return ed25519.PublicKey(raw)
}

func mustEdKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return pub, priv
}

func mustSigner(t *testing.T, priv ed25519.PrivateKey) gossh.Signer {
	t.Helper()
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func mustRSAPublic(t *testing.T) gossh.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, err := gossh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	return pub
}

func mustRSASigner(t *testing.T) gossh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}
