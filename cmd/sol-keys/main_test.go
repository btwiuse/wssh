package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
	"github.com/btwiuse/wssh/solana"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// pinnedEdKey is a real authorized_keys line for a key with no meaning,
// because the test that matters is whether the line survives the listing
// byte for byte. Pinned rather than generated: a listing that quietly
// reformatted it would still be a listing, and only a fixed string notices.
const (
	pinnedEdLine    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
	pinnedEdAddress = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF"
)

// The listing has to be readable by someone who already knows ssh-add, which
// means the key line is the line ssh-add prints, unchanged, and the account
// sits underneath rather than being folded into it.
func TestPrintKeysShowsEveryKeyAndItsAccount(t *testing.T) {
	keys := []solana.AgentKey{{Public: pinnedEdKey(t), Address: pinnedEdAddress}}

	out := capture(t, func(w *bytes.Buffer) { printKeys(w, keys, "/tmp/agent.1") })
	if !strings.Contains(out, pinnedEdLine) {
		t.Errorf("the key line ssh-add would print is missing:\n%s", out)
	}
	if !strings.Contains(out, pinnedEdAddress) {
		t.Errorf("the account is missing:\n%s", out)
	}
	if !strings.HasPrefix(out, "1 key in the agent at /tmp/agent.1\n") {
		t.Errorf("the header does not say what was asked and what came back:\n%s", out)
	}
}

// "1 keys" is wrong English on the one line everybody reads, so the plural is
// worth a branch.
func TestTheHeaderCountsInEnglish(t *testing.T) {
	for _, tc := range []struct {
		count int
		want  string
	}{
		{count: 1, want: "1 key in the agent"},
		{count: 2, want: "2 keys in the agent"},
	} {
		keys := make([]solana.AgentKey, tc.count)
		for i := range keys {
			keys[i] = solana.AgentKey{Public: pinnedEdKey(t)}
		}
		out := capture(t, func(w *bytes.Buffer) { printKeys(w, keys, "/tmp/agent.1") })
		if !strings.Contains(out, tc.want) {
			t.Errorf("%d keys printed a header without %q:\n%s", tc.count, tc.want, out)
		}
	}
}

// The comment an agent carries goes at the end of the line, where ssh-add
// puts it. A wssh session's own forwarded agent sets one, so a listing that
// dropped it would be thinner than ssh-add on the very same socket.
func TestPrintKeysKeepsTheAgentsComment(t *testing.T) {
	keys := []solana.AgentKey{{
		Public:  pinnedEdKey(t),
		Address: pinnedEdAddress,
		Comment: "wssh@bastion",
	}}
	out := capture(t, func(w *bytes.Buffer) { printKeys(w, keys, "/tmp/agent.1") })
	if !strings.Contains(out, pinnedEdLine+" "+keys[0].Comment) {
		t.Errorf("the comment is not at the end of the line:\n%s", out)
	}
}

// A key that names no account has to say why. A bare "solana" under an RSA key
// reads as a bug in the listing rather than a fact about RSA.
func TestPrintKeysSaysWhyAKeyNamesNoAccount(t *testing.T) {
	keys := []solana.AgentKey{{
		Public: anyRSAKey(t),
		Reason: "a ssh-rsa key is not an ed25519 public key",
	}}

	out := capture(t, func(w *bytes.Buffer) { printKeys(w, keys, "/tmp/agent.1") })
	if !strings.Contains(out, "ssh-rsa ") {
		t.Errorf("the key line is missing:\n%s", out)
	}
	if !strings.Contains(out, "not an ed25519 public key") {
		t.Errorf("nothing explains the missing account:\n%s", out)
	}
	if strings.Contains(out, "solana  \n") {
		t.Errorf("an account was left blank rather than explained:\n%s", out)
	}
}

// An empty agent worked. Saying so and stopping is different from failing,
// and that difference is what decides whether a script around this runs at all.
func TestPrintKeysOnAnEmptyAgent(t *testing.T) {
	out := capture(t, func(w *bytes.Buffer) { printKeys(w, nil, "/tmp/agent.1") })
	if !strings.Contains(out, "no keys in the agent at /tmp/agent.1") {
		t.Errorf("an empty agent was not reported plainly:\n%s", out)
	}
	if strings.Contains(out, "0 keys") {
		t.Errorf("an empty agent was reported as a count:\n%s", out)
	}
}

// A key the agent sent that this could not read has no line to print, but it
// still happened, and hiding it would make the count in the header a lie.
func TestPrintKeysSaysWhenAKeyCouldNotBeRead(t *testing.T) {
	keys := []solana.AgentKey{{Reason: "the agent sent a key this could not read: short read"}}
	out := capture(t, func(w *bytes.Buffer) { printKeys(w, keys, "/tmp/agent.1") })
	if !strings.Contains(out, "short read") {
		t.Errorf("the unreadable key was passed over silently:\n%s", out)
	}
}

// --addresses exists so the output can be handed to something that wants an
// address. Keys with no address are left out entirely: an empty line would
// become an empty argument, and the count goes to stderr so that piping stdout
// does not produce something unparseable.
func TestPrintAddressesLeavesOutKeysWithNoAccount(t *testing.T) {
	keys := []solana.AgentKey{
		{Address: pinnedEdAddress},
		{Reason: "a ssh-rsa key is not an ed25519 public key"},
		{Address: "11111111111111111111111111111112"},
	}
	var out, errOut bytes.Buffer
	printAddresses(&out, &errOut, keys)

	got := out.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), got)
	}
	for _, want := range []string{pinnedEdAddress, "11111111111111111111111111111112"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s is missing:\n%s", want, got)
		}
	}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			t.Errorf("an empty line would be an empty argument:\n%s", got)
		}
	}

	// The count belongs on the other writer. On stdout it would be
	// indistinguishable from an address, which is the one thing this
	// output must not contain.
	if !strings.Contains(errOut.String(), "1 of 3") {
		t.Errorf("the dropped key was not counted: %q", errOut.String())
	}
	if strings.Contains(got, "1 of 3") {
		t.Errorf("the count went to stdout:\n%s", got)
	}
}

func capture(t *testing.T, write func(*bytes.Buffer)) string {
	t.Helper()
	var buf bytes.Buffer
	write(&buf)
	return buf.String()
}

// --json is the format something else reads, so it is held to a different
// standard than the listing: every key must be in the document whether or not
// it names an account, and every field must be present whether or not it has
// something to say. A consumer that has to tell those apart is a consumer that
// breaks when the tool changes.
func TestJSONCarriesEveryKeyAndEveryField(t *testing.T) {
	keys := []solana.AgentKey{
		{
			Public:  pinnedEdKey(t),
			Address: pinnedEdAddress,
			Comment: "wssh@bastion",
		},
		{
			Public: anyRSAKey(t),
			Reason: "a ssh-rsa key is not an ed25519 public key",
		},
		// A key the agent sent that could not be read is still a key the
		// agent holds, and dropping it would make the document's length a
		// different number from the agent's.
		{Reason: "the agent sent a key this could not read: short read"},
	}

	var out bytes.Buffer
	if err := writeJSON(&out, keys, "/tmp/agent.1"); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var doc struct {
		Agent string `json:"agent"`
		Keys  []struct {
			Type          string `json:"type"`
			AuthorizedKey string `json:"authorizedKey"`
			Comment       string `json:"comment"`
			Address       string `json:"address"`
			Reason        string `json:"reason"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("the output is not the document it claims to be: %v\n%s", err, out.String())
	}

	if doc.Agent != "/tmp/agent.1" {
		t.Errorf("agent is %q, want the socket that was asked", doc.Agent)
	}
	if len(doc.Keys) != 3 {
		t.Fatalf("got %d keys, want all 3:\n%s", len(doc.Keys), out.String())
	}

	ed, rsaKey, unread := doc.Keys[0], doc.Keys[1], doc.Keys[2]
	if ed.Type != gossh.KeyAlgoED25519 {
		t.Errorf("type is %q, want %q", ed.Type, gossh.KeyAlgoED25519)
	}
	if ed.Address != pinnedEdAddress {
		t.Errorf("address is %q, want %q", ed.Address, pinnedEdAddress)
	}
	if ed.AuthorizedKey != pinnedEdLine+" wssh@bastion" {
		t.Errorf("the key line lost its comment: %q", ed.AuthorizedKey)
	}
	if ed.Reason != "" {
		t.Errorf("a key with an address should carry no reason, got %q", ed.Reason)
	}

	// The reason is the whole point of the key being here: a consumer that
	// only wanted addresses can skip it, but one that shows the user why
	// there is nothing to show needs it.
	if rsaKey.Address != "" {
		t.Errorf("the rsa key was given an address, %q", rsaKey.Address)
	}
	if !strings.Contains(rsaKey.Reason, "not an ed25519 public key") {
		t.Errorf("the reason did not survive: %q", rsaKey.Reason)
	}
	if unread.AuthorizedKey != "" {
		t.Errorf("an unreadable key was given a line to paste: %q", unread.AuthorizedKey)
	}
	if !strings.Contains(unread.Reason, "short read") {
		t.Errorf("the unreadable key's reason did not survive: %q", unread.Reason)
	}

	// Every field present on every entry, so a typed client never has to
	// distinguish "no account" from "this field does not exist".
	for _, key := range doc.Keys {
		raw, err := json.Marshal(key)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		for _, field := range []string{"type", "authorizedKey", "comment", "address", "reason"} {
			if !strings.Contains(string(raw), `"`+field+`"`) {
				t.Errorf("%s is missing from %s", field, raw)
			}
		}
	}
}

// An agent holding nothing is an answer, and "keys": [] is an answer a
// consumer can loop over. "keys": null parses just as happily and then needs
// a nil check everywhere.
func TestJSONOnAnEmptyAgent(t *testing.T) {
	var out bytes.Buffer
	if err := writeJSON(&out, nil, "/tmp/agent.1"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(out.String(), `"keys": []`) {
		t.Errorf("an empty agent did not come back as an empty list:\n%s", out.String())
	}
}

// Two output formats at once is a question with no good answer, so it is
// refused rather than guessed at - and refused before the agent is touched, so
// the message is the conflict rather than a socket error.
func TestJSONAndAddressesTogetherAreRefused(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "never-opened.sock"))

	cmd := newSolKeysCmd()
	cmd.SetArgs([]string{"--addresses", "--json"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("asking for two output formats should have been refused")
	}
	if !strings.Contains(err.Error(), "--addresses") || !strings.Contains(err.Error(), "--json") {
		t.Errorf("the refusal does not name both flags: %v", err)
	}
	if strings.Contains(err.Error(), "never-opened") {
		t.Errorf("the agent was dialed before the conflict was caught: %v", err)
	}
}

// --json that exists in the help but is ignored by RunE is the worst version
// of this feature, so the flag is checked the whole way through: a real agent
// on a real socket, the command as cobra builds it, and the document that
// comes back off its writer.
func TestJSONFlagRunsEndToEnd(t *testing.T) {
	sock, ed := serveAgentWithOneKey(t)
	want := siws.Base58Encode(ed)

	var out bytes.Buffer
	cmd := newSolKeysCmd()
	cmd.SetArgs([]string{"--json", "--agent", sock})
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("run: %v", err)
	}

	var doc listing
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("--json did not produce the document: %v\n%s", err, out.String())
	}
	if doc.Agent != sock {
		t.Errorf("agent is %q, want the socket that was asked", doc.Agent)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("got %d keys, want 1:\n%s", len(doc.Keys), out.String())
	}
	if doc.Keys[0].Address != want {
		t.Errorf("address is %q, want the key's own %q", doc.Keys[0].Address, want)
	}
}

// All three modes, driven the way a person drives them, so none of them can
// quietly stop being reachable from a flag. What is being checked here is
// which writer each one lands on; the shape of each is covered above.
func TestEachOutputModeIsReachable(t *testing.T) {
	sock, ed := serveAgentWithOneKey(t)
	address := siws.Base58Encode(ed)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "the human listing"},
		{name: "addresses only", args: []string{"--addresses"}},
		{name: "json", args: []string{"--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			cmd := newSolKeysCmd()
			cmd.SetArgs(append(tc.args, "--agent", sock))
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("run: %v", err)
			}
			if !strings.Contains(out.String(), address) {
				t.Errorf("stdout does not carry the address:\n%s", out.String())
			}
			if strings.Contains(errOut.String(), address) {
				t.Errorf("the address went to stderr:\n%s", errOut.String())
			}
		})
	}
}

// serveAgentWithOneKey puts a real agent holding one real ed25519 key on a
// real socket, and returns the path and the key's public half. A test double
// would not catch a wire-format mistake, which is the thing most likely to be
// wrong here.
func serveAgentWithOneKey(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ring, err := agentkey.Keyring([]gossh.Signer{signer})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	// The path is deliberately short: a unix socket path is capped at about
	// 104 bytes and a test's own temp directory name can be longer than that
	// on its own.
	sock := filepath.Join(t.TempDir(), "a.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck
				_ = agent.ServeAgent(ring, conn)
			}()
		}
	}()
	return sock, pub
}

// pinnedEdKey is the public key behind pinnedEdLine, read back out of the
// line itself so the two cannot drift apart.
func pinnedEdKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(pinnedEdLine))
	if err != nil {
		t.Fatalf("the pinned key line does not parse: %v", err)
	}
	if pub.Type() != gossh.KeyAlgoED25519 {
		t.Fatalf("the pinned line is a %s, so this test would not mean what it says", pub.Type())
	}
	return pub
}

// anyRSAKey is a key of the kind that names no account. It is generated
// rather than pinned because nothing here is about its bytes - only about
// what the listing does with a key that cannot be one.
func anyRSAKey(t *testing.T) gossh.PublicKey {
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
