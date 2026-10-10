package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"charm.land/ssh"
	"golang.org/x/crypto/bcrypt"
	gossh "golang.org/x/crypto/ssh"
)

// newKey returns a real ed25519 public key, so the tests exercise the same
// parsing path a genuine client would rather than a hand-written fixture that
// might not be a key at all.
func newKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	return key
}

// authorizedLine renders a key the way it would appear in authorized_keys.
func authorizedLine(t *testing.T, key ssh.PublicKey, comment string) string {
	t.Helper()
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key))) + " " + comment
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// applyOptions installs the options on a bare server so the handlers can be
// exercised directly. The handlers ignore the context, so nil is safe here.
func applyOptions(t *testing.T, opts []ssh.Option) *ssh.Server {
	t.Helper()
	srv := &ssh.Server{}
	for _, opt := range opts {
		if err := opt(srv); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	return srv
}

func publicKeyHandler(t *testing.T, opts []ssh.Option) func(ssh.PublicKey) bool {
	t.Helper()
	srv := applyOptions(t, opts)
	if srv.PublicKeyHandler == nil {
		t.Fatal("no public key handler was installed")
	}
	return func(key ssh.PublicKey) bool {
		return srv.PublicKeyHandler(nil, key)
	}
}

func passwordHandler(t *testing.T, opts []ssh.Option) func(string) bool {
	t.Helper()
	srv := applyOptions(t, opts)
	if srv.PasswordHandler == nil {
		t.Fatal("no password handler was installed")
	}
	return func(password string) bool {
		return srv.PasswordHandler(nil, password)
	}
}

func TestDisabledByDefault(t *testing.T) {
	var cfg Config
	if cfg.Enabled() {
		t.Fatal("an empty config should not report itself as enabled")
	}
	// No options at all: this is what makes the server skip authentication.
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	if len(opts) != 0 {
		t.Fatalf("expected no options, got %d", len(opts))
	}
}

func TestPublicKeyFromFile(t *testing.T) {
	allowed, stranger := newKey(t), newKey(t)
	path := writeFile(t, t.TempDir(), "authorized_keys",
		"# a comment\n\n"+authorizedLine(t, allowed, "a@example")+"\n")

	cfg := Config{KeyFiles: []string{path}}
	if !cfg.Enabled() {
		t.Fatal("config with a key file should be enabled")
	}
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected one option, got %d", len(opts))
	}

	handler := publicKeyHandler(t, opts)
	if !handler(allowed) {
		t.Fatal("the key in the file should have been accepted")
	}
	if handler(stranger) {
		t.Fatal("an unrelated key should have been rejected")
	}
}

func TestPublicKeyInline(t *testing.T) {
	allowed, stranger := newKey(t), newKey(t)

	cfg := Config{Keys: []string{authorizedLine(t, allowed, "a@example")}}
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	handler := publicKeyHandler(t, opts)
	if !handler(allowed) {
		t.Fatal("the inline key should have been accepted")
	}
	if handler(stranger) {
		t.Fatal("an unrelated key should have been rejected")
	}
}

func TestPublicKeyInlineRejectsGarbage(t *testing.T) {
	// A bad key must be reported at startup, not silently dropped at login.
	cfg := Config{Keys: []string{"not a key"}}
	if _, err := cfg.Options(); err == nil {
		t.Fatal("a malformed inline key should be an error")
	}
}

func TestPublicKeyFileIsReReadEachTime(t *testing.T) {
	allowed, added := newKey(t), newKey(t)
	path := writeFile(t, t.TempDir(), "authorized_keys", authorizedLine(t, allowed, "a@example")+"\n")

	cfg := Config{KeyFiles: []string{path}}
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	handler := publicKeyHandler(t, opts)

	if handler(added) {
		t.Fatal("the second key should not be accepted yet")
	}
	// Adding a key must not require a restart.
	writeFile(t, filepath.Dir(path), filepath.Base(path),
		authorizedLine(t, allowed, "a@example")+"\n"+authorizedLine(t, added, "b@example")+"\n")
	if !handler(added) {
		t.Fatal("the newly added key should be accepted without a restart")
	}
}

func TestPublicKeyMalformedLineIsSkippedNotFatal(t *testing.T) {
	allowed := newKey(t)
	path := writeFile(t, t.TempDir(), "authorized_keys",
		"this is not a key\n"+authorizedLine(t, allowed, "a@example")+"\n")

	opts, err := Config{KeyFiles: []string{path}}.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	if !publicKeyHandler(t, opts)(allowed) {
		t.Fatal("a valid key on a later line should still be accepted")
	}
}

func TestPasswordFromFile(t *testing.T) {
	path := writeFile(t, t.TempDir(), "passwords", "# accepted\nhunter2\n\ns3cret\n")

	opts, err := Config{PasswordFile: path}.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	handler := passwordHandler(t, opts)

	for _, want := range []string{"hunter2", "s3cret"} {
		if !handler(want) {
			t.Fatalf("%q should be accepted", want)
		}
	}
	for _, reject := range []string{"wrong", ""} {
		if handler(reject) {
			t.Fatalf("%q should be rejected", reject)
		}
	}
}

func TestPasswordBcryptHash(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	path := writeFile(t, t.TempDir(), "passwords", string(hash)+"\n")

	handler := passwordHandler(t, mustOptions(t, Config{PasswordFile: path}))
	if !handler("correct horse") {
		t.Fatal("the password matching the hash should be accepted")
	}
	if handler("correct horsE") {
		t.Fatal("a password that does not match the hash should be rejected")
	}
}

func TestPasswordInline(t *testing.T) {
	handler := passwordHandler(t, mustOptions(t, Config{Passwords: []string{"inline-pw"}}))
	if !handler("inline-pw") {
		t.Fatal("an inline password should be accepted")
	}
	if handler("nope") {
		t.Fatal("any other password should be rejected")
	}
}

func TestUnreadablePasswordFileDoesNotAllowEverything(t *testing.T) {
	// Failing to read the file must fail closed, never open.
	cfg := Config{PasswordFile: filepath.Join(t.TempDir(), "does-not-exist")}
	handler := passwordHandler(t, mustOptions(t, cfg))
	if handler("anything at all") {
		t.Fatal("an unreadable password file must not let anyone in")
	}
}

func TestBothMethodsTogether(t *testing.T) {
	allowed := newKey(t)
	dir := t.TempDir()
	keyPath := writeFile(t, dir, "authorized_keys", authorizedLine(t, allowed, "a@example")+"\n")
	pwPath := writeFile(t, dir, "passwords", "hunter2\n")

	opts, err := Config{KeyFiles: []string{keyPath}, PasswordFile: pwPath}.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	if len(opts) != 2 {
		t.Fatalf("expected both methods installed, got %d", len(opts))
	}
	if !publicKeyHandler(t, opts)(allowed) {
		t.Fatal("public key auth should still work")
	}
	if !passwordHandler(t, opts)("hunter2") {
		t.Fatal("password auth should still work")
	}
}

func TestSystemShorthand(t *testing.T) {
	// "system" must resolve to whatever exists and contribute nothing when
	// nothing does, rather than failing or matching everything.
	stranger := newKey(t)
	opts, err := Config{KeyFiles: []string{SystemAuthorizedKeys}}.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	handler := publicKeyHandler(t, opts)
	if files := expandKeyFiles([]string{SystemAuthorizedKeys}); len(files) == 0 {
		t.Log("this machine has no system authorized_keys, so the key was correctly rejected")
	}
	// Whatever the machine has, a key we just made up is not in it.
	if handler(stranger) {
		t.Fatal("a freshly generated key must never match a system file")
	}
}

func mustOptions(t *testing.T, cfg Config) []ssh.Option {
	t.Helper()
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	return opts
}

// "*" in the key list accepts anything at all. It reads like a convenient
// shorthand for "all of them" and is closer to "anybody", which is worth a
// test of its own so that nobody changes its meaning by accident.
func TestAnyKeyAcceptsEverything(t *testing.T) {
	c := Config{Keys: []string{"*"}}
	if !c.AcceptsAnyKey() {
		t.Fatal("\"*\" should accept any key")
	}

	opts, err := c.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected one option, got %d", len(opts))
	}

	// A key that is on no list is still accepted.
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(key)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if !accepts(t, opts, sshPub) {
		t.Error("a key that is on no list was refused")
	}
}

// It has to be the only thing that changes: keys alongside it still work, and
// a list without it is still a list.
func TestAnyKeyAlongsideRealKeys(t *testing.T) {
	withStar := Config{Keys: []string{"ssh-ed25519 " + strings.TrimSpace(mustKey(t)) + " someone", "*"}}
	if !withStar.AcceptsAnyKey() {
		t.Error("a list containing * should accept any key")
	}

	withoutStar := Config{Keys: []string{"ssh-ed25519 " + strings.TrimSpace(mustKey(t)) + " someone"}}
	if withoutStar.AcceptsAnyKey() {
		t.Error("a list without * should not accept any key")
	}
	if !withoutStar.Enabled() {
		t.Error("a list of real keys is still authentication")
	}
}

func accepts(t *testing.T, opts []ssh.Option, key gossh.PublicKey) bool {
	t.Helper()

	srv := &ssh.Server{}
	for _, opt := range opts {
		if err := opt(srv); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	if srv.PublicKeyHandler == nil {
		t.Fatal("no public key handler was installed")
	}
	return srv.PublicKeyHandler(nil, key)
}

func mustKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	return string(gossh.MarshalAuthorizedKey(sshPub))
}
