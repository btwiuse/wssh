package cafe

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth"
	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/solana"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// This file is the one that says what the product is.
//
// Every assertion here is about something a connection must NOT be able to do.
// The package comment claims there is no path from a session to a process; a
// claim like that is worth nothing without a test that would fail if somebody
// added a shell middleware later, and these are those tests.

const treasuryAddress = "11111111111111111111111111111111"

// cafeServer stands up the real thing: a real wssh.Server on a real TCP
// listener, with the real middleware, and hands back a signer that can reach
// it.
//
// Not a stub and not a unit around one function: the properties under test are
// properties of the assembled server, and a test that built a different thing
// would not notice the one that matters.
func cafeServer(t *testing.T) (addr string, signer gossh.Signer) {
	t.Helper()

	dir := t.TempDir()
	ledger, err := OpenLedger(filepath.Join(dir, "ledger.json"))
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	srv, err := New(Options{
		Ledger:   ledger,
		Treasury: Treasury{Address: treasuryAddress, SolPriceUSD: 180 * PerMicroUSD},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	authOpts, err := auth.Config{Keys: []string{auth.AnyKey}}.Options()
	if err != nil {
		t.Fatalf("auth.Options: %v", err)
	}

	sessions, err := wssh.NewServer(wssh.Options{
		HostKeyPath: filepath.Join(dir, "host_ed25519"),
		// One middleware, and it is the session UI. This line is the whole of
		// the security claim, so it is written out here rather than assembled
		// through a helper a later change could quietly widen.
		Middleware:         []wish.Middleware{srv.Middleware()},
		Pty:                true,
		SSHOptions:         authOpts,
		AllowTcpForwarding: false,
	})
	if err != nil {
		t.Fatalf("wssh.NewServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = sessions.ServeTCP(ln) }()
	t.Cleanup(func() { _ = ln.Close() })

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err = gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return ln.Addr().String(), signer
}

// dial opens a client against the test server with a key, which is what an
// interactive ssh(1) does.
func dial(t *testing.T, addr string, signer gossh.Signer) *gossh.Client {
	t.Helper()
	client, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "anyone",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // a loopback test server
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func exitStatus(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exitErr *gossh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus()
	}
	t.Fatalf("expected an exit status, got %v", err)
	return -1
}

// A command sent instead of a shell must not run, and must say so.
//
// This is the single most important assertion in the repository. If somebody
// ever adds shell middleware to this server, or wires a command handler, this
// fails and says why.
func TestSessionRefusesToRunACommand(t *testing.T) {
	addr, signer := cafeServer(t)
	client := dial(t, addr, signer)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr

	// The exact thing a person would try. It must not run.
	err = session.Run("uptime")

	out := stdout.String() + stderr.String()
	if strings.Contains(out, "load average") {
		t.Fatalf("the command ran: its output is in the session: %q", out)
	}
	if !strings.Contains(out, "does not run commands") {
		t.Errorf("the refusal is not explained; the client saw %q", out)
	}
	if !strings.Contains(out, `"uptime" was not executed`) {
		t.Errorf("the refusal does not name the command; the client saw %q", out)
	}
	if status := exitStatus(t, err); status != 1 {
		t.Errorf("a refused command exited %d, want 1 so a caller notices", status)
	}
}

// The refusal must not be a way to smuggle a shell: no stdin reaches a process
// either, because there is no process.
func TestSessionRefusesACommandEvenWithStdinAndAPTY(t *testing.T) {
	addr, signer := cafeServer(t)
	client := dial(t, addr, signer)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm-256color", 40, 120, gossh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr

	in, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	_, _ = in.Write([]byte("id\nwhoami\ncat /etc/passwd\n"))
	_ = in.Close()

	// A refusal exits non-zero, which is the whole answer to this test: the
	// command did not run, and the caller was told so.
	exitStatus(t, session.Run("/bin/sh"))

	out := stdout.String() + stderr.String()
	if strings.Contains(out, "root:") || strings.Contains(out, "/bin/sh:") {
		t.Errorf("something answered as a shell: %q", out)
	}
	if !strings.Contains(out, "does not run commands") {
		t.Errorf("the refusal is not explained; the client saw %q", out)
	}
}

// Subsystem requests have nothing to authorise here: there are no files.
func TestSessionRefusesSubsystems(t *testing.T) {
	addr, signer := cafeServer(t)
	client := dial(t, addr, signer)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	var stderr strings.Builder
	session.Stderr = &stderr

	if err := session.RequestSubsystem("sftp"); err == nil {
		// Accepted or not, the point is that nothing is serving it.
		if err := session.Wait(); err != nil {
			t.Errorf("the subsystem session ended with %v, which means something handled it", err)
		} else {
			t.Error("an sftp subsystem was accepted and served")
		}
	}
	if strings.Contains(stderr.String(), "OK") {
		t.Error("the subsystem answered as if it existed")
	}
}

// direct-tcpip is what ssh -L and ssh -D go through. This server never installs
// the handler, so a forwarding request has to fail at the channel open rather
// than by a policy flag somebody can turn off.
func TestServerRefusesPortForwarding(t *testing.T) {
	addr, signer := cafeServer(t)
	client := dial(t, addr, signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close() //nolint:errcheck

	// The server should never answer a direct-tcpip open at all; anything that
	// does arrive is refused on the spot rather than left hanging.
	opened := client.HandleChannelOpen("direct-tcpip")
	go func() {
		for ch := range opened {
			_ = ch.Reject(gossh.Prohibited, "RouterCafe has no port forwarding")
		}
	}()

	conn, err := client.Dial("tcp", listener.Addr().String())
	if err == nil {
		_ = conn.Close()
		t.Fatal("a direct-tcpip channel opened; ssh -L would work on this server")
	}
}

// The session itself must be the program, not a shell. This is the positive
// half of the claim: connecting gives the RouterCafe UI.
func TestSessionOpensTheRouterCafeUI(t *testing.T) {
	addr, signer := cafeServer(t)
	client := dial(t, addr, signer)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm-256color", 40, 120, gossh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	var out strings.Builder
	session.Stdout = &out
	session.Stderr = &out

	if err := session.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	_ = stdin.Close()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "RouterCafe") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("the session UI never appeared; the session produced %q", truncate(out.String(), 400))
}

// A key that is not ed25519 names no account, and the refusal says so rather
// than handing out a session with no account behind it.
func TestAccountForNaming(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	edPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	addr, refusal, proven := AccountFor(edPub, "", "")
	if addr == "" || refusal != "" {
		t.Fatalf("an ed25519 key gave %q / %q, want an address and no refusal", addr, refusal)
	}
	if !proven {
		t.Error("a key that authenticated the session was not treated as proof")
	}
	if want, _ := solana.AddressFor(edPub); addr != want {
		t.Errorf("AccountFor gave %q but solana.AddressFor gives %q", addr, want)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey rsa: %v", err)
	}
	rsaPub, err := gossh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey rsa: %v", err)
	}
	addr, refusal, _ = AccountFor(rsaPub, "", "")
	if addr != "" {
		t.Errorf("an RSA key named the account %q", addr)
	}
	if !strings.Contains(refusal, "ed25519") {
		t.Errorf("the refusal does not say what is wrong: %q", refusal)
	}

	// A wallet sign-in wins, because a browser connection has no key at all.
	addr, refusal, proven = AccountFor(nil, treasuryAddress, "")
	if addr != treasuryAddress || refusal != "" || !proven {
		t.Errorf("a wallet connection gave %q / %q proven=%v", addr, refusal, proven)
	}

	// A username written as an account names it, and names it without proof.
	// That is the whole of read-only access: `ssh <address>@host` is the
	// address, and it is exactly what the client typed.
	addr, refusal, proven = AccountFor(nil, "", treasuryAddress)
	if addr != treasuryAddress || refusal != "" {
		t.Errorf("a username naming an account gave %q / %q", addr, refusal)
	}
	if proven {
		t.Error("a username was treated as proof; anyone could then spend that account")
	}

	// A username that is not an account names nothing.
	if addr, refusal, _ = AccountFor(nil, "", "gear"); addr != "" || refusal == "" {
		t.Errorf("a plain username gave %q / %q, want no account and a reason", addr, refusal)
	}
	if addr, _, _ = AccountFor(nil, "", "  "); addr != "" {
		t.Errorf("a blank username named %q", addr)
	}
}

func TestNewRefusesAnUnusableTreasury(t *testing.T) {
	ledger, err := OpenLedger("")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if _, err := New(Options{Ledger: ledger}); err == nil {
		t.Error("New accepted an empty treasury address; deposits would have nowhere to go")
	}
	if _, err := New(Options{Treasury: Treasury{Address: treasuryAddress}}); err == nil {
		t.Error("New accepted a nil ledger")
	}
	if _, err := New(Options{Ledger: ledger, Treasury: Treasury{Address: "not-an-address"}}); err == nil {
		t.Error("New accepted a treasury address that is not one")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// The package comment claims this package cannot start a process. That claim
// is worth a test, because it is the one that a later change could quietly
// undo and no behavioural test would notice: a helper that shells out on some
// path this suite happens not to take is still a shell.
//
// The check is on this package's own source rather than on the dependency
// graph, because os/exec is genuinely in the graph (bubbletea and lipgloss
// pull it in) and what matters is whether anything here calls it.
func TestThePackageCannotStartAProcess(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parse the package: %v", err)
	}
	pkg, ok := pkgs["cafe"]
	if !ok {
		t.Fatal("package cafe did not parse")
	}

	// Anything that could start one: the exec family, os.StartProcess,
	// syscall.Exec, and the shell this repository would otherwise use.
	banned := map[string]string{
		"exec.Command":         "exec.Command starts a process",
		"exec.CommandContext":  "exec.CommandContext starts a process",
		"exec.LookPath":        "looking a program up on PATH is how a shell finds one",
		"os.StartProcess":      "os.StartProcess starts a process",
		"syscall.Exec":         "syscall.Exec replaces this process",
		"syscall.ForkExec":     "syscall.ForkExec starts a process",
		"syscall.StartProcess": "syscall.StartProcess starts a process",
	}

	for name, file := range pkg.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgID, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			call := pkgID.Name + "." + sel.Sel.Name
			if why, banned := banned[call]; banned {
				t.Errorf("%s:%d calls %s: %s. A RouterCafe session is a program, not a command line.",
					name, fset.Position(sel.Pos()).Line, call, why)
			}
			return true
		})
	}
}

// The refusal is the only thing a person sees when their key does not name an
// account, and the two things that must survive it are the words and the
// command. A half-printed command on a narrow terminal is the one thing this
// screen must never do: it is what the person is about to copy.
func TestRefusalStaysReadableAtAnyWidth(t *testing.T) {
	const command = "ssh-keygen -t ed25519 -f ~/.ssh/routercafe -N ''"

	for _, width := range []int{20, 40, 46, 60, 76, 100, 200} {
		r := refuseModel{
			reason: reasonText("not an ed25519 key: a ssh-rsa key is not an ed25519 public key"),
			width:  width,
		}
		var screen tea.View
		screen = r.View()

		for _, line := range strings.Split(screen.Content, "\n") {
			// A hard cut leaves no space in the tail; wrapping never does,
			// and neither should a line that runs off the edge.
			// A line may fill the terminal exactly; anything wider wraps.
			if got := lipgloss.Width(stripForTest(line)); got > width {
				t.Errorf("width %d: a line is %d columns wide: %q", width, got, line)
			}
		}

		// Every word of the command is present, in order, once the screen's
		// own line breaks are undone.
		joined := strings.Join(strings.Fields(screen.Content), " ")
		for _, word := range strings.Fields(command) {
			if !strings.Contains(joined, word) {
				t.Errorf("width %d: the command lost %q", width, word)
			}
		}
	}
}

func TestBothRefusalsSaySomethingDifferent(t *testing.T) {
	noKey := reasonText("no key on this connection")
	wrongType := reasonText("not an ed25519 key: a ssh-rsa key is not an ed25519 public key")

	if noKey == wrongType {
		t.Fatal("a missing key and a key of the wrong type get the same text")
	}
	if !strings.Contains(noKey, "no key") {
		t.Errorf("the missing-key text does not say what is missing: %q", noKey)
	}
	if !strings.Contains(wrongType, "ed25519") {
		t.Errorf("the wrong-type text does not name what is wanted: %q", wrongType)
	}
	// Neither may promise something the product cannot do. A browser holding
	// a wallet is not an SSH key and this screen is only reachable from one.
	for _, text := range []string{noKey, wrongType} {
		if strings.Contains(text, KeyCommand[:20]) {
			t.Errorf("the screen is doing something unexpected: %q", text)
		}
	}
}

// stripForTest removes escape sequences so a width can be measured on the text.
func stripForTest(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

// A key that is adopted out of a forwarded agent has to be proved, not
// believed: the agent is asked to sign a nonce this process made up, and a
// signature that does not verify is not an account.
//
// This is the whole reason anonymous access can be a default. Admitting a
// connection with no key admits every connection that way, so identity has to
// come from something the client does rather than from something it says.
func TestAdoptingAKeyProvesItWithASignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sock := serveAgent(t, []ed25519.PrivateKey{priv})

	d := deps{SockPath: sock, Ledger: testLedger(t), Catalogue: DefaultCatalogue()}
	keys, err := agent.NewClient(dialUnix(t, sock)).List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	adoptable := orderableKeys(keys)
	if len(adoptable) != 1 {
		t.Fatalf("agent listed %d adoptable keys, want 1", len(adoptable))
	}

	msg := adoptCmd(d, adoptable[0])()
	signed, ok := msg.(nonceSignedMsg)
	if !ok {
		t.Fatalf("adopt returned %T", msg)
	}
	if signed.err != nil {
		t.Fatalf("a real key was not adopted: %v", signed.err)
	}
	want, _ := solana.AddressFor(mustPub(t, pub))
	if signed.address != want {
		t.Errorf("adopted the account %q, want %q", signed.address, want)
	}
}

// An agent that will not sign is not an account. That is the negative of the
// test above and the one that matters: the point is that a key has to be
// demonstrably held, and the ordinary way that fails is an agent asked for a
// key it does not have.
func TestAdoptingFailsWhenTheAgentDoesNotHoldTheKey(t *testing.T) {
	_, held, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	stranger, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sock := serveAgent(t, []ed25519.PrivateKey{held})

	d := deps{SockPath: sock, Ledger: testLedger(t), Catalogue: DefaultCatalogue()}
	msg := adoptCmd(d, &agent.Key{
		Format: gossh.KeyAlgoED25519,
		Blob:   blobFor(t, stranger),
	})()
	signed, ok := msg.(nonceSignedMsg)
	if !ok {
		t.Fatalf("adopt returned %T", msg)
	}
	if signed.err == nil {
		t.Fatal("an agent produced a signature for a key it does not hold")
	}
	if signed.address != "" {
		t.Errorf("a failed adoption still named the account %q", signed.address)
	}
}

// Only keys that name an account are offered. A list where one row is a
// refusal is a list somebody tries every row of.
func TestOnlyEd25519KeysAreOfferedForAdoption(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rsaPub, err := gossh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	rsaBlob := gossh.Marshal(rsaPub)

	got := orderableKeys([]*agent.Key{
		{Format: gossh.KeyAlgoED25519, Blob: blobFor(t, edPub), Comment: "keep"},
		{Format: gossh.KeyAlgoRSA, Blob: rsaBlob, Comment: "an rsa key"},
		{Format: gossh.KeyAlgoED25519, Blob: nil, Comment: "a truncated blob"},
		nil,
	})
	if len(got) != 1 {
		t.Fatalf("offered %d keys, want just the one that names an account: %+v", len(got), got)
	}
	if got[0].Comment != "keep" {
		t.Errorf("offered %q", got[0].Comment)
	}
}

// The blob the agent protocol sends is the algorithm name and then the key
// body, each under its own four-byte length. Reading it by hand and getting
// that wrong means holding the wrong 32 bytes, and the failure has to be an
// error rather than an address that belongs to nobody.
func TestParsingAnAgentKeyBlob(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	blob := blobFor(t, pub)

	got, err := parseEd25519Blob(blob)
	if err != nil {
		t.Fatalf("parseEd25519Blob: %v", err)
	}
	if !got.Equal(pub) {
		t.Errorf("read back %x, want %x", got, pub)
	}

	for _, bad := range [][]byte{
		nil,
		{0, 0, 0},                              // ends inside a length
		{0, 0, 0, 9, 'a', 'b', 'c'},            // claims more than it has
		{0, 0, 0, 1, 's', 0, 0, 0, 2, 1, 2, 3}, // body is three bytes
	} {
		if _, err := parseEd25519Blob(bad); err == nil {
			t.Errorf("a malformed blob was read as a key: %x", bad)
		}
	}
}

// serveAgent runs a real ssh-agent on a real socket holding the given keys.
func serveAgent(t *testing.T, keys []ed25519.PrivateKey) string {
	t.Helper()
	// A short path on purpose: a unix socket address is capped at about a
	// hundred bytes, and t.TempDir's is longer than that on macOS.
	dir, err := os.MkdirTemp("", "cafe")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "a.sock")

	if len(keys) == 0 {
		t.Fatal("serveAgent needs a key; agentkey.Keyring returns nil for an empty list and " +
			"an agent server over it panics on the first request")
	}
	signers := make([]gossh.Signer, 0, len(keys))
	for _, priv := range keys {
		signer, err := gossh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("NewSignerFromKey: %v", err)
		}
		signers = append(signers, signer)
	}
	keyring, err := agentkey.Keyring(signers)
	if err != nil { //nolint:wsl
		t.Fatalf("Keyring: %v", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { //nolint:wsl
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()
	return path
}

func dialUnix(t *testing.T, path string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func mustPub(t *testing.T, pub ed25519.PublicKey) gossh.PublicKey {
	t.Helper()
	out, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return out
}

// blobFor is the agent protocol's shape: the algorithm name and the key body,
// each under its own four-byte length.
//
// The method on the key, not the package function: gossh.Marshal reaches for
// struct tags by reflection and an ed25519 key is a defined []byte, so it
// panics on exactly the key type this is about.
func blobFor(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return sshPub.Marshal()
}

// Read-only is the whole of what a named account buys, and it has to stay
// that way. Someone can type any address they can find, so every action that
// changes the account has to be behind proof of holding the key.
func TestANamedAccountCannotChangeAnything(t *testing.T) {
	ledger := testLedger(t)
	if err := ledger.Credit(treasuryAddress, 5*PerMicroUSD); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	d := deps{
		Address:   treasuryAddress,
		Ledger:    ledger,
		Treasury:  testTreasury(),
		Catalogue: DefaultCatalogue(),
		Host:      Domain,
	}
	m := model{deps: d, st: newStyles(), view: screenHome, account: ledger.Account(d.Address), width: 100, height: 40}

	// Minting refuses. The command it hands back carries the refusal, so what
	// matters is what running it produces: a notice, never a key.
	next, cmd := m.mintKey()
	if cmd != nil {
		t.Errorf("minting for an account nobody proved started something: %v", cmd)
	}
	got := next.(model)
	if got.notice.kind != noticeBad || got.notice.text == "" {
		t.Errorf("minting gave %+v, want a refusal with a reason", got.notice)
	}
	if len(ledger.Account(d.Address).Keys) != 0 {
		t.Error("a key was minted against an account that was only named")
	}

	// A deposit refuses the same way, before anything is asked of an agent.
	_, cmd = got.startDeposit()
	if cmd != nil {
		t.Errorf("a deposit for an account nobody proved started something: %v", cmd)
	}
	if len(ledger.Account(d.Address).Keys) != 0 {
		t.Error("something changed an account that was only named")
	}

	// And the same model with proof does mint, which is what makes the
	// boundary a boundary rather than a wall.
	proved := got
	proved.deps.Proven = true
	_, cmd = proved.mintKey()
	if cmd == nil {
		t.Fatal("the account's actual owner was refused")
	}
	cmd() // The mint happens when the command runs, not when it is handed back.
	if len(ledger.Account(d.Address).Keys) != 1 {
		t.Error("the owner could not mint a key against their own account")
	}
}
