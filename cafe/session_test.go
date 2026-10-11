package cafe

import (
	"context"
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

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"charm.land/wish/v2"
	"github.com/routercafe/routercafe"
	"github.com/routercafe/routercafe/auth"
	"github.com/routercafe/routercafe/auth/agentkey"
	"github.com/routercafe/routercafe/solana"
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

// A username naming an account wins over the key the connection authenticated
// with, and this is the case that only exists now that "none" is refused.
//
// Nearly every connection carries a key now, because refusing "none" is what
// lets the server see one. If the key won, `ssh <someone-else>@host` would open
// the account of whoever was holding the connection and say nothing - the worst
// possible answer, because it is a real balance belonging to somebody else.
func TestANamedUsernameOutranksTheKeyThatAuthenticated(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	edPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	addr, refusal, proven := AccountFor(edPub, "", treasuryAddress)
	if addr != treasuryAddress || refusal != "" {
		t.Fatalf("gave %q / %q, want the account that was named", addr, refusal)
	}
	if proven {
		t.Error("naming an account proved it; the key on the connection was never checked against it")
	}

	// A username that is not an account changes nothing: the key is still the
	// account, still proved, because nothing was asked for.
	addr, refusal, proven = AccountFor(edPub, "", "gear")
	want, _ := solana.AddressFor(edPub)
	if addr != want || refusal != "" || !proven {
		t.Errorf("a plain username gave %q / %q proven=%v, want the key's own account", addr, refusal, proven)
	}
}

// The help screen says which server this is. It is the screen somebody goes
// to when they need to know, and the answer has to come from the server
// rather than from the binary the client happens to have.
//
// A build with no version ldflags must say nothing at all: a blank line, or a
// bare "dev", reads as a bug rather than as an unversioned build.
func TestTheHelpScreenSaysWhichServerThisIs(t *testing.T) {
	m := model{st: newStyles(), width: 100, deps: deps{Version: "0.1.0"}}
	if got := m.renderHelp(); !strings.Contains(got, "server version 0.1.0") {
		t.Errorf("the help screen does not say the version:\n%s", got)
	}

	for _, none := range []string{"", "   ", "dev"} {
		got := model{st: newStyles(), width: 100, deps: deps{Version: none}}.renderHelp()
		if strings.Contains(got, "server version") {
			t.Errorf("an unversioned build (%q) printed a version line", none)
		}
	}
}

// The version has to survive the trip from Options to the model, which is
// the same deps plumbing every other session fact rides.
func TestVersionReachesTheAccountScreenFromOptions(t *testing.T) {
	srv, err := New(Options{
		Ledger:   testLedger(t),
		Treasury: testTreasury(),
		Version:  "9.9.9",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.opts.Version != "9.9.9" {
		t.Errorf("the version did not survive: %q", srv.opts.Version)
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

// A typed address opens an account read-only. This is the whole of what the
// no-key screen is for, and the whole of what it must not do is prove it: the
// session that opens here is the same one `ssh <address>@host` opens, which can
// look at a balance and cannot spend one.
func TestATypedAddressOpensAnAccountWithoutProvingIt(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	address, err := solana.AddressFor(mustPub(t, pub))
	if err != nil {
		t.Fatalf("AddressFor: %v", err)
	}

	m := anonymousModel{deps: deps{Ledger: testLedger(t)}, width: 80, height: 24}
	for _, c := range address {
		next, _ := m.onKey(tea.KeyPressMsg(tea.Key{Code: c, Text: string(c)}))
		m = next.(anonymousModel)
	}
	if m.typed != address {
		t.Fatalf("typed %q, want %q", m.typed, address)
	}

	next, _ := m.openAddress()
	got, ok := next.(model)
	if !ok {
		t.Fatalf("a typed address opened %T, want the account screen", next)
	}
	if got.deps.Address != address {
		t.Errorf("opened the account %q, want %q", got.deps.Address, address)
	}
	if got.deps.Proven {
		t.Error("typing an address proved it; a named account is a view")
	}
}

// An address that cannot be one is refused in place. The session stays on the
// screen that can be typed at, because that is where the correction goes.
func TestAnAddressThatCannotBeOneIsRefusedInPlace(t *testing.T) {
	m := anonymousModel{
		deps:   deps{Ledger: testLedger(t)},
		width:  80,
		height: 24,
		typed:  "not-an-address",
		notice: notice{},
	}
	next, _ := m.openAddress()
	if _, ok := next.(model); ok {
		t.Fatal("an invalid address opened an account")
	}
	got := next.(anonymousModel)
	if got.notice.kind != noticeBad {
		t.Errorf("refusing an invalid address said %+v", got.notice)
	}
}

// The address row is always the last row and always reachable, and typing moves
// the selection to it. A person who has started typing must not have to know
// which row they were on, which is also why q types a q here instead of
// quitting: it is a base58 character and the field is most of the screen.
func TestTypingMovesTheSelectionToTheAddressRow(t *testing.T) {
	key := &agent.Key{Format: gossh.KeyAlgoED25519, Comment: "me"}
	m := anonymousModel{
		deps:  deps{Ledger: testLedger(t)},
		keys:  []*agent.Key{key},
		width: 80, height: 24,
	}
	if m.rows() != 2 {
		t.Fatalf("a screen with one key offers %d rows, want the key and the address", m.rows())
	}

	// Printable characters go to the field, wherever the selection was.
	next, _ := m.onKey(tea.KeyPressMsg(tea.Key{Code: 'q', Text: "q"}))
	m = next.(anonymousModel)
	if m.typed != "q" {
		t.Fatalf("typed %q, want q", m.typed)
	}
	if m.picked != m.addressRow() {
		t.Errorf("typing left the selection on row %d, want the address row %d", m.picked, m.addressRow())
	}

	// Characters base58 leaves out never reach the field, so there is no state
	// in which it holds something ValidateAddress is about to refuse.
	for _, c := range []string{"0", "O", "I", "l", "-", " "} {
		next, _ := m.onKey(tea.KeyPressMsg(tea.Key{Code: rune(c[0]), Text: c}))
		m = next.(anonymousModel)
		if m.typed != "q" {
			t.Fatalf("typing %q changed the field to %q", c, m.typed)
		}
	}
}

// esc clears a field that has something in it and quits when it does not. The
// asymmetry is the point: quitting by accident throws away what was typed.
func TestEscapeClearsTheFieldBeforeItQuits(t *testing.T) {
	esc := tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape})
	m := anonymousModel{deps: deps{Ledger: testLedger(t)}, width: 80, height: 24, typed: "abc"}

	next, cmd := m.onKey(esc)
	if cmd != nil {
		t.Error("escape quit a session that had an address typed into it")
	}
	m = next.(anonymousModel)
	if m.typed != "" {
		t.Errorf("escape left %q in the field", m.typed)
	}
	if _, cmd := m.onKey(esc); cmd == nil {
		t.Error("escape on an empty field did not quit")
	}
}

// ctrl+c is the only key that always quits, because on this screen almost
// every other character is something to type.
func TestControlCQuitsEvenMidAddress(t *testing.T) {
	m := anonymousModel{deps: deps{Ledger: testLedger(t)}, width: 80, height: 24, typed: "abc"}
	if _, cmd := m.onKey(tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl})); cmd == nil {
		t.Error("ctrl+c did not quit")
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

// The key a session just minted is the only one it will ever see: the ledger
// kept a digest and threw the key away. So y has to work right after a mint,
// and it has to stop working the moment the key is off the screen - which is
// the only way "copy it" and "you can still see it" cannot drift apart.
func TestCopyingAKeyOnlyWhileItIsOnScreen(t *testing.T) {
	ledger := testLedger(t)
	d := deps{
		Address:   treasuryAddress,
		Ledger:    ledger,
		Treasury:  testTreasury(),
		Catalogue: DefaultCatalogue(),
		Proven:    true,
		Host:      Domain,
	}
	// focus is set because a list arrives focused; this test wants to leave
	// the page in one press, not two.
	m := model{deps: d, st: newStyles(), view: screenKeys, focus: true,
		account: ledger.Account(d.Address), width: 100, height: 40}
	m.syncLists()

	// Minting clears any previous key, so the one on screen is always the only
	// one on screen.
	next, cmd := m.mintKey()
	m = next.(model)
	minted, ok := cmd().(keyMintedMsg)
	if !ok || minted.err != nil {
		t.Fatalf("mint gave %+v", minted)
	}
	next, _ = m.Update(minted)
	m = next.(model)
	if m.fresh != minted.key {
		t.Fatalf("the minted key is not on the model: %q vs %q", m.fresh, minted.key)
	}

	// y asks for the clipboard, which is tea.SetClipboard - a command, because
	// that is how Bubble Tea writes an escape sequence without fighting the
	// renderer for stdout.
	next, cmd = m.copyFreshKey()
	if cmd == nil {
		t.Fatal("y on a key that is on screen did nothing")
	}
	if msg := cmd(); msg == nil {
		t.Error("the clipboard command produced no message")
	}
	if got := next.(model); got.notice.kind != noticeGood {
		t.Errorf("copying said %+v, want a confirmation", got.notice)
	}

	// Leaving the screen takes the key with it.
	next, _ = m.onKey(tea.KeyPressMsg(tea.Key{Code: tea.KeyTab}))
	m = next.(model)
	if m.fresh != "" {
		t.Error("a key was still copyable after the screen that showed it was left")
	}
	next, cmd = m.copyFreshKey()
	if cmd != nil {
		t.Error("y copied a key that was never displayed again")
	}
	if got := next.(model); got.notice.kind != noticeBad {
		t.Errorf("y with nothing on screen said %+v, want a refusal saying why", got.notice)
	}
}

// The footer advertises y only when there is something to copy. A binding that
// is always offered and usually refused is one people learn to ignore.
func TestCopyIsOnlyOfferedWhenThereIsSomethingToCopy(t *testing.T) {
	m := model{st: newStyles(), deps: deps{Catalogue: DefaultCatalogue()}, width: 100}
	if strings.Contains(m.footer(), "copy key") {
		t.Error("y is offered with no key on screen")
	}
	m.fresh = "rc_live_abc"
	if !strings.Contains(m.footer(), "copy key") {
		t.Error("y is not offered with a key on screen")
	}
}

// Tab is the navigation, and it walks a ring rather than a list of shortcuts:
// this page's widget, then the next page. A list arrives already focused,
// because hjkl is only ever wanted by something looking at a list. An amount
// field arrives cold, which is the whole reason it was given focus.
func TestTabWalksTheRingAndOnlyTakesTheAmountWhenAsked(t *testing.T) {
	m := model{st: newStyles(), view: screenHome, deps: deps{Catalogue: DefaultCatalogue(), Proven: true}, width: 100, height: 40}
	m.syncLists()

	// From the balance screen, one tab lands on the deposit screen without
	// touching the amount: there is no widget to take yet.
	next, _ := m.onKey(tea.KeyPressMsg(tea.Key{Code: tea.KeyTab}))
	m = next.(model)
	if m.view != screenDeposit {
		t.Fatalf("tab from balance went to %v, want deposit", m.view)
	}
	if m.focus {
		t.Error("arriving at the deposit screen focused the amount; it eats keystrokes")
	}

	// The next tab takes the caret, and only then do digits type.
	next, _ = m.onKey(tea.KeyPressMsg(tea.Key{Code: tea.KeyTab}))
	m = next.(model)
	if !m.focus {
		t.Fatal("tab did not put the caret in the amount")
	}
	next, _ = m.onKey(tea.KeyPressMsg(tea.Key{Code: '3', Text: "3"}))
	m = next.(model)
	if m.amount != "3" {
		t.Errorf("typed %q into the amount, want 3", m.amount)
	}

	// A third tab leaves the page entirely, and the amount goes with it.
	next, _ = m.onKey(tea.KeyPressMsg(tea.Key{Code: tea.KeyTab}))
	m = next.(model)
	if m.view != screenKeys || m.amount != "" {
		t.Errorf("tab landed on %v with amount %q, want the api keys and nothing typed", m.view, m.amount)
	}

	// And a list arrives live, so hjkl works with no press at all.
	next, _ = m.onKey(tea.KeyPressMsg(tea.Key{Code: 'j', Text: "j"}))
	if got := next.(model).routes.Index(); got != 0 {
		t.Errorf("the routes list arrived with the cursor on row %d, want the first", got)
	}

	// shift+tab goes back the way it came, around the end included.
	next, _ = m.onKey(tea.KeyPressMsg(tea.Key{Code: tea.KeyTab, Mod: tea.ModShift}))
	m = next.(model)
	if m.view != screenDeposit {
		t.Errorf("shift+tab went to %v, want back to deposit", m.view)
	}
	m = m.show(screenHome)
	next, _ = m.onKey(tea.KeyPressMsg(tea.Key{Code: tea.KeyTab, Mod: tea.ModShift}))
	if got := next.(model).view; got != screenHelp {
		t.Errorf("shift+tab off the end went to %v, want it to wrap to help", got)
	}
}

// esc and tab have to mean different things now, or the fix is just a rename:
// while the field has the caret, esc puts it down without leaving the screen.
func TestEscapeBlursTheFieldRatherThanLeavingTheScreen(t *testing.T) {
	m := model{
		st: newStyles(), view: screenDeposit, focus: true, amount: "1.5",
		deps: deps{Catalogue: DefaultCatalogue()}, width: 100,
	}
	next, _ := m.onKey(tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape}))
	got := next.(model)
	if got.view != screenDeposit {
		t.Errorf("escape left the deposit screen for %v", got.view)
	}
	if got.focus {
		t.Error("escape left the field focused")
	}
	if got.amount != "1.5" {
		t.Errorf("escape cleared the amount to %q", got.amount)
	}

	// With nothing focused, escape has nothing to undo: there are no page
	// shortcuts left to back out of, and leaving is ctrl+c or q.
	next, _ = got.onKey(tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape}))
	after := next.(model)
	if after.view != screenDeposit {
		t.Errorf("escape with nothing focused left the screen for %v", after.view)
	}
}

// A list arrives focused and an amount field does not, and that asymmetry is
// the whole of the navigation model rather than an inconsistency.
func TestArrivingAtAListFocusesItAndArrivingAtAFieldDoesNot(t *testing.T) {
	m := model{st: newStyles(), deps: deps{Catalogue: DefaultCatalogue(), Proven: true}, width: 100, height: 40}
	m.syncLists()

	for _, tc := range []struct {
		view screen
		want bool
	}{
		{screenKeys, true},
		{screenModels, true},
		{screenDeposit, false},
		{screenHome, false},
		{screenHelp, false},
	} {
		got := m.show(tc.view)
		if got.focus != tc.want {
			t.Errorf("arriving at %v focused=%v, want %v", tc.view, got.focus, tc.want)
		}
	}

	// Going back to the balance screen drops the focus, so nothing is left
	// lit that the next tab will not light again.
	if m.show(screenKeys).show(screenHome).focus {
		t.Error("the focus outlived the page that had it")
	}
}

// The field has to look like the focus is in it. Colour alone is not enough on
// a terminal with no colour at all, so the focused state also carries a cursor.
func TestTheAmountFieldLooksDifferentWhenFocused(t *testing.T) {
	m := model{st: newStyles(), view: screenDeposit, deps: deps{Catalogue: DefaultCatalogue()}, width: 100}
	// Unfocused, the field is quiet and carries no cursor: a caret sitting in
	// a field that is not taking keystrokes is a lie about where typing goes.
	if got := m.amountField(); strings.Contains(got, "\u2588") {
		t.Errorf("an unfocused field shows a cursor: %q", got)
	}

	m.focus, m.amount = true, "1.5"
	got := m.amountField()
	if !strings.Contains(got, "1.5") {
		t.Errorf("the focused field does not show what was typed: %q", got)
	}
	if !strings.Contains(got, "\u2588") {
		t.Errorf("the focused field shows no cursor: %q", got)
	}

	// Both states carry the amount, so the field is visibly the same thing
	// either way rather than appearing from nowhere when focused.
	m.focus = false
	if !strings.Contains(m.amountField(), "1.5") {
		t.Errorf("unfocusing the field hid what was typed: %q", m.amountField())
	}
}

// hjkl has to move the cursor, or the list is decoration. Update hands back a
// new list rather than moving this one, so a caller who drops it has a cursor
// that looks like it works and does nothing.
func TestTheListCursorMoves(t *testing.T) {
	m := model{
		st: newStyles(), view: screenModels, focus: true,
		deps: deps{Catalogue: DefaultCatalogue(), Proven: true}, width: 100, height: 40,
	}
	m.syncLists()
	if n := len(m.routes.Items()); n < 3 {
		t.Fatalf("the catalogue has %d routes, too few to move a cursor in", n)
	}

	for _, k := range []string{"j", "j", "k"} {
		next, _ := m.onKey(tea.KeyPressMsg(tea.Key{Code: rune(k[0]), Text: k}))
		m = next.(model)
	}
	if got := m.routes.Index(); got != 1 {
		t.Errorf("j j k left the cursor on row %d, want 1", got)
	}

	// g and G are the ends, which is what makes a long list navigable without
	// holding down a key.
	next, _ := m.onKey(tea.KeyPressMsg(tea.Key{Code: 'G', Text: "G"}))
	m = next.(model)
	if got, last := m.routes.Index(), len(m.routes.Items())-1; got != last {
		t.Errorf("G left the cursor on row %d of %d, want the last", got, last+1)
	}
	next, _ = m.onKey(tea.KeyPressMsg(tea.Key{Code: 'g', Text: "g"}))
	if got := next.(model).routes.Index(); got != 0 {
		t.Errorf("g left the cursor on row %d, want the first", got)
	}
}

// The whole reason for a hand-written keymap. A list that answered to b, d or
// u for paging would take three of the page shortcuts, and the footer at the
// bottom of every screen would be lying on the two screens where it matters
// most.
func TestAListCannotTakeAPageShortcut(t *testing.T) {
	keys := []string{"b", "d", "u", "f"}
	km := listKeyMap()
	bindings := []string{}
	for _, b := range []key.Binding{km.PrevPage, km.NextPage} {
		bindings = append(bindings, b.Keys()...)
	}
	for _, k := range keys {
		for _, bound := range bindings {
			if bound == k {
				t.Errorf("paging is bound to %q, which is a page shortcut here", k)
			}
		}
	}
	if got := km.Quit.Keys(); len(got) != 0 {
		t.Errorf("the list still answers to %v; q is this program's disconnect", got)
	}
	if got := km.Filter.Keys(); len(got) != 0 {
		t.Errorf("the list still answers to %v; a filter would want esc", got)
	}
}

// A list may not answer to q or ?: those belong to the program rather than to
// a widget, and a list that swallowed them would make q stop disconnecting
// and ? stop opening the help on exactly the two screens with a cursor in them.
func TestAListCannotTakeTheProgramsKeys(t *testing.T) {
	km := listKeyMap()
	if got := km.Quit.Keys(); len(got) != 0 {
		t.Errorf("the list answers to %v; q disconnects this program", got)
	}
	if got := km.ShowFullHelp.Keys(); len(got) != 0 {
		t.Errorf("the list answers to %v; ? opens this program's help", got)
	}
	if got := km.Filter.Keys(); len(got) != 0 {
		t.Errorf("the list answers to %v; a filter would want esc", got)
	}

	// Paging stays narrow on purpose. Nothing needs b, d, f or u any more -
	// there are no page shortcuts - but a list that takes four ways to page is
	// a list with four things to remember, and this is a program about money.
	page := append(km.PrevPage.Keys(), km.NextPage.Keys()...)
	for _, k := range []string{"b", "d", "f", "u"} {
		for _, bound := range page {
			if bound == k {
				t.Errorf("paging is bound to %q, which was left out deliberately", k)
			}
		}
	}
}

// Enter means different things on the two lists, and the one where it means
// nothing has to say so rather than sitting there looking like a dead key.
func TestEnterMeansSomethingDifferentOnEachList(t *testing.T) {
	ledger := testLedger(t)
	d := deps{
		Address: treasuryAddress, Ledger: ledger, Treasury: testTreasury(),
		Catalogue: DefaultCatalogue(), Proven: true, Host: Domain,
	}
	m := model{st: newStyles(), view: screenModels, focus: true, deps: d, width: 100, height: 40}
	m.syncLists()

	next, _ := m.onKey(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	got := next.(model)
	if got.notice.kind != noticeBad {
		t.Errorf("enter on the routes list gave %+v, want it to say a route is not chosen here", got.notice)
	}
}

// The cursor has to survive a refresh, or a background balance re-read moves
// the target out from under the enter that was about to follow it.
func TestRefreshingKeepsTheCursorOnTheSameKey(t *testing.T) {
	ledger := testLedger(t)
	for range 4 {
		if _, err := ledger.MintKey(treasuryAddress, ""); err != nil {
			t.Fatalf("MintKey: %v", err)
		}
	}
	d := deps{
		Address: treasuryAddress, Ledger: ledger, Treasury: testTreasury(),
		Catalogue: DefaultCatalogue(), Proven: true, Host: Domain,
	}
	m := model{st: newStyles(), view: screenKeys, deps: d, account: ledger.Account(treasuryAddress), width: 100, height: 40}
	m.syncLists()

	next, _ := m.onKey(tea.KeyPressMsg(tea.Key{Code: 'j', Text: "j"}))
	m = next.(model)
	m.apiKeys.Select(2)
	before := m.apiKeys.Index()

	next, _ = m.Update(refreshedMsg{account: ledger.Account(treasuryAddress)})
	if got := next.(model).apiKeys.Index(); got != before {
		t.Errorf("a refresh moved the cursor from %d to %d", before, got)
	}
}

// A local run has no SSH handshake and therefore no authenticated key, no
// username and no wallet - which is the shape of a connection that proved
// nothing. Both must be answered by the same rules and reach the same screen,
// or "works on my machine" becomes a way to bypass the proof that gates
// spending.
func TestALocalRunIsTheSameAsAConnectionThatProvedNothing(t *testing.T) {
	srv, err := New(Options{
		Ledger:         testLedger(t),
		Treasury:       testTreasury(),
		AllowAnonymous: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	local := srv.modelFor(who{ctx: context.Background(), local: true})
	if _, ok := local.(anonymousModel); !ok {
		t.Fatalf("a local run opened %T, want the screen a connection with no key gets", local)
	}

	// A connection that carried a key must not land in the same place, or the
	// local path would be a way to be nobody on purpose.
	remote := srv.modelFor(who{pub: mustEd25519(t), user: "gear", ctx: context.Background()})
	if _, ok := remote.(model); !ok {
		t.Fatalf("a connection with a key opened %T, want the account screen", remote)
	}

	// And the rules are the rules: an account named rather than proved still
	// cannot be changed, whichever way it was arrived at.
	address, refusal, proven := AccountFor(nil, "", treasuryAddress)
	if refusal != "" || proven {
		t.Errorf("a named address gave %q / proven=%v", refusal, proven)
	}
	if address != treasuryAddress {
		t.Errorf("a named address gave %q, want %q", address, treasuryAddress)
	}
}

// A local run takes its agent from the environment rather than a flag: the
// point of it is that there is nothing to set up, and a flag would have to be
// typed by somebody who already has a working agent.
func TestALocalRunFindsTheAgentThatIsAlreadyRunning(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	if got := LocalAgent(); got != "/tmp/agent.sock" {
		t.Errorf("LocalAgent gave %q, want the socket from the environment", got)
	}
	t.Setenv("SSH_AUTH_SOCK", "")
	if got := LocalAgent(); got != "" {
		t.Errorf("LocalAgent gave %q with no agent set, want empty rather than an error", got)
	}
}

func mustEd25519(t *testing.T) gossh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	out, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return out
}
