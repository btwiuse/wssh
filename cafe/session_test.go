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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth"
	"github.com/btwiuse/wssh/solana"
	gossh "golang.org/x/crypto/ssh"
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
	addr, refusal := AccountFor(edPub, "")
	if addr == "" || refusal != "" {
		t.Fatalf("an ed25519 key gave %q / %q, want an address and no refusal", addr, refusal)
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
	addr, refusal = AccountFor(rsaPub, "")
	if addr != "" {
		t.Errorf("an RSA key named the account %q", addr)
	}
	if !strings.Contains(refusal, "ed25519") {
		t.Errorf("the refusal does not say what is wrong: %q", refusal)
	}

	// A wallet sign-in wins, because a browser connection has no key at all.
	addr, refusal = AccountFor(nil, treasuryAddress)
	if addr != treasuryAddress || refusal != "" {
		t.Errorf("a wallet connection gave %q / %q", addr, refusal)
	}

	// And neither is nothing: an unauthenticated connection names nobody.
	if addr, refusal = AccountFor(nil, ""); addr != "" || refusal == "" {
		t.Errorf("an unauthenticated connection gave %q / %q, want no account and a reason", addr, refusal)
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
