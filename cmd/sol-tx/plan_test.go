package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btwiuse/wssh/auth/agentkey"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// The plan is printed before anything is signed, so its whole job is to be
// true. Each case is checked against a real agent on a real socket, because
// what it reads - the key list and the labels on it - only exists on the wire.

// A browser that imported an SSH key and connected a wallet holds both, and
// the wallet is the one labelled `solana:<address>`. This is the case the
// whole thing was written for: two keys, and the two are not interchangeable,
// because only one of them can be asked.
func TestPlanNamesWhichKeyIsTheWallet(t *testing.T) {
	sock := serveAgent(t,
		agentkey.Key{Signer: newSigner(t), Comment: "ssh-ed25519 2026-10-10"},
		agentkey.Key{Signer: newSigner(t), Comment: agentkey.WalletCommentPrefix + "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"},
	)

	plan := planSigner(context.Background(), sock, "")
	if len(plan.lines) < 2 {
		t.Fatalf("plan is too short to say anything: %q", plan.lines)
	}
	if !strings.Contains(plan.lines[0], "the wallet will sign") {
		t.Errorf("the head does not say the wallet will be asked: %q", plan.lines[0])
	}

	joined := strings.Join(plan.lines, "\n")
	if !strings.Contains(joined, "ssh-ed25519 2026-10-10") {
		t.Errorf("the imported key's label is missing:\n%s", joined)
	}
	if !strings.Contains(joined, "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5") {
		t.Errorf("the wallet's account is missing:\n%s", joined)
	}
	// Marked on its own line, and only once: a label on the wrong key would
	// tell the reader the imported key is the wallet's, which is the exact
	// confusion this is meant to prevent.
	marked := 0
	for _, line := range plan.lines[1:] {
		if strings.Contains(line, "<- the wallet") {
			marked++
			if !strings.Contains(line, agentkey.WalletCommentPrefix) {
				t.Errorf("the wrong key is marked as the wallet: %q", line)
			}
		}
	}
	if marked != 1 {
		t.Errorf("%d keys are marked as the wallet, want 1:\n%s", marked, joined)
	}
}

// The wallet picks the account when it is asked, and that choice belongs to
// the person at the popup. The plan has to say who will sign - the wallet,
// which is settled - without claiming to know which of its accounts that
// will be. A plan that named an account here would be right today and wrong
// the moment somebody switched accounts in their wallet, which is the one
// thing this line is here to prevent.
func TestPlanSaysTheWalletSignsWithoutNamingItsAccount(t *testing.T) {
	wallet := "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"
	sock := serveAgent(t,
		agentkey.Key{Signer: newSigner(t), Comment: "ssh-ed25519 2026-10-10"},
		agentkey.Key{Signer: newSigner(t), Comment: agentkey.WalletCommentPrefix + wallet},
	)

	plan := planSigner(context.Background(), sock, "")
	joined := strings.Join(plan.lines, "\n")

	// Who signs: said, and it is the wallet.
	if !strings.Contains(joined, "the wallet will sign") {
		t.Errorf("the plan does not say who will sign:\n%s", joined)
	}
	// Which of the wallet's accounts: deferred to the popup, in as many words.
	if !strings.Contains(joined, "its prompt has selected") {
		t.Errorf("the plan does not leave the account to the wallet's prompt:\n%s", joined)
	}
	// The other key must be marked as not used, or the reader cannot tell
	// that the two entries are not equally likely.
	if !strings.Contains(joined, "unused unless --signer names it") {
		t.Errorf("the plan does not mark the other key as unused:\n%s", joined)
	}
}

// One key and no wallet: the agent will sign with it, and the plan says so.
func TestPlanWithOneKeyAndNoWallet(t *testing.T) {
	sock := serveAgent(t, agentkey.Key{Signer: newSigner(t), Comment: "bastion"})

	plan := planSigner(context.Background(), sock, "")
	joined := strings.Join(plan.lines, "\n")
	if !strings.Contains(joined, "one key") {
		t.Errorf("the plan does not say the key is settled:\n%s", joined)
	}
	if !strings.Contains(joined, "bastion") {
		t.Errorf("the key's label is missing:\n%s", joined)
	}
}

// Several keys and no wallet is not a question the agent can answer: it will
// refuse. Saying that here is the point of printing it before the request.
func TestPlanSaysSeveralKeysWithoutAWalletWillRefuse(t *testing.T) {
	sock := serveAgent(t,
		agentkey.Key{Signer: newSigner(t), Comment: "one"},
		agentkey.Key{Signer: newSigner(t), Comment: "two"},
	)

	plan := planSigner(context.Background(), sock, "")
	joined := strings.Join(plan.lines, "\n")
	if !strings.Contains(joined, "refuse") || !strings.Contains(joined, "--signer") {
		t.Errorf("the plan does not say what will happen:\n%s", joined)
	}
}

// An rsa key is not a Solana account, so it is not a candidate and saying so
// is more useful than leaving the reader to wonder.
func TestPlanWithNoEd25519Key(t *testing.T) {
	sock := serveAgent(t, agentkey.Key{Signer: newRSASigner(t), Comment: "old@box"})

	plan := planSigner(context.Background(), sock, "")
	if !strings.Contains(plan.lines[0], "ed25519") {
		t.Errorf("the plan does not say why there is no candidate:\n%s", strings.Join(plan.lines, "\n"))
	}
}

// A named signer is settled, and the agent is not asked what it holds: there
// is nothing to work out.
func TestANamedSignerIsReportedWithoutAskingTheAgent(t *testing.T) {
	const named = "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"

	// A path with nothing behind it, so any attempt to dial would show up.
	plan := planSigner(context.Background(), filepath.Join(t.TempDir(), "no.sock"), named)
	if len(plan.lines) != 1 || plan.lines[0] != "signer="+named {
		t.Errorf("plan is %q, want one line naming the signer", plan.lines)
	}
}

// An agent that will not say what it holds is not a reason to refuse the
// request. The signature that comes back is still checked against the bytes.
func TestPlanWithAnAgentThatWillNotAnswer(t *testing.T) {
	plan := planSigner(context.Background(), filepath.Join(t.TempDir(), "no.sock"), "")
	if len(plan.lines) != 1 {
		t.Fatalf("plan is %q, want one line", plan.lines)
	}
	if !strings.Contains(plan.lines[0], "not named") {
		t.Errorf("the plan does not say the signer is unnamed: %q", plan.lines[0])
	}
}

func serveAgent(t *testing.T, keys ...agentkey.Key) string {
	t.Helper()
	ring, err := agentkey.KeyringWithComments(keys)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	// A short directory on purpose: a unix socket path caps at about 104
	// bytes, and t.TempDir embeds the test name, which here is longer than
	// the whole path budget.
	dir, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
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
	return sock
}

func newSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func newRSASigner(t *testing.T) gossh.Signer {
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

// Every key that is not the one about to sign says so. The wallet's marker
// alone is not enough: without a note on the others, two rows differ only by
// which one has "<- the wallet", and the reader has to work out the rest.
func TestEveryKeyThatWillNotSignIsMarked(t *testing.T) {
	sock := serveAgent(t,
		agentkey.Key{Signer: newSigner(t), Comment: "first"},
		agentkey.Key{Signer: newSigner(t), Comment: agentkey.WalletCommentPrefix + "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"},
		agentkey.Key{Signer: newSigner(t), Comment: "third"},
	)

	plan := planSigner(context.Background(), sock, "")
	marked, unmarked := 0, 0
	for _, line := range plan.lines[1:] {
		switch {
		case strings.Contains(line, "<- the wallet"):
			marked++
		case strings.Contains(line, "<- unused unless --signer names it"):
			unmarked++
		default:
			t.Errorf("a key carries no note, so nothing says whether it signs: %q", line)
		}
	}
	if marked != 1 {
		t.Errorf("%d keys marked as the wallet, want 1", marked)
	}
	if unmarked != 2 {
		t.Errorf("%d keys marked as unused, want 2:\n%s", unmarked, strings.Join(plan.lines, "\n"))
	}
}
