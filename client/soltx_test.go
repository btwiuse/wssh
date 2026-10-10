//go:build !js

package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
	"github.com/btwiuse/wssh/client"
)

// startFakeAgent serves a keyring that signs transactions without a wallet.
//
// Everything except the serialisation is the real thing: the agent protocol,
// the extension framing, the verification on the way back. The page's half of
// this is a library call and a popup, and neither is what is under test.
func startFakeAgent(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()

	pub := priv.Public().(ed25519.PublicKey)
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ring, err := agentkey.Keyring([]gossh.Signer{signer})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	// Whatever the page would have built, as far as this end is concerned the
	// message is opaque bytes covered by a signature.
	if err := agentkey.WithSolana(ring, func(req agentkey.SolanaTxRequest) (agentkey.SolanaTxResponse, ed25519.PublicKey, error) {
		message := []byte(strings.Join([]string{req.Blockhash, req.Label}, "|"))
		for _, in := range req.Instructions {
			message = append(message, in.ProgramID...)
			message = append(message, in.DataBase58...)
		}
		sig := ed25519.Sign(priv, message)
		signed := append([]byte{1}, sig...)
		return agentkey.SolanaTxResponse{
			Signature:         sig,
			SignedTransaction: append(signed, message...),
		}, pub, nil
	}, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// A real unix socket, because that is what a session actually has. The
	// directory name is kept short on purpose: a unix socket path is capped at
	// 104 bytes, and t.TempDir embeds the test name, which is easily longer than
	// that on its own.
	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck
				_ = agent.ServeAgent(ring.(agent.Agent), conn)
			}()
		}
	}()
	return path
}

func soltxRequest(t *testing.T, to string, lamports uint64) agentkey.SolanaTxRequest {
	t.Helper()
	instructions, err := client.NewSolanaTransfer(client.TransferInstruction{
		Lamports: lamports,
		To:       to,
	})
	if err != nil {
		t.Fatalf("build the transfer: %v", err)
	}
	return agentkey.SolanaTxRequest{
		Blockhash:    "9xQeVvM816uMixesDjoeL7PkZn7W5jNf1WnokxBfXmG",
		Label:        "an invoice",
		Instructions: instructions,
	}
}

// The whole conversation: a session asks, the wallet signs, the caller gets
// something it can verify without trusting anybody in the middle.
func TestSolanaTxReachesAnAgentAndComesBackSigned(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	sock := startFakeAgent(t, priv)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := client.SolanaTxAt(ctx, sock, soltxRequest(t, "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5", 1_000_000_000))
	if err != nil {
		t.Fatalf("ask: %v", err)
	}

	if len(resp.Signature) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes", len(resp.Signature))
	}
	if err := agentkey.VerifySolanaTx(resp, pub); err != nil {
		t.Fatalf("the answer did not verify: %v", err)
	}
	if !strings.Contains(string(resp.SignedTransaction), "an invoice") {
		t.Error("the label did not survive the round trip")
	}
}

// An agent that has never heard of the extension is a different problem from
// one that declined, and the caller needs to be able to tell them apart.
func TestSolanaTxExplainsAnAgentWithoutOne(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
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

	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck
				_ = agent.ServeAgent(ring, conn)
			}()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err = client.SolanaTxAt(ctx, path, soltxRequest(t, "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5", 1))
	if err == nil {
		t.Fatal("an agent with no wallet should not have signed")
	}
	// A plain ssh-agent signs anything, so being told that this command is
	// unnecessary is more use than being sent off to attach a wallet.
	if !strings.Contains(err.Error(), "real ssh-agent you do not need this command") {
		t.Errorf("the refusal should say why this command is not needed, got %v", err)
	}
}

// Nothing here needs an agent at all, and saying so plainly beats a dial
// failure against a path that does not exist.
func TestSolanaTxWithNoAgentSaysSo(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	if _, err := client.SolanaTxAt(context.Background(), "",
		soltxRequest(t, "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5", 1)); err == nil {
		t.Fatal("expected a refusal with no agent")
	} else if !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Errorf("the refusal should name what is missing, got %v", err)
	}
}

// A transfer's instruction data is a fixed twelve bytes: a discriminant and an
// amount. It is written here rather than left to the browser because it is a
// struct, not a serialisation format, and getting it wrong is the difference
// between sending the money and sending nothing.
func TestNewSolanaTransfer(t *testing.T) {
	const to = "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"

	instructions, err := client.NewSolanaTransfer(client.TransferInstruction{
		Lamports: 1_000_000_000,
		To:       to,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(instructions) != 1 {
		t.Fatalf("a transfer is one instruction, got %d", len(instructions))
	}
	in := instructions[0]
	if in.ProgramID != client.SystemProgramID {
		t.Errorf("program is %q, want the System Program", in.ProgramID)
	}
	if len(in.Accounts) != 1 || in.Accounts[0].Address != to {
		t.Errorf("accounts came back as %+v", in.Accounts)
	}
	// The destination is written to. Stating it wrong produces a transaction
	// that either fails to send or does something other than a transfer.
	if !in.Accounts[0].IsWritable || in.Accounts[0].IsSigner {
		t.Errorf("the destination came back as %+v", in.Accounts[0])
	}

	data, err := base58DecodeForTest(t, in.DataBase58)
	if err != nil {
		t.Fatalf("data is not base58: %v", err)
	}
	if len(data) != 12 {
		t.Fatalf("instruction data is %d bytes, want 12", len(data))
	}
	if data[0] != 2 {
		t.Errorf("the discriminant is %d, want 2", data[0])
	}
	amount := uint64(0)
	for i := 7; i >= 0; i-- {
		amount = amount<<8 | uint64(data[4+i])
	}
	if amount != 1_000_000_000 {
		t.Errorf("the amount came back as %d", amount)
	}

	// A transfer of nothing, or to nowhere, is not worth asking a wallet for.
	if _, err := client.NewSolanaTransfer(client.TransferInstruction{Lamports: 0, To: to}); err == nil {
		t.Error("a transfer of nothing should be refused")
	}
	if _, err := client.NewSolanaTransfer(client.TransferInstruction{Lamports: 1, To: "0OIl"}); err == nil {
		t.Error("a destination that is not an address should be refused")
	}
}

func TestParseLamports(t *testing.T) {
	got, err := client.ParseLamports("1")
	if err != nil {
		t.Fatalf("1 SOL: %v", err)
	}
	if got != 1_000_000_000 {
		t.Errorf("1 SOL is %d lamports", got)
	}
	if _, err := client.ParseLamports("0.000000001"); err != nil {
		t.Errorf("a billionth of a SOL should parse: %v", err)
	}

	for _, bad := range []string{"0", "-1", "", "lots", "1000000000"} {
		if _, err := client.ParseLamports(bad); err == nil {
			t.Errorf("%q should not have parsed", bad)
		}
	}
}

func base58DecodeForTest(t *testing.T, s string) ([]byte, error) {
	t.Helper()
	return siws.Base58Decode(s)
}

// The only function here that reaches outside the process, and therefore the
// one most likely to be wrong in a way nothing else would notice.
//
// Solana wraps getLatestBlockhash in a context, so the blockhash is a level
// deeper than it looks. Reading it from the wrong place finds nothing at all,
// which no other test in this package would notice.
func TestLatestBlockhash(t *testing.T) {
	// The shape an endpoint really returns, copied from one.
	const body = `{"jsonrpc":"2.0","result":{"context":{"apiVersion":"4.3.0","slot":455186569},` +
		`"value":{"blockhash":"2QaBotLgbzXTfMJH11nTp8KzsQKiejR3C7odjYvkd83Z",` +
		`"lastValidBlockHeight":433223950}},"id":1}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("asked with %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	got, err := client.LatestBlockhash(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("blockhash: %v", err)
	}
	if got != "2QaBotLgbzXTfMJH11nTp8KzsQKiejR3C7odjYvkd83Z" {
		t.Errorf("got %q", got)
	}
}

func TestLatestBlockhashReportsWhatWentWrong(t *testing.T) {
	t.Run("an error from the endpoint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","error":{"code":-32602,"message":"bad params"}}`)
		}))
		defer server.Close()

		if _, err := client.LatestBlockhash(context.Background(), server.URL); err == nil {
			t.Fatal("an endpoint error should be reported")
		} else if !strings.Contains(err.Error(), "bad params") {
			t.Errorf("the endpoint's own wording should survive, got %v", err)
		}
	})

	t.Run("an answer with no blockhash", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","result":{"value":{}},"id":1}`)
		}))
		defer server.Close()

		if _, err := client.LatestBlockhash(context.Background(), server.URL); err == nil {
			t.Fatal("an empty answer should be reported")
		}
	})

	t.Run("an endpoint that is not there", func(t *testing.T) {
		if _, err := client.LatestBlockhash(context.Background(), "http://127.0.0.1:1"); err == nil {
			t.Fatal("an unreachable endpoint should be reported")
		}
	})
}
