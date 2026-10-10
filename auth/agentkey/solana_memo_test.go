package agentkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

// A memo request arrives with an empty accounts list, because the memo
// program only ever takes the signer and the wallet knows which pubkey
// that is. The question this test answers is narrow and important: does
// the request reach the wallet at all, or does something upstream refuse
// it first?
//
// "Reached the wallet" is the observable difference, so this checks the call
// rather than the message: an agent-side refusal never calls Ask. That matters
// because the two failures look the same on the wire otherwise, and picking the
// wrong one sends whoever is reading it off to rebuild the wrong thing.
func TestMemoRequestWithNoAccountsReachesTheWallet(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ring, _ := mustKeyring(t, priv)

	reached := false
	ask := func(req SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error) {
		reached = true
		if len(req.Instructions) != 1 {
			t.Errorf("the wallet saw %d instructions, want 1", len(req.Instructions))
		}
		if req.Instructions[0].ProgramID != SolanaMemoProgramV2 {
			t.Errorf("the wallet saw program %q, want the memo program %q",
				req.Instructions[0].ProgramID, SolanaMemoProgramV2)
		}
		message := []byte("a message the wallet signs")
		return SolanaTxResponse{
			Signature:         ed25519.Sign(priv, message),
			SignedTransaction: buildSignedTransaction(pub, priv, message),
		}, pub, nil
	}
	if err := WithSolana(ring, ask, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// The exact bytes the Deno script puts on the wire for a memo.
	body := []byte(`{"blockhash":"CoweCSaCseXBYuJ2UQk195skjChyHAbW34QRvDi4hF2k",` +
		`"instructions":[{"programId":"MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",` +
		`"accounts":[],"data":"4FsZFKWTZeq1FdYMrNeZd"}]}`)

	raw, err := ring.Extension(SolanaTxExtension, body)
	if err != nil {
		t.Fatalf("extension: %v", err)
	}

	if !reached {
		var got SolanaTxResponse
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("the answer is not readable: %v", err)
		}
		t.Fatalf("the wallet was never asked; the agent refused first: %s", got.Refusal)
	}

	var got SolanaTxResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the answer is not readable: %v", err)
	}
	if got.Refusal != "" {
		t.Fatalf("the wallet refused a memo: %s", got.Refusal)
	}
	if len(got.SignedTransaction) == 0 {
		t.Fatal("no signed transaction came back")
	}
	if err := VerifySolanaTx(got, pub); err != nil {
		t.Errorf("the signature does not check out: %v", err)
	}
}

// The same request against a program that genuinely needs its accounts:
// the carve-out is for the memo program alone, and widening it would let
// a malformed request through to the wallet as a transaction that fails
// on chain for reasons nobody can see from the request.
func TestNonMemoRequestWithNoAccountsIsStillRefused(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ring, _ := mustKeyring(t, priv)

	reached := false
	ask := func(SolanaTxRequest) (SolanaTxResponse, ed25519.PublicKey, error) {
		reached = true
		return SolanaTxResponse{}, nil, nil
	}
	if err := WithSolana(ring, ask, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}

	body := []byte(`{"blockhash":"CoweCSaCseXBYuJ2UQk195skjChyHAbW34QRvDi4hF2k",` +
		`"instructions":[{"programId":"11111111111111111111111111111111",` +
		`"accounts":[],"data":"4FsZFKWTZeq1FdYMrNeZd"}]}`)

	raw, err := ring.Extension(SolanaTxExtension, body)
	if err != nil {
		t.Fatalf("extension: %v", err)
	}
	if reached {
		t.Error("the wallet was asked to sign an instruction with no accounts")
	}

	var got SolanaTxResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the answer is not readable: %v", err)
	}
	if got.Refusal == "" {
		t.Fatal("a request with no accounts should have been refused")
	}
	if !strings.Contains(got.Refusal, "the agent refused") {
		t.Errorf("the refusal should name the agent so it can be told apart from the "+
			"wallet's own check, got %q", got.Refusal)
	}
}
