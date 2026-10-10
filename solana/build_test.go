package solana

import (
	"bytes"
	"testing"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
)

// The one memo request that produced the bytes in golden_test.go, rebuilt
// here so the comparison is against the same request rather than against a
// copy of its answer.
func goldenRequest(t *testing.T) agentkey.SolanaTxRequest {
	t.Helper()
	const payer = "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"
	data, err := siws.Base58Decode("3Bxs4NN2")
	if err != nil {
		t.Fatalf("memo data: %v", err)
	}
	return agentkey.SolanaTxRequest{
		Blockhash: "B1P9Y4gHoGaSX9FS6nUeAb5Jx3ATjNPGmc7YE4jfEQUZ",
		Signer:    payer,
		Instructions: []agentkey.SolanaInstruction{{
			ProgramID:  MemoProgramID,
			Accounts:   []agentkey.SolanaAccount{{Address: payer, IsSigner: true, IsWritable: true}},
			DataBase58: siws.Base58Encode(data),
		}},
	}
}

// A builder that disagrees with the library has to fail here rather than on
// chain, where the only feedback is "invalid transaction discriminator" and
// nothing about which byte was wrong.
func TestBuildTransactionMatchesTheLibrary(t *testing.T) {
	got, err := BuildTransaction(goldenRequest(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := append([]byte{1}, append(make([]byte, 64), goldenMessage(t)...)...)

	if !bytes.Equal(got, want) {
		t.Fatalf("the built transaction is not the one the library built\n"+
			"  got  %x\n  want %x", got, want)
	}
}

// The message has to survive being read back as well as written: the signer
// will be handed these bytes and the cluster will be handed the result, and
// neither of them has our source.
func TestBuiltTransactionCarriesTheFeePayer(t *testing.T) {
	got, err := BuildTransaction(goldenRequest(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	who, err := FeePayer(got)
	if err != nil {
		t.Fatalf("the built transaction cannot be read back: %v", err)
	}
	if who != goldenRequest(t).Signer {
		t.Errorf("fee payer reads back as %q, want %q", who, goldenRequest(t).Signer)
	}
}

// A transaction that asks for a signature this path cannot supply is refused
// rather than sent with a signature missing, which the cluster rejects with
// nothing that points back here.
func TestBuildRefusesASignerItDoesNotHave(t *testing.T) {
	req := goldenRequest(t)
	req.Instructions[0].Accounts = append(req.Instructions[0].Accounts, agentkey.SolanaAccount{
		Address: "9LEc9vSFTppQNFjscPTxJKqUUioP4SvHMDgHX8fLtPLm", IsSigner: true,
	})
	if _, err := BuildTransaction(req); err == nil {
		t.Error("a transaction asking a second signer should have been refused")
	}
}

// No payer is not a default; it is the one thing this path cannot invent,
// because the payer is the key that is going to sign.
func TestBuildRefusesWithoutAPayer(t *testing.T) {
	req := goldenRequest(t)
	req.Signer = ""
	if _, err := BuildTransaction(req); err == nil {
		t.Error("a transaction with no fee payer should have been refused")
	}
}
