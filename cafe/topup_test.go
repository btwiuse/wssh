package cafe

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/routercafe/routercafe/auth/agentkey"
	"github.com/routercafe/routercafe/auth/siws"
	"github.com/routercafe/routercafe/solana"
)

// The deposit is the only place this server spends somebody's money on their
// behalf, so the checks below are all about what a signed transaction has to
// look like before any of it is broadcast. Each test builds a real transaction
// with the real builder rather than a hand-made byte string, because the thing
// being checked is what comes back from an agent, and a fixture written beside
// the reader can share its mistake.

// address builds a valid base58 account from one byte, so the fixtures are
// addresses the builders and the checker both agree are accounts, rather than
// strings that only look like them.
func address(b byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	return siws.Base58Encode(raw)
}

var (
	sourceAddress   = address(1)
	destinationAddr = address(2)
	strangerAddress = address(3)
	blockhash       = address(4)
)

func testTreasury() Treasury {
	return Treasury{
		Address:     destinationAddr,
		SolPriceUSD: 200 * PerMicroUSD,
	}
}

func TestCreditsRoundDown(t *testing.T) {
	tr := testTreasury()
	cases := []struct {
		lamports uint64
		want     MicroUSD
	}{
		{1_000_000_000, 200 * PerMicroUSD}, // 1 SOL at $200
		{100_000_000, 20 * PerMicroUSD},    // 0.1 SOL
		{1, 0},                             // one lamport is worth nothing at this rate
		{999_999_999, 199_999_999},         // just under 1 SOL, rounded down
		{5_000, 1000},                      // the network fee of a transfer, about a cent
	}
	for _, c := range cases {
		if got := tr.Credits(c.lamports); got != c.want {
			t.Errorf("Credits(%d) = %d, want %d", c.lamports, got, c.want)
		}
	}
}

// Rounding down is the operator's rule, and rounding up would be a way to mint
// a little money out of many small deposits, so it is a test and not a comment.
func TestCreditsNeverRoundUp(t *testing.T) {
	tr := Treasury{Address: destinationAddr, SolPriceUSD: 3}
	// 1 lamport at $3/SOL is three millionths of a millionth of a dollar,
	// which has to floor to nothing.
	if got := tr.Credits(1); got != 0 {
		t.Errorf("Credits(1) at $3/SOL = %d, want 0 (rounded down, never up)", got)
	}
}

func TestTransferAmount(t *testing.T) {
	instructions, err := solana.NewTransfer(solana.TransferInstruction{
		Lamports: 1_234_567_890,
		To:       destinationAddr,
	})
	if err != nil {
		t.Fatalf("NewTransfer: %v", err)
	}
	data, err := siws.Base58Decode(instructions[0].DataBase58)
	if err != nil {
		t.Fatalf("decode the instruction data: %v", err)
	}
	got, err := transferAmount(data)
	if err != nil {
		t.Fatalf("transferAmount: %v", err)
	}
	if got != 1_234_567_890 {
		t.Errorf("transferAmount = %d, want 1234567890", got)
	}
}

func TestTransferAmountRefusesAnythingElse(t *testing.T) {
	if _, err := transferAmount([]byte{2, 0}); err == nil {
		t.Error("a two byte transfer data field was accepted")
	}
	if _, err := transferAmount(make([]byte, 20)); err == nil {
		t.Error("a twenty byte transfer data field was accepted; that is something else")
	}
	wrong := make([]byte, 12)
	wrong[0] = 3
	if _, err := transferAmount(wrong); err == nil {
		t.Error("a data field that is not a transfer was accepted")
	}
}

// A message is checked against what was asked for. Every case here is a
// transaction that would move money somebody did not agree to move.
func TestCheckTransfer(t *testing.T) {
	const lamports = 1_000_000_000

	// build runs the real builder and decodes the result, so what checkTransfer
	// sees is what an agent would have been handed back.
	build := func(t *testing.T, instructions ...agentkey.SolanaInstruction) solana.Message {
		t.Helper()
		unsigned, err := solana.BuildTransaction(agentkey.SolanaTxRequest{
			Blockhash:    blockhash,
			Signer:       sourceAddress,
			Instructions: instructions,
		})
		if err != nil {
			t.Fatalf("BuildTransaction: %v", err)
		}
		msg, err := solana.DecodeSigned(unsigned)
		if err != nil {
			t.Fatalf("DecodeSigned: %v", err)
		}
		return msg
	}

	transfer := func(lamports uint64, to string) agentkey.SolanaInstruction {
		list, err := solana.NewTransfer(solana.TransferInstruction{Lamports: lamports, To: to})
		if err != nil {
			t.Fatalf("NewTransfer: %v", err)
		}
		return list[0]
	}

	if err := checkTransfer(build(t, transfer(lamports, destinationAddr)),
		sourceAddress, destinationAddr, lamports); err != nil {
		t.Fatalf("a correct deposit was refused: %v", err)
	}

	if err := checkTransfer(build(t, transfer(lamports*2, destinationAddr)),
		sourceAddress, destinationAddr, lamports); err == nil {
		t.Error("a transaction for twice the amount asked for was accepted")
	}

	if err := checkTransfer(build(t, transfer(lamports, strangerAddress)),
		sourceAddress, destinationAddr, lamports); err == nil {
		t.Error("a transaction paying a stranger was accepted")
	}

	// A third writable account is the one that would cost somebody else money:
	// two instructions, one of them naming an account nobody asked about.
	two := []agentkey.SolanaInstruction{
		transfer(lamports, destinationAddr),
		{
			ProgramID: solana.SystemProgramID,
			Accounts: []agentkey.SolanaAccount{
				{Address: strangerAddress, IsWritable: true},
			},
			DataBase58: transfer(lamports, destinationAddr).DataBase58,
		},
	}
	if err := checkTransfer(build(t, two...), sourceAddress, destinationAddr, lamports); err == nil {
		t.Error("a transaction that can change a third account was accepted")
	}

	memo, err := solana.NewMemo("hello")
	if err != nil {
		t.Fatalf("NewMemo: %v", err)
	}
	if err := checkTransfer(build(t, memo[0]), sourceAddress, destinationAddr, lamports); err == nil {
		t.Error("a memo was accepted as a deposit")
	}
}

// A deposit is refused before anything is asked for, on the grounds that would
// waste the person's money.
func TestDepositRefusesBeforeAsking(t *testing.T) {
	cases := []struct {
		name     string
		from     string
		treasury string
		sock     string
		lamports uint64
		want     string
	}{
		{"not an address", "nope", destinationAddr, "/tmp/sock", 1_000_000, "account to pay from"},
		{"no treasury", sourceAddress, "", "/tmp/sock", 1_000_000, "no treasury address"},
		{"bad treasury", sourceAddress, "nope", "/tmp/sock", 1_000_000, "treasury address"},
		{"to itself", destinationAddr, destinationAddr, "/tmp/sock", 1_000_000, "own address"},
		{"nothing", sourceAddress, destinationAddr, "/tmp/sock", 0, "nothing"},
		{"no agent", sourceAddress, destinationAddr, "", 1_000_000, "ssh -A"},
		{"under the fee", sourceAddress, destinationAddr, "/tmp/sock", 100, "network fee"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ledger := testLedger(t)
			_, err := Deposit(context.Background(), ledger,
				Treasury{Address: c.treasury, SolPriceUSD: PerMicroUSD},
				c.from, c.sock, c.lamports)
			if err == nil {
				t.Fatalf("deposit of %d was accepted", c.lamports)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("refusal %q does not mention %q", err, c.want)
			}
			if got := ledger.Account(c.from).Balance; got != 0 {
				t.Errorf("a refused deposit changed a balance to %d", got)
			}
		})
	}
}

// A dry run prices the deposit and changes nothing: no signature asked for, no
// balance moved.
func TestDepositDryRunMovesNothing(t *testing.T) {
	ledger := testLedger(t)
	treasury := Treasury{Address: destinationAddr, SolPriceUSD: 200 * PerMicroUSD, DryRun: true}

	receipt, err := Deposit(context.Background(), ledger, treasury,
		sourceAddress, "/tmp/does-not-exist.sock", 1_000_000_000)
	if err != nil {
		t.Fatalf("a dry run reached for an agent: %v", err)
	}
	if !receipt.Pending {
		t.Error("the receipt does not say it was a dry run")
	}
	if receipt.Signature != "" {
		t.Errorf("a dry run reported signature %q", receipt.Signature)
	}
	if receipt.Credits != 200*PerMicroUSD {
		t.Errorf("dry run priced at %d, want %d", receipt.Credits, 200*PerMicroUSD)
	}
	if got := ledger.Account(sourceAddress).Balance; got != 0 {
		t.Errorf("a dry run moved a balance to %d", got)
	}
}

func TestSolText(t *testing.T) {
	cases := []struct {
		lamports uint64
		want     string
	}{
		{0, "0 SOL"},
		{1_000_000_000, "1 SOL"},
		{1_500_000_000, "1.5 SOL"},
		{5_000, "0.000005 SOL"},
		{1, "0.000000001 SOL"},
	}
	for _, c := range cases {
		if got := solText(c.lamports); got != c.want {
			t.Errorf("solText(%d) = %q, want %q", c.lamports, got, c.want)
		}
	}
}

// parseSOL is what a person types, and the arithmetic has to be exact: this is
// an amount of money and a float would let 0.1 + 0.2 drift reach a chain.
func TestParseSOL(t *testing.T) {
	cases := []struct {
		in      string
		want    uint64
		wantErr string
	}{
		{"1", 1_000_000_000, ""},
		{"0.5", 500_000_000, ""},
		{"0.000001", 1_000, ""},
		{"2.000000001", 2_000_000_001, ""},
		{".5", 500_000_000, ""},
		{" 3 ", 3_000_000_000, ""},
		{"", 0, "type an amount"},
		{"abc", 0, "not an amount"},
		{"1.2.3", 0, "not an amount"},
		{"1.", 0, "not an amount"},
		{"-1", 0, "not an amount"},
		{"0.0000000001", 0, "nine decimal places"},
		{"1e9", 0, "not an amount"},
	}
	for _, c := range cases {
		got, err := parseSOL(c.in)
		if c.wantErr != "" {
			if err == nil {
				t.Errorf("parseSOL(%q) = %d, want an error mentioning %q", c.in, got, c.wantErr)
			} else if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("parseSOL(%q) error %q does not mention %q", c.in, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSOL(%q) = %v, want %d", c.in, err, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("parseSOL(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// VerifySigned is the check that makes the rest of the deposit checks mean
// anything: they are all about the bytes, and this is about who signed them.
func TestVerifySigned(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	message := []byte("the message the signature covers")
	signed := []byte{0x01} // compact-u16: one signature
	signed = append(signed, ed25519.Sign(priv, message)...)
	signed = append(signed, message...)

	if err := solana.VerifySigned(signed, pub); err != nil {
		t.Errorf("a correct signature was refused: %v", err)
	}
	if err := solana.VerifySigned(signed, otherPub); err == nil {
		t.Error("a signature by another key was accepted")
	}

	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 0xff
	if err := solana.VerifySigned(tampered, pub); err == nil {
		t.Error("a signature over different bytes was accepted")
	}
	if err := solana.VerifySigned([]byte{0x01, 0x02}, pub); err == nil {
		t.Error("a truncated signature was accepted")
	}
	if err := solana.VerifySigned([]byte{0x02, 0x01}, pub); err == nil {
		t.Error("two signature slots were accepted")
	}
	if err := solana.VerifySigned(signed, pub[:16]); err == nil {
		t.Error("a short public key was accepted")
	}
}
