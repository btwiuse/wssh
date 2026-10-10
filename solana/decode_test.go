package solana

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
)

// messageOf is the part a signature covers.
func messageOf(unsigned []byte) []byte {
	rest, err := afterSignatures(unsigned)
	if err != nil {
		panic(err)
	}
	return rest
}

// The reader is measured against the same bytes the writer is, and those are
// the bytes a Solana library produced. A reader that has drifted describes an
// approval dialog that says something other than what is about to be signed,
// which is the one thing such a dialog must never do.
func TestDecodeMessageReadsTheGoldenBytes(t *testing.T) {
	msg, err := DecodeMessage(goldenMessage(t))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if want := "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"; msg.FeePayer != want {
		t.Errorf("fee payer is %q, want %q", msg.FeePayer, want)
	}
	if want := "B1P9Y4gHoGaSX9FS6nUeAb5Jx3ATjNPGmc7YE4jfEQUZ"; msg.Blockhash != want {
		t.Errorf("blockhash is %q, want %q", msg.Blockhash, want)
	}
	// The header's four groups, read off the key order. The byte called
	// numReadonlyUnsignedAccounts counts accounts that are neither
	// signers nor read-only, so it is the writable non-signers: this
	// message has one writable signer and one writable non-signer.
	if len(msg.Accounts) != 2 {
		t.Fatalf("got %d accounts, want 2", len(msg.Accounts))
	}
	if !msg.Accounts[0].Signer || !msg.Accounts[0].Writable {
		t.Errorf("the fee payer is %+v, want a writable signer", msg.Accounts[0])
	}
	if msg.Accounts[1].Signer || !msg.Accounts[1].Writable {
		t.Errorf("the program account is %+v, want a writable non-signer", msg.Accounts[1])
	}
	if msg.LookupTables != 0 {
		t.Errorf("lookup tables is %d, want 0", msg.LookupTables)
	}
	if len(msg.Instructions) != 1 {
		t.Fatalf("got %d instructions, want 1", len(msg.Instructions))
	}
	if msg.Instructions[0].ProgramID != MemoProgramID {
		t.Errorf("program is %q, want the memo program", msg.Instructions[0].ProgramID)
	}
	if len(msg.Instructions[0].Accounts) != 1 ||
		msg.Instructions[0].Accounts[0] != msg.FeePayer {
		t.Errorf("accounts are %v, want just the payer", msg.Instructions[0].Accounts)
	}
	// This fixture carries its data base58-encoded once more than a browser
	// would, so the bytes behind it are not the memo text. What matters
	// here is only that the reader returns exactly what was written.
	if got, want := len(msg.Instructions[0].Data), 6; got != want {
		t.Errorf("data is %d bytes, want %d", got, want)
	}
}

// What the summary says is the whole point of the reader, so each fact a
// person approves on has to be in it.
//
// Built rather than taken from the golden fixture, because a browser sends the
// memo as raw bytes - the page encodes them when it writes the request and the
// library decodes them back when it builds the transaction - and the golden
// fixture has them encoded one time further than that. Approving a memo means
// reading what it says, so the text has to be in the summary rather than
// matched by accident against the program's name.
func TestSummariseNamesTheTransaction(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	address := siws.Base58Encode(pub)
	unsigned, err := BuildTransaction(agentkey.SolanaTxRequest{
		Blockhash: "B1P9Y4gHoGaSX9FS6nUeAb5Jx3ATjNPGmc7YE4jfEQUZ",
		Signer:    address,
		Instructions: []agentkey.SolanaInstruction{{
			ProgramID:  MemoProgramID,
			Accounts:   []agentkey.SolanaAccount{},
			DataBase58: siws.Base58Encode([]byte("pay alice 5 SOL")),
		}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	got := Summarise("ssh-ed25519 SHA256:abc", messageOf(unsigned))

	for _, want := range []string{
		address,            // who pays
		"SPL Memo program", // what it calls
		"pay alice 5 SOL",  // what it says
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary does not mention %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "not a Solana transaction") {
		t.Errorf("a transaction was described as not one:\n%s", got)
	}
	// No hex dump in the transaction case: the point is that a person can
	// read what they are approving.
	if strings.Contains(got, "8001000102") {
		t.Errorf("the summary falls back to hex for a transaction:\n%s", got)
	}
}

// Something that opens like a transaction and does not decode must say so, and
// must not be passed off as an ordinary blob. Falling through to a hex dump
// here is how a malformed transaction gets approved as something harmless.
func TestAnUnreadableTransactionSaysSo(t *testing.T) {
	truncated := goldenMessage(t)[:20]
	got := Summarise("key", truncated)

	if !strings.Contains(got, "could not be read") {
		t.Errorf("an unreadable message is not reported as one:\n%s", got)
	}
	if strings.Contains(got, "not a Solana transaction") {
		t.Errorf("something that opened like a transaction was called something else:\n%s", got)
	}
}

// Most signatures this sees are SSH wire protocol, and there is no transaction
// to decode. Saying so is more use than a hex dump and says the truth.
func TestSomethingThatIsNotATransactionSaysSo(t *testing.T) {
	got := Summarise("key", []byte{0x00, 0x00, 0x00, 0x07, 's', 's', 'h', '-', 'e', 'd'})

	if !strings.Contains(got, "not a Solana transaction") {
		t.Errorf("the summary does not say what this is:\n%s", got)
	}
}

// A legacy message has no version byte, so it cannot be read this way and
// saying so beats reading a version number out of its first header byte.
func TestALegacyMessageIsRefusedNotMisread(t *testing.T) {
	legacy := []byte{0x01, 0x00, 0x00}
	if _, err := DecodeMessage(legacy); err == nil {
		t.Error("a legacy message was read as a versioned one")
	}
	if LooksLikeMessage(legacy) {
		t.Error("a legacy message was taken for a versioned one")
	}
}

// Every malformed shape has to be an error rather than a partial read. A
// half-decoded message is the worst outcome, because it describes a
// transaction that does not exist.
func TestMalformedMessagesAreRefused(t *testing.T) {
	cases := map[string][]byte{
		"empty":                 {},
		"unknown version":       {0x81, 0x00, 0x00, 0x00, 0x00},
		"ends in the header":    {0x80, 0x01},
		"claims absent keys":    {0x80, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00},
		"ends before blockhash": {0x80, 0x01, 0x00, 0x00, 0x01, 0x00},
	}
	for name, data := range cases {
		if _, err := DecodeMessage(data); err == nil {
			t.Errorf("%s was decoded rather than refused", name)
		}
	}
}

// A transfer is the one instruction whose meaning the protocol fixes rather
// than the program's interface, so it is the one worth showing as words. The
// amount is the field a person approves on, so it has to come out right - and
// it is little-endian, which is the detail that is easy to get wrong in a way
// that looks like a plausible number.
func TestATransferIsDescribedInWords(t *testing.T) {
	payer, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	to, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	payerAddr := siws.Base58Encode(payer)
	toAddr := siws.Base58Encode(to)

	// One SOL: discriminant 2, then a little-endian u64.
	unsigned, err := BuildTransaction(agentkey.SolanaTxRequest{
		Blockhash: "B1P9Y4gHoGaSX9FS6nUeAb5Jx3ATjNPGmc7YE4jfEQUZ",
		Signer:    payerAddr,
		Instructions: []agentkey.SolanaInstruction{{
			ProgramID: SystemProgramID,
			Accounts: []agentkey.SolanaAccount{
				{Address: payerAddr, IsSigner: true, IsWritable: true},
				{Address: toAddr, IsWritable: true},
			},
			DataBase58: "3Bxs3zzLZLuLQEYX",
		}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	got := Summarise("key", messageOf(unsigned))
	for _, want := range []string{
		"transfers 1000000000 lamports", // the amount
		toAddr,                          // and where it goes
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary does not say %q:\n%s", want, got)
		}
	}
}

// Whether an account can be written is the question a person is really asking,
// and it falls out of the header's four groups rather than from the program's
// interface. Getting the groups the wrong way round would say a signature
// could not sign or a write could not write.
func TestWhichAccountsTheTransactionMayWrite(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	address := siws.Base58Encode(pub)
	// Header 1 0 0 with two keys: one writable signer, one read-only.
	message := []byte{0x80, 1, 0, 0}
	message = appendCompactU16ForTest(message, 2)
	raw, err := siws.Base58Decode(address)
	if err != nil {
		t.Fatalf("address: %v", err)
	}
	message = append(message, raw...) // account 0
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	otherRaw, err := siws.Base58Decode(siws.Base58Encode(otherPub))
	if err != nil {
		t.Fatalf("address: %v", err)
	}
	message = append(message, otherRaw...)         // account 1
	message = append(message, make([]byte, 32)...) // blockhash
	message = appendCompactU16ForTest(message, 1)  // one instruction
	message = appendCompactU16ForTest(message, 0)  // program 0
	message = appendCompactU16ForTest(message, 0)  // no accounts
	message = appendCompactU16ForTest(message, 0)  // no data
	message = appendCompactU16ForTest(message, 0)  // no lookup tables

	msg, err := DecodeMessage(message)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(msg.Accounts) != 2 {
		t.Fatalf("got %d accounts, want 2", len(msg.Accounts))
	}
	if !msg.Accounts[0].Signer || !msg.Accounts[0].Writable {
		t.Errorf("account 0 is %+v, want a writable signer", msg.Accounts[0])
	}
	if msg.Accounts[1].Signer || msg.Accounts[1].Writable {
		t.Errorf("account 1 is %+v, want neither", msg.Accounts[1])
	}
}

// A message that names an address lookup table has accounts this file cannot
// name: resolving one means asking an RPC node. That is said rather than
// hidden, because a list of accounts that silently omitted them would be
// shorter than the list the transaction touches.
func TestLookupTablesAreReportedNotHidden(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	address := siws.Base58Encode(pub)
	unsigned, err := BuildTransaction(agentkey.SolanaTxRequest{
		Blockhash: "B1P9Y4gHoGaSX9FS6nUeAb5Jx3ATjNPGmc7YE4jfEQUZ",
		Signer:    address,
		Instructions: []agentkey.SolanaInstruction{{
			ProgramID:  MemoProgramID,
			DataBase58: siws.Base58Encode([]byte("hi")),
		}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	message := messageOf(unsigned)
	// The build writes no lookup tables; saying one is last is enough.
	message[len(message)-1] = 1

	msg, err := DecodeMessage(message)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.LookupTables != 1 {
		t.Errorf("lookup tables is %d, want 1", msg.LookupTables)
	}
	got := Summarise("key", message)
	if !strings.Contains(got, "address lookup table") {
		t.Errorf("the summary does not mention the lookup table:\n%s", got)
	}
}

func appendCompactU16ForTest(dst []byte, n int) []byte {
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		dst = append(dst, b)
		if n == 0 {
			return dst
		}
	}
}
