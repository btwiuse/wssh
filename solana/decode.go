package solana

// Reading a transaction message back, so a person can be shown what they are
// about to approve.
//
// This is the other half of build.go and it is kept beside it deliberately.
// The bytes that go into a signing request are written by that file and read
// by this one, and the fixture that pins them - golden_test.go, holding a
// message a Solana library produced - is what both are measured against. A
// writer and a reader that live apart drift, and a reader that has drifted
// shows an approval dialog describing a transaction that is not the one.
//
// What this is for is not the reading. It is that a person asked to approve a
// signature cannot approve a hex string: they cannot tell what it authorises,
// so the prompt tells them nothing and asking is theatre. Phantom solves this
// by refusing anything it cannot decode, and so does this - see Summarise.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/btwiuse/wssh/auth/siws"
)

// Two more program ids, named so an approval dialog reads as a decision
// rather than as a lookup. Both are as fixed as the memo program: what they do
// is not a matter of interpretation.
const (
	// TokenProgramID is the SPL token program.
	TokenProgramID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

	// AssociatedTokenProgramID creates the account a token lives in.
	AssociatedTokenProgramID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
)

// Account is one of the message's keys, with what the transaction may do to
// it.
//
// The writable flag is the one a person needs before approving: it is the
// difference between a transaction that notes something and one that changes
// an account. Nothing else in this file answers that question, and it is
// answerable without the program's own interface because the header counts
// the four groups.
type Account struct {
	Address  string
	Signer   bool
	Writable bool
}

// Message is a decoded versioned transaction message.
type Message struct {
	// FeePayer is the first account key, which Solana requires to be a
	// required signer and therefore the account paying.
	FeePayer string

	// Blockhash is what makes the transaction stale in about a minute.
	Blockhash string

	// Accounts are the message's own keys, in the order Solana puts them:
	// writable signers, then read-only signers, then writable accounts,
	// then read-only ones.
	Accounts []Account

	// LookupTables is how many address lookup tables the message
	// references.
	//
	// A non-zero count means some account indices point into a table
	// rather than at Accounts, and those names are not here to be shown:
	// resolving one means asking an RPC node for the table's contents.
	// It is reported rather than ignored, because a message decoded as if
	// it had no tables would name fewer accounts than it touches.
	LookupTables int

	// Instructions is what the transaction does, in order.
	Instructions []DecodedInstruction
}

// DecodedInstruction is one instruction with its accounts named.
type DecodedInstruction struct {
	ProgramID string
	Accounts  []string
	Data      []byte
}

// DecodeMessage reads a versioned transaction message.
//
// The layout is what build.go writes and what golden_test.go holds: version,
// a three-byte header, the account keys, the blockhash, the instructions, and
// a lookup count. Nothing is skipped and nothing is guessed - a message that
// does not fit is an error, because an approval dialog that describes
// something other than what will be signed is worse than one that says it
// could not read it.
func DecodeMessage(data []byte) (Message, error) {
	var msg Message

	if len(data) == 0 {
		return msg, errors.New("there is nothing to read")
	}
	if data[0]&0x80 == 0 {
		// A legacy message has no version byte and its header counts
		// signatures, so the top bit can never be set. Reading one as
		// versioned would take the first account key as a version number
		// and produce nonsense from real data.
		return msg, errors.New("this is a legacy message, which has no version byte")
	}
	if version := data[0] & 0x7f; version != 0 {
		return msg, fmt.Errorf("this is message version %d, which this reader does not know", version)
	}

	rest := data[1:]
	if len(rest) < 3 {
		return msg, errors.New("the message ends inside its header")
	}
	required := int(rest[0])
	readonlySigned := int(rest[1])
	readonlyUnsigned := int(rest[2])
	rest = rest[3:]

	count, n, err := readCompactU16(rest)
	if err != nil {
		return msg, fmt.Errorf("the account count is not readable: %w", err)
	}
	rest = rest[n:]
	if len(rest) < count*32 {
		return msg, fmt.Errorf("the message claims %d account keys but has %d bytes", count, len(rest))
	}
	keys := make([]string, count)
	for i := range count {
		keys[i] = siws.Base58Encode(rest[i*32 : (i+1)*32])
	}
	rest = rest[count*32:]

	if len(rest) < 32 {
		return msg, errors.New("the message ends before its blockhash")
	}
	msg.Blockhash = siws.Base58Encode(rest[:32])
	rest = rest[32:]
	if len(keys) == 0 {
		return msg, errors.New("the message names no accounts, so it has no fee payer")
	}
	msg.FeePayer = keys[0]

	// The four groups the header counts, in the order Solana lays them out.
	// Everything a person approves on - which accounts sign, which ones can
	// be changed - falls out of these four numbers and the key order.
	msg.Accounts = make([]Account, count)
	writableSigners := required
	readonlySigners := readonlySigned
	writableOthers := readonlyUnsigned
	for i, key := range keys {
		switch {
		case i < writableSigners:
			msg.Accounts[i] = Account{Address: key, Signer: true, Writable: true}
		case i < writableSigners+readonlySigners:
			msg.Accounts[i] = Account{Address: key, Signer: true}
		case i < writableSigners+readonlySigners+writableOthers:
			msg.Accounts[i] = Account{Address: key, Writable: true}
		default:
			msg.Accounts[i] = Account{Address: key}
		}
	}

	instructions, n, err := readCompactU16(rest)
	if err != nil {
		return msg, fmt.Errorf("the instruction count is not readable: %w", err)
	}
	rest = rest[n:]

	for i := range instructions {
		ix, n, err := readInstruction(rest, keys, i)
		if err != nil {
			return msg, err
		}
		msg.Instructions = append(msg.Instructions, ix)
		rest = rest[n:]
	}

	lookupTables, _, err := readCompactU16(rest)
	if err != nil {
		return msg, fmt.Errorf("the address table count is not readable: %w", err)
	}
	msg.LookupTables = lookupTables
	return msg, nil
}

// LooksLikeMessage reports whether the bytes open as a versioned message,
// without reading any of it.
//
// It exists so that something that does look like a transaction and then
// cannot be read is reported as such, rather than quietly falling back to a
// hex dump. A person must never be shown a blob and told it is the wrong kind
// of thing.
func LooksLikeMessage(data []byte) bool {
	return len(data) > 0 && data[0]&0x80 != 0
}

func readInstruction(data []byte, keys []string, at int) (DecodedInstruction, int, error) {
	var ix DecodedInstruction

	program, n, err := readCompactU16(data)
	if err != nil {
		return ix, 0, fmt.Errorf("instruction %d: the program is not readable: %w", at, err)
	}
	data = data[n:]
	if program >= len(keys) {
		return ix, 0, fmt.Errorf("instruction %d: names program %d, and the message has %d accounts", at, program, len(keys))
	}
	ix.ProgramID = keys[program]

	count, n, err := readCompactU16(data)
	if err != nil {
		return ix, 0, fmt.Errorf("instruction %d: the account count is not readable: %w", at, err)
	}
	data = data[n:]

	used := 2 * n // the program index and the account count are already spent
	for i := range count {
		index, n, err := readCompactU16(data)
		if err != nil {
			return ix, 0, fmt.Errorf("instruction %d account %d: %w", at, i, err)
		}
		if index >= len(keys) {
			return ix, 0, fmt.Errorf(
				"instruction %d account %d: names account %d, and the message has %d",
				at, i, index, len(keys))
		}
		ix.Accounts = append(ix.Accounts, keys[index])
		data = data[n:]
		used += n
	}

	length, n, err := readCompactU16(data)
	if err != nil {
		return ix, 0, fmt.Errorf("instruction %d: the data length is not readable: %w", at, err)
	}
	data = data[n:]
	used += n
	if len(data) < length {
		return ix, 0, fmt.Errorf("instruction %d: claims %d bytes of data but has %d", at, length, len(data))
	}
	ix.Data = data[:length]
	used += length
	return ix, used, nil
}

// Summarise describes a signature as YAML.
//
// It is YAML rather than prose for two reasons. A person approving a signature
// reads it as structure - what pays, what may change, what it calls - and
// indentation carries that where a paragraph cannot. And it is stable: what a
// person approved can be pasted somewhere and compared, which a sentence
// written for the moment cannot.
//
// Every case has the same shape, so a reader never has to guess. A transaction
// carries its facts. Anything else carries a note saying what it is, because
// the most useful thing to say about a signature that is not a transaction is
// that it is not one.
//
// Nothing here falls back to a hex dump for a transaction. A person asked to
// approve bytes they cannot read has been asked nothing.
func Summarise(name string, data []byte) string {
	var out strings.Builder
	fmt.Fprintf(&out, "signature:\n  key: %s\n", name)

	if LooksLikeMessage(data) {
		msg, err := DecodeMessage(data)
		if err != nil {
			fmt.Fprintf(&out,
				"  kind: unreadable-solana-transaction\n  reason: %q\n", err.Error())
			out.WriteString("  warning: this could not be read, and nothing about it should be approved\n")
			return strings.TrimRight(out.String(), "\n")
		}
		msg.writeYAML(&out)
		return strings.TrimRight(out.String(), "\n")
	}

	fmt.Fprintf(&out, "  kind: not-a-solana-transaction\n  size_bytes: %d\n", len(data))
	if text := printable(data); text != "" {
		fmt.Fprintf(&out, "  data: %q\n", text)
	} else {
		fmt.Fprintf(&out, "  data: %s\n", hexPreview(data))
	}
	return strings.TrimRight(out.String(), "\n")
}

// writeYAML is the transaction, in the order a person decides in: who pays,
// what may change, what it calls, and only then bytes.
func (m Message) writeYAML(out *strings.Builder) {
	out.WriteString("  kind: solana-transaction\n")
	fmt.Fprintf(out, "  fee_payer: %s\n", m.FeePayer)
	fmt.Fprintf(out, "  blockhash: %s\n", m.Blockhash)

	out.WriteString("  accounts:\n")
	for _, a := range m.Accounts {
		role := "read_only"
		switch {
		case a.Signer && a.Writable:
			role = "signs+may_write"
		case a.Signer:
			role = "signs"
		case a.Writable:
			role = "may_write"
		}
		fmt.Fprintf(out, "    - address: %s\n      role: %s\n", a.Address, role)
	}

	if short := m.shortInstructions(); len(short) > 0 {
		out.WriteString("  warning: this transaction cannot be carried out\n")
		for _, why := range short {
			fmt.Fprintf(out, "    - %s\n", why)
		}
	}

	out.WriteString("  instructions:\n")
	for _, ix := range m.Instructions {
		fmt.Fprintf(out, "    - program: %s\n", describeProgram(ix.ProgramID))
		fmt.Fprintf(out, "      program_id: %s\n", ix.ProgramID)
		for _, account := range ix.Accounts {
			fmt.Fprintf(out, "      account: %s\n", account)
		}
		switch {
		case describeInstruction(ix) != "":
			fmt.Fprintf(out, "      does: %q\n", describeInstruction(ix))
		case printable(ix.Data) != "":
			// Text the instruction carries. For a memo this is the whole
			// point of the transaction, and showing it as hex would leave the
			// one thing worth reading out of the one thing a person cannot
			// read.
			fmt.Fprintf(out, "      data: %q\n", printable(ix.Data))
		default:
			fmt.Fprintf(out, "      data: %s\n", hexPreview(ix.Data))
		}
	}

	if m.LookupTables > 0 {
		// Said plainly rather than left out: those names live on chain, and
		// a list that silently omitted them would be shorter than the list
		// the transaction touches.
		fmt.Fprintf(out, "  lookup_tables: %d\n", m.LookupTables)
		out.WriteString(
			"  warning: some account names live in address lookup tables and are not shown; " +
				"resolving one needs an RPC node\n")
	}
}

// accountsTouched is every account the transaction may write to, which is the
// list that says what approving costs.
func (m Message) accountsTouched() []Account {
	var out []Account
	for _, a := range m.Accounts {
		if a.Writable {
			out = append(out, a)
		}
	}
	return out
}

func (m Message) signers() []Account {
	var out []Account
	for _, a := range m.Accounts {
		if a.Signer {
			out = append(out, a)
		}
	}
	return out
}

// describeInstruction renders the instructions whose meaning is fixed by the
// protocol rather than by a program's own interface.
//
// Only the System program qualifies. A transfer's meaning is not a matter of
// interpretation: the discriminant and the amount are the instruction. What a
// token program or a contract does is defined by that program's own interface,
// which is not here and cannot be guessed at - so those fall through to the
// data, and the accounts above already say what it may change.
func describeInstruction(ix DecodedInstruction) string {
	if ix.ProgramID != SystemProgramID || len(ix.Data) < 4 {
		return ""
	}
	kind := binary.LittleEndian.Uint32(ix.Data[:4])
	amount := func() uint64 {
		if len(ix.Data) < 12 {
			return 0
		}
		return binary.LittleEndian.Uint64(ix.Data[4:12])
	}
	destination := func() string {
		if len(ix.Accounts) < 2 {
			return "?"
		}
		return ix.Accounts[1]
	}

	// A System instruction's accounts are fixed by the program, so an
	// instruction that names fewer of them than it needs cannot be carried
	// out. Saying "transfers N lamports to ?" would be describing a
	// transaction that cannot exist, so nothing is described and the
	// shortfall is reported at the top instead, where a warning belongs.
	switch kind {
	case 0:
		if len(ix.Accounts) >= 2 {
			return fmt.Sprintf("creates account %s with %d lamports", ix.Accounts[1], amount())
		}
	case 2:
		if len(ix.Accounts) >= 2 {
			return fmt.Sprintf("transfers %d lamports to %s", amount(), destination())
		}
	case 3:
		if len(ix.Accounts) >= 2 {
			return fmt.Sprintf("creates account %s with %d lamports, from a seed", ix.Accounts[1], amount())
		}
	case 11:
		if len(ix.Accounts) >= 2 {
			return fmt.Sprintf("transfers %d lamports to %s, from an account with a seed", amount(), destination())
		}
	}
	return ""
}

// shortInstructions are the instructions whose shape cannot be carried out,
// by name rather than by description: a System transfer with one account is
// not a transfer, and rendering it as one would be the worst thing this file
// could do.
func (m Message) shortInstructions() []string {
	var out []string
	for i, ix := range m.Instructions {
		if ix.ProgramID != SystemProgramID || len(ix.Data) < 4 {
			continue
		}
		needs := 0
		switch binary.LittleEndian.Uint32(ix.Data[:4]) {
		case 0, 3: // CreateAccount, CreateAccountWithSeed
			needs = 2
		case 2, 11: // Transfer, TransferWithSeed
			needs = 2
		}
		if needs > 0 && len(ix.Accounts) < needs {
			out = append(out, fmt.Sprintf(
				"instruction %d calls the System program but names %d of the 2 accounts it needs",
				i+1, len(ix.Accounts)))
		}
	}
	return out
}

// describeProgram names a program, because a base58 id is not something a
// person can decide on.
func describeProgram(id string) string {
	switch id {
	case MemoProgramID:
		return "the SPL Memo program - writes a note, moves nothing"
	case SystemProgramID:
		return "the System program - moves lamports between accounts"
	case TokenProgramID:
		return "the SPL Token program - moves tokens"
	case AssociatedTokenProgramID:
		return "the associated-token program - creates an account bound to a token"
	default:
		return "program " + id + " - what it does is defined by that program, not by this reading"
	}
}

func printable(data []byte) string {
	const max = 200
	if len(data) == 0 || len(data) > max {
		return ""
	}
	for _, b := range data {
		if b != '\n' && b != '\t' && (b < 0x20 || b > 0x7e) {
			return ""
		}
	}
	return strings.TrimSpace(string(data))
}

func hexPreview(data []byte) string {
	const max = 48
	if len(data) <= max {
		return hexOf(data)
	}
	return hexOf(data[:max]) + fmt.Sprintf("... (%d bytes)", len(data))
}

func hexOf(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}
