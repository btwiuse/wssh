package solana

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/routercafe/routercafe/auth/agentkey"
	"github.com/routercafe/routercafe/auth/siws"
)

// BuildTransaction assembles an unsigned versioned transaction from a
// request's raw instructions.
//
// This exists so that a session holding nothing but an ssh-agent can sign a
// Solana transaction. The agent protocol has no operation for that, and
// neither does the agent in a plain ssh -A: it will sign whatever bytes it is
// given, but it will not know what a transaction is. Building the bytes here
// and asking the agent for a signature over them is the whole of what a
// transaction needs from a signer, so the agent never has to learn more.
//
// The layout is fixed and shallow, and it is checked against bytes a Solana
// library produced in a browser: version, a three-byte header, the account
// keys, the blockhash, the instructions, and a lookup count. The blockhash
// sits before the instructions, which reads oddly and is not a mistake - a
// hand-written message that put it last was rejected by the cluster as an
// invalid discriminator, and this one simulates.
//
// The account keys go in the four groups Solana requires, in order: writable
// signers, read-only signers, writable accounts, read-only accounts. The
// instruction indices are remapped when that happens, because an index means
// a position in the key list and the list is what moved.
//
// That ordering is not a convention. A message whose keys are not grouped this
// way is rejected before it runs, and the header is what says how the keys
// were grouped - so the counts and the order have to agree with each other or
// a read-only account reads as writable in an approval somebody is about to
// sign.
//
// An instruction that asks for a signer this path cannot supply is refused
// rather than approximated: a transaction missing one of its signatures is one
// the cluster rejects with nothing that points here.
func BuildTransaction(req agentkey.SolanaTxRequest) ([]byte, error) {
	if req.Signer == "" {
		return nil, errors.New("no signer: this path signs with a key it holds, so it has to be named")
	}
	blockhash, err := decode32(req.Blockhash, "blockhash")
	if err != nil {
		return nil, err
	}
	// The named signer is the fee payer, and not because the caller said so
	// twice: Solana requires the fee payer to be a required signer, so a
	// transaction with one signer has that signer paying.
	payer, err := decode32(req.Signer, "signer")
	if err != nil {
		return nil, err
	}
	if len(req.Instructions) == 0 {
		return nil, errors.New("the request carries no instructions")
	}

	keys := newKeyTable(payer)

	type compiled struct {
		program uint16
		keys    []uint16
		data    []byte
	}
	ixs := make([]compiled, 0, len(req.Instructions))

	for i, ix := range req.Instructions {
		program, err := decode32(ix.ProgramID, "program id")
		if err != nil {
			return nil, fmt.Errorf("instruction %d: %w", i, err)
		}
		// A program id is never writable and never signs, whatever the
		// request says about it: that is a property of what a program is,
		// not of the instruction.
		progIdx := keys.internAs(program, false, false)

		accounts := make([]uint16, 0, len(ix.Accounts)+1)
		if sourceIsFeePayer(ix) {
			// A System transfer's accounts are [source, destination] and
			// the source is whoever signs, which is the fee payer - the
			// request cannot name it because the signer is not known when
			// the request is written. Inserting it here is the one place
			// that knows both, and getting this wrong produces a
			// transaction the cluster rejects with an account count that
			// points nowhere near the cause.
			accounts = append(accounts, 0)
		}
		for j, a := range ix.Accounts {
			raw, err := decode32(a.Address, "account")
			if err != nil {
				return nil, fmt.Errorf("instruction %d account %d: %w", i, j, err)
			}
			if a.IsSigner && !equalBytes(raw, payer) {
				return nil, fmt.Errorf(
					"instruction %d account %d asks %s to sign, and the only key "+
						"available is the fee payer's: use a wallet for this",
					i, j, a.Address)
			}
			accounts = append(accounts, keys.internAs(raw, a.IsSigner, a.IsWritable))
		}

		data, err := siws.Base58Decode(ix.DataBase58)
		if err != nil {
			return nil, fmt.Errorf("instruction %d has data that is not base58: %w", i, err)
		}
		ixs = append(ixs, compiled{program: progIdx, keys: accounts, data: data})
	}

	// Sort the keys into the four groups and move every instruction index
	// with them. Stable, so two accounts in the same group keep the order
	// they were first mentioned in - which is what put the payer first and
	// is the only thing the golden fixture pins.
	order, header, err := keys.group()
	if err != nil {
		return nil, err
	}
	for i := range ixs {
		ixs[i].program = order[ixs[i].program]
		for j, k := range ixs[i].keys {
			ixs[i].keys[j] = order[k]
		}
	}
	ordered := make([][]byte, 0, len(keys.list))
	for _, old := range order {
		ordered = append(ordered, keys.list[old])
	}

	msg := []byte{0x80} // version 0; the high bit marks the message as versioned
	msg = append(msg, header.required)
	msg = append(msg, header.readonlySigned)
	msg = append(msg, header.readonlyUnsigned)
	msg = appendCompactU16(msg, len(ordered))
	for _, k := range ordered {
		msg = append(msg, k...)
	}
	msg = append(msg, blockhash...)
	msg = appendCompactU16(msg, len(ixs))
	for _, ix := range ixs {
		msg = appendCompactU16(msg, int(ix.program))
		msg = appendCompactU16(msg, len(ix.keys))
		for _, k := range ix.keys {
			msg = appendCompactU16(msg, int(k))
		}
		msg = appendCompactU16(msg, len(ix.data))
		msg = append(msg, ix.data...)
	}
	msg = appendCompactU16(msg, 0) // no address table lookups

	// The wire shape an agent is handed: a compact-u16 signature count, that
	// many empty 64-byte slots, then the message. A plain ssh-agent signs the
	// message; the slot is only here because that is the shape it has to fit
	// into afterwards.
	out := appendCompactU16(nil, 1)
	out = append(out, make([]byte, ed25519.SignatureSize)...)
	return append(out, msg...), nil
}

// systemAccountCount is how many accounts each System instruction takes.
// A request may name fewer, and the missing one is the fee payer; anything
// else missing is a transaction that cannot be carried out, which
// DecodeMessage's reader reports rather than papering over.
var systemAccountCount = map[uint32]int{
	0:  2, // CreateAccount
	1:  2, // Assign
	2:  2, // Transfer
	3:  2, // CreateAccountWithSeed
	4:  1, // AdvanceNonceAccount
	5:  2, // WithdrawNonceAccount
	6:  1, // InitializeNonceAccount
	7:  1, // AuthorizeNonceAccount
	8:  2, // Allocate
	9:  0, // AllocateWithSeed
	10: 1, // AssignWithSeed
	11: 2, // TransferWithSeed
	12: 1, // UpgradeNonceAccount
}

// sourceIsFeePayer reports whether an instruction is a System instruction
// whose first account is whoever signs, which the request leaves out.
//
// The System program is the one case where the answer is not a matter of the
// program's own interface: a transfer's source is the signer, and the signer
// is the fee payer, because Solana requires the fee payer to sign.
func sourceIsFeePayer(ix agentkey.SolanaInstruction) bool {
	if ix.ProgramID != SystemProgramID {
		return false
	}
	data, err := siws.Base58Decode(ix.DataBase58)
	if err != nil || len(data) < 4 {
		return false
	}
	needed, known := systemAccountCount[binary.LittleEndian.Uint32(data[:4])]
	return known && needed > len(ix.Accounts)
}

// keyTable interns account keys so the same one is named once, with the roles
// it was first seen with.
type keyTable struct {
	list  [][]byte
	roles []keyRole
	index map[string]uint16
}

// keyRole is what a key is in a message. Solana has exactly four kinds and
// they are the groups the keys have to be sorted into.
type keyRole struct {
	signer   bool
	writable bool
}

// group is the three-byte header, once the keys have been sorted.
type groupHeader struct {
	required         byte
	readonlySigned   byte
	readonlyUnsigned byte
}

func newKeyTable(payer []byte) *keyTable {
	t := &keyTable{index: map[string]uint16{}}
	// The payer signs and pays, so it is a writable signer. That is Solana's
	// requirement rather than a convenience: the fee payer must be a required
	// signer, and a signer that is not writable cannot be the fee payer.
	t.internAs(payer, true, true)
	return t
}

// internAs adds a key, or returns the index it already has.
//
// Roles only ever get added, never taken away: an account named writable by
// one instruction and read-only by another is writable, and taking the last
// word seen would understate what the transaction can change.
func (t *keyTable) internAs(key []byte, signer, writable bool) uint16 {
	if i, ok := t.index[string(key)]; ok {
		t.roles[i].signer = t.roles[i].signer || signer
		t.roles[i].writable = t.roles[i].writable || writable
		return i
	}
	i := uint16(len(t.list))
	t.list = append(t.list, key)
	t.roles = append(t.roles, keyRole{signer: signer, writable: writable})
	t.index[string(key)] = i
	return i
}

// group sorts the keys into Solana's four groups and reports the header that
// describes the result. The returned slice maps an old index to a new one, so
// every instruction index can be rewritten through it.
//
// The four groups, in the order Solana requires them: writable signers,
// read-only signers, writable accounts, read-only accounts. Sorting is stable,
// so the order keys were first mentioned in survives within a group; that is
// what keeps the fee payer at index 0 and the golden fixture byte for byte.
func (t *keyTable) group() ([]uint16, groupHeader, error) {
	n := len(t.list)
	if n > 1<<8 {
		return nil, groupHeader{}, fmt.Errorf(
			"a transaction naming %d accounts is more than the header can say", n)
	}
	order := make([]uint16, 0, n)
	for rank := range 4 {
		for i, role := range t.roles {
			if groupOf(role) == rank {
				order = append(order, uint16(i))
			}
		}
	}

	remap := make([]uint16, n)
	for new, old := range order {
		remap[old] = uint16(new)
	}
	var header groupHeader
	for _, i := range order {
		role := t.roles[i]
		switch groupOf(role) {
		case 0:
			header.required++
		case 1:
			header.readonlySigned++
		case 3:
			header.readonlyUnsigned++
		}
	}
	return remap, header, nil
}

// groupOf is the sort rank of a key: writable signers first, then read-only
// signers, then writable accounts, then read-only accounts.
func groupOf(role keyRole) int {
	switch {
	case role.signer && role.writable:
		return 0
	case role.signer:
		return 1
	case role.writable:
		return 2
	default:
		return 3
	}
}

// appendCompactU16 writes Solana's compact-u16: seven bits per byte, low
// first, with the high bit marking that another byte follows.
func appendCompactU16(dst []byte, n int) []byte {
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

func decode32(s, what string) ([]byte, error) {
	raw, err := siws.Base58Decode(s)
	if err != nil {
		return nil, fmt.Errorf("the %s is not base58: %w", what, err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("the %s is %d bytes, want 32", what, len(raw))
	}
	return raw, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
