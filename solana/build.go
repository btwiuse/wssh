package solana

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
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
// The account keys are in the order they were first mentioned, the fee payer
// first. Solana requires every signer before any account that does not sign,
// so with one signer that means: the payer, then whatever the instructions
// name. An instruction that asks for a signer this path cannot supply is
// refused rather than approximated - a transaction missing one of its
// signatures is one the cluster rejects with nothing that points here.
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
		progIdx := keys.intern(program)

		accounts := make([]uint16, 0, len(ix.Accounts))
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
			accounts = append(accounts, keys.intern(raw))
		}

		data, err := siws.Base58Decode(ix.DataBase58)
		if err != nil {
			return nil, fmt.Errorf("instruction %d has data that is not base58: %w", i, err)
		}
		ixs = append(ixs, compiled{program: progIdx, keys: accounts, data: data})
	}

	// One signer - the payer - and nothing else. Every other account is
	// unsigned and goes in the third group, which is what the byte named
	// numReadonlyUnsignedAccounts actually counts: accounts that are
	// neither signers nor read-only, and therefore writable. The name reads
	// the other way round, which is how this was once described backwards.
	//
	// This matches what a Solana library produces for the same request, and
	// that is the constraint: the golden fixture is bytes the cluster
	// accepted, so deviating from it would trade a working encoder for a
	// tidier one.
	unsignedCount := len(keys.list) - 1
	if len(keys.list) > 1<<8 || unsignedCount > 1<<8 {
		return nil, fmt.Errorf("a transaction naming %d accounts is more than the header can say", len(keys.list))
	}

	msg := []byte{0x80}  // version 0; the high bit marks the message as versioned
	msg = append(msg, 1) // one required signature: the payer
	msg = append(msg, 0) // no readonly signers
	msg = append(msg, byte(unsignedCount))
	msg = appendCompactU16(msg, len(keys.list))
	for _, k := range keys.list {
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

// keyTable interns account keys so the same one is named once, with the fee
// payer always first: it is the signer, and Solana wants signers before
// everything else.
type keyTable struct {
	list  [][]byte
	index map[string]uint16
}

func newKeyTable(payer []byte) *keyTable {
	t := &keyTable{index: map[string]uint16{}}
	t.intern(payer)
	return t
}

func (t *keyTable) intern(key []byte) uint16 {
	if i, ok := t.index[string(key)]; ok {
		return i
	}
	i := uint16(len(t.list))
	t.list = append(t.list, key)
	t.index[string(key)] = i
	return i
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
