package solana

import (
	"encoding/hex"
	"testing"
)

// The message body a Solana library built in a browser for one memo
// request, kept as the thing a builder is measured against.
//
// It is written out rather than generated so that a builder which disagrees
// with it fails a test instead of quietly producing a transaction the cluster
// refuses. The request behind it:
//
//	blockhash  B1P9Y4gHoGaSX9FS6nUeAb5Jx3ATjNPGmc7YE4jfEQUZ (live at the time)
//	payer      5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5
//	program    MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
//	account    the payer, as signer and writable
//	data       base58 3Bxs4NN2, which decodes to "Memo"
//
// The cluster accepted these bytes: simulating them reached the point of
// reporting that the payer does not exist there, which is a statement about
// the account rather than about the encoding. An earlier hand-written
// message with the blockhash last was rejected outright, so the order below
// is the one that works and not the one that reads most naturally.
const goldenMessageHex = "" +
	"80" + // version 0
	"010001" + // numRequiredSignatures=1, numReadonlySigned=0, numReadonlyUnsigned=1
	"02" + // two static account keys
	"44a6815795e5c35909318e36848c95a470d31ee022aa4db8dd627971c3dc271a" + // the payer
	"054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d" + // the memo program
	"94ade940a9e7622557a136e1d923a513bb7dd43254d6b91fba3f50a26b041762" + // the blockhash, before the instructions
	"01" + // one instruction
	"01" + // program id index 1
	"01" + // one account
	"00" + // account index 0, the payer
	"06" + // six bytes of data
	"046558672d2f" + // base58 3Bxs4NN2
	"00" // no address table lookups

func goldenMessage(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString(goldenMessageHex)
	if err != nil {
		t.Fatalf("the golden message is not hex: %v", err)
	}
	return raw
}
