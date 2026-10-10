// scripts/sol-tx/build_test.ts
//
// The bytes a Solana library produced in a browser, for one memo request.
//
// These are the same fixture solana/golden_test.go holds, and they are
// written out rather than generated: hand-written serialisation is exactly
// the thing that is right locally and wrong on chain, so the only comparison
// worth having is against bytes the cluster accepted. A builder that
// disagrees fails here rather than in front of a person whose memo went
// nowhere.
//
// The request behind it:
//
//	blockhash  B1P9Y4gHoGaSX9FS6nUeAb5Jx3ATjNPGmc7YE4jfEQUZ (live at the time)
//	signer    5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5
//	program   MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
//	account   the payer, as signer and writable
//	data      base58 3Bxs4NN2, which decodes to "Memo"
//
// An earlier hand-written message with the blockhash last was rejected
// outright as an invalid discriminator, so the order below is the one that
// works and not the one that reads most naturally.

import { assertEquals, assertThrows } from "jsr:@std/assert";

import { buildTransaction, messageOf, MEMO_PROGRAM_ID } from "./build.ts";
import { encodeBase58 } from "./base58.ts";
import type { SolanaTxRequest } from "./agent.ts";

const GOLDEN_MESSAGE_HEX = "" +
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
  "00"; // no address table lookups

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)));
}

const PAYER = "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5";

function goldenRequest(): SolanaTxRequest {
  return {
    blockhash: "B1P9Y4gHoGaSX9FS6nUeAb5Jx3ATjNPGmc7YE4jfEQUZ",
    signer: PAYER,
    instructions: [{
      programId: MEMO_PROGRAM_ID,
      accounts: [{ address: PAYER, isSigner: true, isWritable: true }],
      data: "3Bxs4NN2",
    }],
  };
}

Deno.test("the message matches the bytes a Solana library produced", () => {
  const got = messageOf(buildTransaction(goldenRequest()));
  const want = hexToBytes(GOLDEN_MESSAGE_HEX);
  assertEquals([...got], [...want]);
});

// The signature section is not part of what gets signed, but it is part of
// what the cluster is handed, and a wrong count or a short slot region is a
// transaction the cluster rejects before it reads an instruction.
Deno.test("the unsigned transaction is one empty signature then the message", () => {
  const tx = buildTransaction(goldenRequest());
  assertEquals(tx[0], 1, "one signature");
  assertEquals(tx.length, 1 + 64 + GOLDEN_MESSAGE_HEX.length / 2);
  const slot = tx.subarray(1, 65);
  assertEquals([...new Set([...slot])], [0], "the slot is empty for the agent to fill");
  assertEquals([...tx.subarray(65)], [...hexToBytes(GOLDEN_MESSAGE_HEX)]);
});

// The cases that cost a build its usefulness, all of them refused rather than
// approximated: a transaction the cluster would reject is worse than no
// transaction, because the only feedback arrives after it is broadcast.
Deno.test("what cannot be built is refused with a reason", () => {
  const noSigner = goldenRequest();
  noSigner.signer = undefined;
  assertThrows(() => buildTransaction(noSigner), Error, "no signer");

  const noInstructions = goldenRequest();
  noInstructions.instructions = [];
  assertThrows(() => buildTransaction(noInstructions), Error, "no instructions");

  // Thirty-one ones are thirty-one zero bytes, and a blockhash is thirty-two.
  const shortBlockhash = goldenRequest();
  shortBlockhash.blockhash = "1111111111111111111111111111111";
  assertThrows(() => buildTransaction(shortBlockhash), Error, "blockhash is 31 bytes");

  // An instruction asking for a second signer: the one key here cannot
  // supply it, and saying so is the whole point of the check.
  const secondSigner = goldenRequest();
  secondSigner.instructions = [{
    programId: MEMO_PROGRAM_ID,
    accounts: [{
      address: "41AZvbsCJJoKT27SCLAd7HCNK7mdU2TA9LLUWwyjnyLA",
      isSigner: true,
      isWritable: true,
    }],
    data: "3Bxs4NN2",
  }];
  assertThrows(() => buildTransaction(secondSigner), Error, "use a wallet for this");
});

// The payer is named first and every other account after it, because Solana
// wants every signer before anything that does not sign. A builder that
// interned them the other way round produces a transaction that parses and is
// rejected, which is the worst of both.
Deno.test("the payer is the first account key", () => {
  const other = "41AZvbsCJJoKT27SCLAd7HCNK7mdU2TA9LLUWwyjnyLA";
  const req = goldenRequest();
  req.instructions = [{
    programId: MEMO_PROGRAM_ID,
    accounts: [
      { address: other, isSigner: false, isWritable: true },
      { address: PAYER, isSigner: true, isWritable: true },
    ],
    data: "3Bxs4NN2",
  }];

  const msg = messageOf(buildTransaction(req));
  // version, three header bytes, a compact-u16 count of keys, then the keys:
  // the payer, the program, and the other account, in that order.
  assertEquals([...msg.subarray(0, 4)], [0x80, 1, 0, 2], "version and header");
  assertEquals(msg[4], 3, "three account keys");
  const keyAt = (i: number) =>
    encodeBase58(new Uint8Array(msg.subarray(5 + i * 32, 5 + (i + 1) * 32)));
  assertEquals(keyAt(0), PAYER, "the payer is first");
  assertEquals(keyAt(1), MEMO_PROGRAM_ID);
  assertEquals(keyAt(2), other);
});