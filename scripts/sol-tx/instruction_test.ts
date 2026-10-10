// scripts/sol-tx/instruction_test.ts
//
// Tests for the parts of the script that have no external dependencies:
// base58 round-trips, the SystemProgram transfer encoding, and the
// rawCall input validation.

import { assertEquals, assertThrows } from "jsr:@std/assert";
import { decodeBase58, encodeBase58, isBase58 } from "./base58.ts";
import { memo, rawCall, transferLamports } from "./instruction.ts";

Deno.test("base58 roundtrip survives a Solana-shaped byte sequence", () => {
  // 32-byte public key with leading zeros - the kind of thing Solana
  // addresses are made of, and where naive base58 decoders go wrong.
  const bytes = new Uint8Array(32);
  bytes[0] = 0;
  bytes[31] = 1;
  const encoded = encodeBase58(bytes);
  const decoded = decodeBase58(encoded);
  assertEquals(decoded, bytes);
  assertEquals(decoded.length, 32);
});

Deno.test("base58 isBase58 rejects alphabet drift", () => {
  assertEquals(isBase58("11111111111111111111111111111111"), true); // all-zeros addr
  assertEquals(isBase58(""), false);
  assertEquals(isBase58("0"), false); // 0 is not in the Bitcoin alphabet
  assertEquals(isBase58("O"), false); // O is not in the alphabet either
  assertEquals(isBase58("I"), false); // I is not in the alphabet
  assertEquals(isBase58("l"), false); // l is not in the alphabet
});

Deno.test("transferLamports encodes discriminant + amount as 12 LE bytes", () => {
  const ix = transferLamports("5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5", 1);
  assertEquals(ix.programId, "11111111111111111111111111111111");
  assertEquals(ix.accounts.length, 1);
  assertEquals(ix.accounts[0].address, "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5");
  assertEquals(ix.accounts[0].isSigner, false);
  assertEquals(ix.accounts[0].isWritable, true);
  // base58 decode the data and check its layout
  const data = decodeBase58(ix.data);
  assertEquals(data.length, 12);
  assertEquals(data[0], 2);
  assertEquals(data[1], 0);
  assertEquals(data[2], 0);
  assertEquals(data[3], 0);
  assertEquals(data[4], 1); // lamports=1, low byte
  for (let i = 5; i < 12; i++) assertEquals(data[i], 0);
});

Deno.test("transferLamports refuses non-base58 destinations", () => {
  assertThrows(
    () => transferLamports("not-base58", 1),
    Error,
    "Solana address",
  );
});

Deno.test("transferLamports refuses a zero transfer", () => {
  assertThrows(
    () => transferLamports("5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5", 0),
    Error,
    "nothing",
  );
});

Deno.test("rawCall validates inputs", () => {
  assertThrows(() => rawCall("prog", [], "data"), Error, "at least one");
  assertThrows(() => rawCall("prog", ["addr"], ""), Error, "needs some data");
  assertThrows(
    () => rawCall("bad!", ["5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"], "data"),
    Error,
    "program id",
  );
});

Deno.test("rawCall passes accounts through as non-signer writable", () => {
  const ix = rawCall("programid", [
    "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5",
    "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC6",
  ], "3Bxs");
  assertEquals(ix.accounts.length, 2);
  for (const a of ix.accounts) {
    assertEquals(a.isSigner, false);
    assertEquals(a.isWritable, true);
  }
});

Deno.test("memo encodes text as UTF-8 base58 data with empty accounts", () => {
  const ix = memo("hello from wssh");
  assertEquals(ix.programId, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
  // The accounts list is empty on the wire: the agent protocol's
  // isNoAccountProgram carve-out for memo lets it through, and the
  // wallet fills the signer itself.
  assertEquals(ix.accounts.length, 0);
  // The data is the UTF-8 bytes of the memo, base58-encoded.
  assertEquals(decodeBase58(ix.data), new TextEncoder().encode("hello from wssh"));
});

Deno.test("memo refuses an empty string", () => {
  assertThrows(
    () => memo(""),
    Error,
    "nothing",
  );
});

Deno.test("memo refuses text longer than 566 bytes", () => {
  const longText = "x".repeat(600);
  assertThrows(
    () => memo(longText),
    Error,
    "566 bytes",
  );
});