// scripts/sol-tx/fee_test.ts
//
// The fee payer is read out of the signed bytes rather than out of the
// request, so these cover the two message layouts there are. A versioned
// message counts its static keys; a legacy one does not, and a reader that
// expects a count there finds a plausible looking key that is not the payer.

import { assertEquals, assertThrows } from "jsr:@std/assert";
import { feePayer } from "./fee.ts";
import { encodeBase58 } from "./base58.ts";

const PAYER = new Uint8Array(32).map((_, i) => i + 1);

function compact(n: number): number[] {
  if (n > 127) throw new Error("these fixtures are all one byte");
  return [n];
}

function signedWith(message: number[]): Uint8Array {
  return new Uint8Array([...compact(1), ...new Array(64).fill(0), ...message]);
}

Deno.test("feePayer reads a versioned transaction", () => {
  const message = [
    0x80, // version 0
    0x00, // header
    ...compact(1), // one static account key
    ...PAYER,
  ];
  assertEquals(feePayer(signedWith(message)), encodeBase58(PAYER));
});

Deno.test("feePayer reads a legacy transaction", () => {
  const message = [
    ...compact(1), // required signatures
    ...compact(0), // readonly signed
    ...compact(0), // readonly unsigned
    ...PAYER, // one account key, unprefixed
  ];
  assertEquals(feePayer(signedWith(message)), encodeBase58(PAYER));
});

// Silence is the honest answer when the bytes cannot be read, so every one
// of these has to throw rather than name something that is not there.
Deno.test("feePayer refuses what it cannot read", () => {
  assertThrows(() => feePayer(new Uint8Array(0)), Error);
  assertThrows(() => feePayer(new Uint8Array([5, 1, 2, 3, 4, 5])), Error, "claims 5 signatures");
  assertThrows(() => feePayer(new Uint8Array([1, ...new Array(64).fill(0)])), Error);
});
