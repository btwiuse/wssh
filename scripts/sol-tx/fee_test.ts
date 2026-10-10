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
    0x80, // version 0, top bit set
    0x01, // header: required signatures
    0x00, // header: readonly signed
    0x00, // header: readonly unsigned
    ...compact(1), // one static account key
    ...PAYER,
  ];
  assertEquals(feePayer(signedWith(message)), encodeBase58(PAYER));
});

// The two above can both be green and still not mean anything: the first
// version of the versioned fixture wrote a one-byte header, which is what the
// reader expected, so the two agreed and the real answer was wrong. This one
// is bytes Go's own builder produced for a memo, held here so both readers
// are pinned to a transaction rather than to a fixture written alongside them.
Deno.test("feePayer reads a transaction Go built", () => {
  const signed = hexToBytes(
    "01923ce4dc70fae15fb746adbf6ab5998dd8257e94e932aad17b3314e489882bb4fe9294c5a0505a993b5d10cfe8a12fd2063fd1c315107b283f24b1bcf1cdb00580010001021c497d4515909b72923389c97f7424e9631cf38b7f1a4c9969aea635058d077f054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d94ade940a9e7622557a136e1d923a513bb7dd43254d6b91fba3f50a26b04176201010006046558672d2f00",
  );
  assertEquals(feePayer(signed), "2uRQmq8fQXKLmm8fSdUqkHr8UbwpyEA687Jgut16DJrJ");
});

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)));
}

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
