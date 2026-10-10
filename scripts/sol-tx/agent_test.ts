// scripts/sol-tx/agent_test.ts
//
// The two things this file exists for are both ways a transaction comes back
// wrong without looking wrong: a field read in the wrong encoding, and a
// signature put in the wrong place. Neither throws, and both produce bytes of
// exactly the right length.

import { assertEquals, assertThrows } from "jsr:@std/assert";

import {
  AgentHasNoExtension,
  signedTransactionBytes,
} from "./agent.ts";

const PAYER = "5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5";

// One real signed transaction, the same one solana/fee_test.go pins. 173 bytes.
const SIGNED_HEX =
  "01923ce4dc70fae15fb746adbf6ab5998dd8257e94e932aad17b3314e489882bb4fe9294c5a05" +
  "05a993b5d10cfe8a12fd2063fd1c315107b283f24b1bcf1cdb00580010001021c497d4515909b7" +
  "2923389c97f7424e9631cf38b7f1a4c9969aea635058d077f054a535a992921064d24e87160da38" +
  "7c35b5ddbc92bb81e41fa8404105448d94ade940a9e7622557a136e1d923a513bb7dd43254d6" +
  "b91fba3f50a26b04176201010006046558672d2f00";

Deno.test("the signed transaction comes back as bytes, not as hex read as base64", () => {
  const bytes = signedTransactionBytes({ signedTransaction: SIGNED_HEX });
  assertEquals(bytes.length, SIGNED_HEX.length / 2);
  // The first byte is the signature count and the next 64 are a signature.
  // Read as base64 instead, this would have been 259 bytes of something that
  // still looked like a transaction.
  assertEquals(bytes[0], 1);
  assertEquals(bytes[65], 0x80, "the message starts with version 0");
});

// A response is only worth reporting if it is shaped like one. An odd number
// of hex characters is the signature of an encoding mistake, and saying so is
// the difference between a wrong transaction and no transaction.
Deno.test("a response that is not hex is refused", () => {
  assertThrows(
    () => signedTransactionBytes({ signedTransaction: "abc" }),
    Error,
    "not a whole number of bytes",
  );
  assertThrows(
    () => signedTransactionBytes({ signedTransaction: "zzzz" }),
    Error,
    "not hex",
  );
  assertThrows(
    () => signedTransactionBytes({}),
    Error,
    "no signed transaction",
  );
});

// The extension being absent is an answer, not a fault, and the caller cannot
// fall back unless it can tell it apart from every other refusal. That is the
// whole reason this is a class rather than a sentence.
Deno.test("no extension is its own kind of answer", () => {
  const err = new AgentHasNoExtension();
  assertEquals(err instanceof AgentHasNoExtension, true);
  assertEquals(err instanceof Error, true);
  assertEquals(err.message.includes("bin/sol-tx"), true, "it says what to do");
});
