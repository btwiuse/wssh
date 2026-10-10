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

// One real signed transaction, the same one solana/fee_test.go pins, as the
// answer carries it: base64, because the field is a byte slice on the other
// side of the protocol and encoding/json writes it that way.
const SIGNED_B64 =
"AZI85Nxw+uFft0atv2q1mY3YJX6U6TKq0XszFOSJiCu0/pKUxaBQWpk7XRDP6KEv0gY/" +
  "0cMVEHsoPySxvPHNsAWAAQABAhxJfUUVkJtykjOJyX90JOljHPOLfxpMmWmupjUFjQd/" +
  "BUpTWpkpIQZNJOhxYNo4fHw1td28kruB5B+oQEEFRI2UrelAqediJVehNuHZI6UTu33U" +
  "MlTWuR+6P1CiawQXYgEBAAYEZVhnLS8A";

Deno.test("the signed transaction comes back as bytes", () => {
  const bytes = signedTransactionBytes({ signedTransaction: SIGNED_B64 });
  assertEquals(bytes.length, 177);
  // The first byte is the signature count and the next 64 are a signature.
  assertEquals(bytes[0], 1);
  assertEquals(bytes[65], 0x80, "the message starts with version 0");
});

// Reading a base64 answer as hex does not fail: every base64 character is
// also a legal hex character, so it parses into bytes and there is nothing to
// notice. What gives it away is only that the bytes are not the transaction.
Deno.test("reading a base64 answer as hex gives different bytes", () => {
  const right = signedTransactionBytes({ signedTransaction: SIGNED_B64 });

  const hexChars = SIGNED_B64.replace(/[^0-9a-fA-F]/g, "");
  const wrong = new Uint8Array(hexChars.length / 2);
  for (let i = 0; i < wrong.length; i++) {
    wrong[i] = parseInt(hexChars.substr(i * 2, 2), 16);
  }

  let same = wrong.length === right.length;
  for (let i = 0; same && i < wrong.length; i++) {
    if (wrong[i] !== right[i]) same = false;
  }
  assertEquals(same, false, "the two encodings gave the same bytes");
});

Deno.test("a response that is not base64 is refused", () => {
  assertThrows(
    () => signedTransactionBytes({ signedTransaction: "abc" }),
    Error,
    "not a whole number of bytes",
  );
  assertThrows(
    () => signedTransactionBytes({ signedTransaction: "!!!!" }),
    Error,
    "not base64",
  );
  assertThrows(
    () => signedTransactionBytes({}),
    Error,
    "no signed transaction",
  );
});
