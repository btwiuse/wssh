import { assertEquals } from "jsr:@std/assert@^1";

import { parseIdentitiesForTest } from "./agent.ts";

/** Hex to bytes, so a fixture on screen stays the bytes an agent really sent. */
function bytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)));
}

// The exact body an OpenSSH agent sent for one ed25519 key, byte for byte:
// the type byte, a count of one, then the 51-byte ssh wire-format blob and a
// comment. Captured rather than written out by hand, because the thing that
// went wrong here was reading the blob as if it were a type field and that is
// exactly the kind of mistake a hand-written fixture hides.
//
// The address is checked against what solana/keys.go derives from the same
// key, so the two implementations of this cannot drift apart silently.
const CAPTURED = [
  "0c00000001000000330000000b7373682d65643235353139000000206034d454" +
  "496165c55307d449e2b449f31f787b36d2f6d81965e3b60274079e720000000f" +
  "6765617240676561722e6c6f63616c" +  "",
].join("");

Deno.test("an identities answer is read as a blob and a comment, not a type", () => {
  const keys = parseIdentitiesForTest(bytes(CAPTURED));
  assertEquals(keys.length, 1);
  assertEquals(keys[0].type, "ssh-ed25519");
  assertEquals(keys[0].comment, "gear@gear.local");
  // base58 of the 32 bytes inside the blob
  assertEquals(keys[0].address, "7UYryNPnvn9iKdPZRWTztsLVt3VdwfutQAMPSmzNJvDo");
});

// An agent with nothing in it answers with a count of zero and no records.
// Reading a record anyway is how an empty agent looks like a malformed one.
Deno.test("an empty agent answers with nothing", () => {
  assertEquals(parseIdentitiesForTest(bytes("0c00000000")), []);
});

// A key with nothing to say for itself still sends the comment field, just
// empty. Reading it as absent rather than as a zero-length string is how the
// record after it gets misread, so the empty case is pinned rather than an
// invented "field was left off" one: both Go's marshalKey and OpenSSH write
// the field.
Deno.test("a key with an empty comment still parses", () => {
  const blob = new Uint8Array([...sshString("ssh-ed25519"), ...sshString(new Uint8Array(32))]);
  const body = new Uint8Array([
    12,
    ...uint32(1),
    ...sshString(blob),
    ...sshString(new Uint8Array(0)),
  ]);

  const keys = parseIdentitiesForTest(body);
  assertEquals(keys.length, 1);
  assertEquals(keys[0].type, "ssh-ed25519");
  assertEquals(keys[0].comment, "");
  // An all-zero key is 32 real bytes, and its address is still base58: one
  // "1" per leading zero byte, which is how the System Program's own address
  // comes out. Getting that wrong truncates a leading-zero address, and the
  // System Program is nothing but leading zeros.
  assertEquals(keys[0].address, "11111111111111111111111111111111");
});

function uint32(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

function sshString(s: string | Uint8Array): Uint8Array {
  const body = typeof s === "string" ? new TextEncoder().encode(s) : s;
  return new Uint8Array([...uint32(body.length), ...body]);
}


// Two keys with long comments is what a browser agent actually holds: an
// imported SSH key and a connected wallet, each labelled by where it came
// from. Built here rather than captured, because what it pins is that a
// length-prefixed string is a length-prefixed string - and the parser that
// mistook the blob for a type field read exactly this message and failed.
Deno.test("a browser agent's two keys, with their labels", () => {
  const key = (n: number) =>
    new Uint8Array([...sshString("ssh-ed25519"), ...sshString(new Uint8Array(32).fill(n))]);
  const record = (n: number, comment: string) =>
    new Uint8Array([...sshString(key(n)), ...sshString(comment)]);

  const body = new Uint8Array([
    12,
    ...uint32(2),
    ...record(1, "ssh-ed25519 2026-10-10"),
    ...record(2, "solana:5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5"),
  ]);

  const keys = parseIdentitiesForTest(body);
  assertEquals(keys.length, 2);
  assertEquals(keys[0].comment, "ssh-ed25519 2026-10-10");
  assertEquals(keys[1].comment, "solana:5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5");
  // The addresses come out of the filler bytes, and they are different keys,
  // so they must not come out the same. Written as the values they should be
  // rather than as a property, because "they differ" would also pass if the
  // reader were returning the key's comment or its type.
  assertEquals(keys[0].address, "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
  assertEquals(keys[1].address, "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR");
});
