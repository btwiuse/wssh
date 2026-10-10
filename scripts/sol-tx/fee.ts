// scripts/sol-tx/fee.ts
//
// The account a signed transaction was actually paid by, read back out of
// the signed bytes.
//
// Reading it back is the point. The request may name a payer, or name none
// and leave the wallet to choose, and in neither case is the session certain
// what the wallet did until it has the transaction. The answer here comes
// from the same bytes the wallet signed, so it is the account that paid
// rather than a claim about which one was asked to.
//
// The layout is shallow and fixed: a compact-u16 signature count, that many
// 64-byte signatures, then the message. The message opens with a header and
// its account keys, and the first key is the fee payer - which is why this
// walks the two length-prefixed forms rather than just taking 32 bytes
// after the signatures.

const SIGNATURE_SIZE = 64;
const PUBKEY_SIZE = 32;

/** Solana's compact-u16: seven bits per byte, low first, high bit continues. */
function compactU16(bytes: Uint8Array, offset: number): [number, number] {
  let value = 0;
  for (let i = 0; i < 3; i++) {
    if (offset + i >= bytes.length) throw new Error("the value ends before it does");
    const b = bytes[offset + i];
    value |= (b & 0x7f) << (7 * i);
    if ((b & 0x80) === 0) return [value, offset + i + 1];
  }
  throw new Error("the value is longer than a compact-u16 can be");
}

/**
 * The fee payer's base58 address.
 * @param signed  the signed transaction, as it went over the wire
 * @returns the base58 address that paid
 */
export function feePayer(signed: Uint8Array): string {
  const [count, after] = compactU16(signed, 0);
  let rest = signed.subarray(after);
  if (rest.length < count * SIGNATURE_SIZE) {
    throw new Error(`the transaction claims ${count} signatures but is ${signed.length} bytes`);
  }
  rest = rest.subarray(count * SIGNATURE_SIZE);

  // A versioned message starts with a byte whose top bit is set and whose
  // low seven bits are the version. A legacy one starts with the header,
  // which counts signatures and can never have that bit set.
  const versioned = rest.length > 0 && (rest[0] & 0x80) !== 0;
  if (versioned) rest = rest.subarray(1);

  if (versioned) {
    // Three separate bytes - required signatures, readonly signatures,
    // readonly unsigned - and only then a count of the static keys. This
    // read one byte and the rest of the message came back shifted, which
    // returned the tail of the header joined to the front of the fee payer:
    // a base58 address of the right length, naming an account nobody holds.
    rest = rest.subarray(3); // header
    const [, afterKeys] = compactU16(rest, 0); // number of static keys
    rest = rest.subarray(afterKeys);
  } else {
    // Three counts in a row: required signatures, readonly signatures,
    // readonly unsigned. Then the keys, with no count of their own.
    for (let i = 0; i < 3; i++) {
      const [, next] = compactU16(rest, 0);
      rest = rest.subarray(next);
    }
  }

  if (rest.length < PUBKEY_SIZE) throw new Error("the signed transaction carries no fee payer");
  return base58Of(rest.subarray(0, PUBKEY_SIZE));
}

// Imported here rather than at the top so this file reads as the single
// description of the layout, and the base58 it needs comes from one place.
import { encodeBase58 as base58Of } from "./base58.ts";
