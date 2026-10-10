// scripts/sol-tx/base58.ts
//
// Solana base58 (Bitcoin alphabet). Used to encode instruction data and
// the signed transaction for printing, and to validate user-supplied
// addresses and program ids.
//
// The encoding is delegated to @scure/base so the script does not ship
// its own copy: @scure is audited, 0-dep, and the same alphabet Solana
// uses. The wrapper here only adapts the API to the call sites in this
// package.

import { base58 } from "@scure/base";

export function encodeBase58(bytes: Uint8Array): string {
  return base58.encode(bytes);
}

export function decodeBase58(s: string): Uint8Array {
  return base58.decode(s);
}

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INDEX: Record<string, true> = {};
for (const ch of ALPHABET) INDEX[ch] = true;

export function isBase58(s: string): boolean {
  if (s.length === 0) return false;
  for (const ch of s) if (!(ch in INDEX)) return false;
  return true;
}