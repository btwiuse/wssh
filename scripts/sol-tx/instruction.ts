// scripts/sol-tx/instruction.ts
//
// Builds the raw instruction shapes the wallet signs. Mirrors Go's
// client.NewSolanaTransfer and the call branch in cmd/wssh/soltx.go. The
// wallet does the heavy lifting (transaction assembly, signing); we just
// describe what we want.
//
// Everything here is raw bytes encoded as base58 strings, which is the
// shape the wssh agent protocol expects.

import type { SolanaInstruction } from "./agent.ts";
import { encodeBase58, isBase58 } from "./base58.ts";

// System Program id: 32 zero bytes. The fixed address every transfer lands
// on, so a hard-coded constant is more honest than reading it from a keypair.
const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";

// SPL Memo Program v2. A log-only program: the only thing it does is write
// the supplied UTF-8 string into the transaction's log messages. No state
// is touched, no destination account is needed, and the fee is just the
// base signature fee - which makes it the cheapest possible way to confirm
// that the agent, the wallet, and the RPC are all talking to each other.
export const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/**
 * Build an SPL Memo instruction. The signer is the only account; the memo
 * program is invoked with the bytes of the message as its data. The string
 * is passed through as-is - UTF-8 is what gets logged, and what the
 * signTransaction prompt in the wallet shows the person approving.
 *
 * The accounts list is empty on the wire: the wssh agent protocol
 * (ParseSolanaTxRequest) accepts an empty list when the program is the
 * SPL Memo v2 program, and the browser-side transaction builder has
 * the same carve-out. The wallet itself is the signer - it knows which
 * pubkey it is, and the memo program has no other role for the position
 * to fill.
 */
export function memo(text: string): SolanaInstruction {
  if (text.length === 0) {
    throw new Error("a memo of nothing is not worth asking for");
  }
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > 566) {
    // SPL Memo v2 rejects data longer than 566 bytes; the program will
    // fail the instruction with "Memo too long" and the whole transaction
    // lands as a fee-burning error.
    throw new Error("a memo is limited to 566 bytes");
  }
  return {
    programId: MEMO_PROGRAM_ID,
    accounts: [],
    data: encodeBase58(bytes),
  };
}

/**
 * Transfer `lamports` of SOL to `to`. The instruction data is the System
 * Program's "Transfer" discriminant (2) followed by the lamport count as
 * eight little-endian bytes, twelve bytes total.
 */
export function transferLamports(to: string, lamports: number): SolanaInstruction {
  if (lamports <= 0) {
    throw new Error("a transfer of nothing is not worth asking for");
  }
  if (!isBase58(to)) {
    throw new Error("the destination is not a Solana address");
  }

  const data = new Uint8Array(12);
  new DataView(data.buffer).setUint32(0, 2, true); // little-endian discriminant
  // eight little-endian bytes of lamports. BigInt because the count may
  // exceed Number.MAX_SAFE_INTEGER.
  const big = BigInt(lamports);
  for (let i = 0; i < 8; i++) {
    data[4 + i] = Number((big >> BigInt(8 * i)) & 0xffn);
  }

  return {
    programId: SYSTEM_PROGRAM_ID,
    accounts: [{ address: to, isSigner: false, isWritable: true }],
    data: encodeBase58(data),
  };
}

/**
 * A raw program call. The data and accounts are passed through unchanged;
 * the agent has no opinion on what they mean, and the wallet is the one
 * that shows them to a person before signing.
 */
export function rawCall(
  program: string,
  accounts: string[],
  data: string,
): SolanaInstruction {
  if (accounts.length === 0) {
    throw new Error("a call needs at least one account");
  }
  if (data === "") {
    throw new Error("a call needs some data");
  }
  if (!isBase58(program)) {
    throw new Error("the program id is not a Solana address");
  }
  for (const a of accounts) {
    if (!isBase58(a)) {
      throw new Error(`account ${JSON.stringify(a)} is not a Solana address`);
    }
  }
  if (!isBase58(data)) {
    throw new Error("the data is not base58");
  }
  return {
    programId: program,
    accounts: accounts.map((address) => ({
      address,
      isSigner: false,
      isWritable: true,
    })),
    data,
  };
}