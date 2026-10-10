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