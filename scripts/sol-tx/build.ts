// scripts/sol-tx/build.ts
//
// Assembling an unsigned versioned transaction, for an agent that has never
// heard of Solana.
//
// This is the same thing solana/build.go does on the Go side, ported rather
// than reimplemented, and it is measured against the same bytes a Solana
// library produced in a browser - see build_test.ts. Having two is already one
// too many; having two that disagree would be worse than one that is missing,
// because the failure would only show up on chain with nothing pointing here.
//
// It exists at all because a real ssh-agent will sign whatever bytes it is
// given but will not know what a transaction is, and the protocol has no
// operation for asking one to find out. So the bytes are built here and the
// agent is asked for a signature over them, which is one thing an agent has
// always understood.
//
// The layout is fixed and shallow: version, a three-byte header, the account
// keys, the blockhash, the instructions, and a lookup count. The blockhash
// sits before the instructions, which reads oddly and is not a mistake - a
// hand-written message that put it last was rejected by the cluster as an
// invalid discriminator.

import { decodeBase58 } from "./base58.ts";
import { MEMO_PROGRAM_ID, SYSTEM_PROGRAM_ID } from "./instruction.ts";
import type { SolanaTxRequest } from "./agent.ts";

const SIGNATURE_SIZE = 64;
const PUBKEY_SIZE = 32;

export { MEMO_PROGRAM_ID };

/**
 * Build the unsigned transaction an ordinary signature can be asked over.
 *
 * The result is the wire shape an agent is handed: a compact-u16 signature
 * count, that many empty 64-byte slots, then the message. A plain agent signs
 * the message; the slot is only there because that is the shape it has to fit
 * into afterwards.
 *
 * @param req  the transaction to build
 * @returns    the unsigned transaction, or a sentence saying why there is none
 */
export function buildTransaction(req: SolanaTxRequest): Uint8Array {
  if (!req.signer) {
    throw new Error("no signer: this path signs with a key it holds, so it has to be named");
  }
  const blockhash = decode32(req.blockhash, "blockhash");
  // The named signer is the fee payer, and not because the caller said so
  // twice: Solana requires the fee payer to be a required signer, so a
  // transaction with one signer has that signer paying.
  const payer = decode32(req.signer, "signer");
  if (req.instructions.length === 0) {
    throw new Error("the request carries no instructions");
  }

  // Account keys in the order they were first mentioned, the fee payer
  // first: Solana wants every signer before anything that does not sign.
  const keys = new KeyTable(payer);

  const compiled = req.instructions.map((ix, i) => {
    const program = keys.intern(decode32(ix.programId, `instruction ${i} program id`));
    // A System transfer names [source, destination] and the source is
    // whoever signs, which is the fee payer - a request cannot name it
    // because the signer is not known when the request is written. This is
    // the same insertion solana/build.go does, and the Deno and Go
    // transactions have to be the same bytes or the two commands stop
    // agreeing about what they signed.
    const accounts = ix.accounts.map((a, j) => {
      const raw = decode32(a.address, `instruction ${i} account ${j}`);
      if (a.isSigner && !equalBytes(raw, payer)) {
        // Refused rather than approximated: a transaction missing one of
        // its signatures is one the cluster rejects with nothing that
        // points here. Use a wallet, which can supply any number.
        throw new Error(
          `instruction ${i} account ${j} asks ${a.address} to sign, and the ` +
            `only key available is the fee payer's: use a wallet for this`,
        );
      }
      return keys.intern(raw);
    });
    if (sourceIsFeePayer(ix, accounts.length)) accounts.unshift(0);
    return { program, accounts, data: decodeBase58(ix.data) };
  });

  // One signer - the payer - and nothing else. Every other account is
  // unsigned and therefore readonly, which is the conservative reading: a
  // transaction that writes more than it has to is one that has to be undone
  // if it is wrong.
  const unsignedCount = keys.list.length - 1;
  if (keys.list.length > 1 << 8 || unsignedCount > 1 << 8) {
    throw new Error(
      `a transaction naming ${keys.list.length} accounts is more than the header can say`,
    );
  }

  const msg = [0x80]; // version 0; the high bit marks the message as versioned
  msg.push(1); // one required signature: the payer
  msg.push(0); // no readonly signers
  msg.push(unsignedCount);
  pushCompactU16(msg, keys.list.length);
  for (const k of keys.list) msg.push(...k);
  msg.push(...blockhash);
  pushCompactU16(msg, compiled.length);
  for (const ix of compiled) {
    pushCompactU16(msg, ix.program);
    pushCompactU16(msg, ix.accounts.length);
    for (const a of ix.accounts) pushCompactU16(msg, a);
    pushCompactU16(msg, ix.data.length);
    msg.push(...ix.data);
  }
  pushCompactU16(msg, 0); // no address table lookups

  const out = [...compactU16(1)];
  out.push(...new Array(SIGNATURE_SIZE).fill(0));
  out.push(...msg);
  return new Uint8Array(out);
}

/**
 * The message the signatures cover: everything after the signature section.
 *
 * @param unsigned  the transaction buildTransaction returned
 */
export function messageOf(unsigned: Uint8Array): Uint8Array {
  const [count, after] = readCompactU16(unsigned, 0);
  const need = count * SIGNATURE_SIZE;
  if (unsigned.length < after + need) {
    throw new Error(`the transaction claims ${count} signatures but is ${unsigned.length} bytes`);
  }
  return unsigned.subarray(after + need);
}

/** Solana's compact-u16: seven bits per byte, low first, high bit continues. */
function compactU16(n: number): number[] {
  const out: number[] = [];
  for (;;) {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    out.push(b);
    if (n === 0) return out;
  }
}

function pushCompactU16(out: number[], n: number): void {
  out.push(...compactU16(n));
}

function readCompactU16(bytes: Uint8Array, offset: number): [number, number] {
  let value = 0;
  for (let i = 0; i < 3; i++) {
    if (offset + i >= bytes.length) throw new Error("the value ends before it does");
    const b = bytes[offset + i];
    value |= (b & 0x7f) << (7 * i);
    if ((b & 0x80) === 0) return [value, offset + i + 1];
  }
  throw new Error("the value is longer than a compact-u16 can be");
}

/** How many accounts each System instruction takes, by discriminant. */
const SYSTEM_ACCOUNTS = new Map<number, number>([
  [0, 2], // CreateAccount
  [1, 2], // Assign
  [2, 2], // Transfer
  [3, 2], // CreateAccountWithSeed
  [4, 1], // AdvanceNonceAccount
  [5, 2], // WithdrawNonceAccount
  [6, 1], // InitializeNonceAccount
  [7, 1], // AuthorizeNonceAccount
  [8, 2], // Allocate
  [9, 0], // AllocateWithSeed
  [10, 1], // AssignWithSeed
  [11, 2], // TransferWithSeed
  [12, 1], // UpgradeNonceAccount
]);

/**
 * Whether the fee payer is this instruction's first account.
 *
 * The System program is the one case where that is not a matter of the
 * program's own interface: a transfer's source is the signer, and Solana
 * requires the fee payer to sign. See solana/build.go for the Go side.
 */
function sourceIsFeePayer(
  ix: { programId: string; data: string },
  named: number,
): boolean {
  if (ix.programId !== SYSTEM_PROGRAM_ID) return false;
  if (named >= 2) return false;
  const data = decodeBase58(ix.data || "");
  if (data.length < 4) return false;
  const discriminant =
    (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)) >>> 0;
  const needed = SYSTEM_ACCOUNTS.get(discriminant);
  return needed !== undefined && needed > named;
}

/** Interns account keys so the same one is named once. */
class KeyTable {
  readonly list: number[][] = [];
  private readonly index = new Map<string, number>();

  constructor(payer: number[]) {
    this.intern(payer);
  }

  intern(key: number[]): number {
    const at = String.fromCharCode(...key);
    const seen = this.index.get(at);
    if (seen !== undefined) return seen;
    const i = this.list.length;
    this.list.push(key);
    this.index.set(at, i);
    return i;
  }
}

function decode32(s: string, what: string): number[] {
  const raw = decodeBase58(s);
  if (raw.length !== PUBKEY_SIZE) {
    throw new Error(`the ${what} is ${raw.length} bytes, want ${PUBKEY_SIZE}`);
  }
  return [...raw];
}

function equalBytes(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
