// scripts/sol-tx/main.ts
//
// wssh sol-tx in TypeScript. Asks the browser wallet to sign a Solana
// transaction via SSH_AUTH_SOCK and the wssh agent protocol, then prints
// (or broadcasts, with --send) the signed transaction.
//
// Why a separate script: it lets a person hand-step the protocol with
// `deno run -A main.ts ...` and see every byte that crosses the wire.
// The Go implementation in cmd/wssh/soltx.go does the same job in
// production; this one is for debugging, learning, and the cases where
// a CLI built on real libraries is more useful than one that ships its
// own.
//
// Usage:
//   deno task start --agent $SSH_AUTH_SOCK transfer --to <addr> --sol 0.001 --send
//   deno task start --rpc https://api.devnet.solana.com call --program <id> --account <addr> --data <base58>
//
// The agent socket defaults to $SSH_AUTH_SOCK, the RPC defaults to
// mainnet-beta, --network {mainnet,testnet,devnet} flips it.

import { parseArgs } from "@std/cli/parse-args";
import * as agent from "./agent.ts";
import * as rpc from "./rpc.ts";
import * as instruction from "./instruction.ts";
import { encodeBase58 } from "./base58.ts";

// -- Args --------------------------------------------------------------------

interface TransferArgs {
  mode: "transfer";
  to: string;
  lamports: number;
  blockhash?: string;
  payer?: string;
  label?: string;
}

interface CallArgs {
  mode: "call";
  program: string;
  accounts: string[];
  data: string;
  blockhash?: string;
  payer?: string;
  label?: string;
}

type Mode = TransferArgs | CallArgs;

interface GlobalArgs {
  agent?: string;
  rpc?: string;
  network?: string;
  send: boolean;
  verbose: boolean;
}

function usage(): never {
  console.error(`wssh sol-tx (Deno)

Usage:
  deno task start transfer --to <addr> --sol <amount> [--send] [--rpc <url>] [--network <name>]
  deno task start transfer --to <addr> --lamports <n> [--send]
  deno task start call    --program <id> --account <addr> [--account <addr>...]
                            --data <base58> [--send]

Options:
  --agent <path>     SSH agent socket; default $SSH_AUTH_SOCK
  --rpc <url>        RPC endpoint; takes precedence over --network
  --network <name>   mainnet | testnet | devnet | custom URL; default mainnet
  --blockhash <bh>   blockhash to build against; fetched when absent
  --payer <addr>     base58 fee payer; defaults to the connected wallet
  --label <text>     free text shown beside the transaction
  --send             broadcast through --rpc and wait for confirmation
  --verbose          log every step on stderr

Environment:
  SSH_AUTH_SOCK        agent socket
  WSSH_SOLANA_RPC      default --rpc when the flag is empty
`);
  Deno.exit(2);
}

function parseLamports(sol: string): number {
  const v = parseFloat(sol);
  if (isNaN(v) || v <= 0) throw new Error(`${sol} is not an amount of SOL`);
  const lamports = Math.floor(v * 1e9);
  if (lamports === 0) throw new Error("less than a lamport");
  if (lamports > 500_000_000_000_000_000) throw new Error("more lamports than exist");
  return lamports;
}

function resolveNetwork(name: string): string {
  switch (name.trim().toLowerCase()) {
    case "":
    case "mainnet":
    case "mainnet-beta":
      return "https://api.mainnet-beta.solana.com";
    case "testnet":
      return "https://api.testnet.solana.com";
    case "devnet":
      return "https://api.devnet.solana.com";
    default:
      return name;
  }
}

function effectiveRPC(rpcFlag: string | undefined, networkFlag: string | undefined): string {
  const envRPC = Deno.env.get("WSSH_SOLANA_RPC") ?? "";
  const rpc = rpcFlag ?? envRPC;
  if (rpc.trim() !== "") return rpc;
  return resolveNetwork(networkFlag ?? "mainnet");
}

// -- Main --------------------------------------------------------------------

const argv = Deno.args;
if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") usage();

const mode = argv[0];
if (mode !== "transfer" && mode !== "call") {
  console.error(`unknown mode ${JSON.stringify(mode)}: must be "transfer" or "call"`);
  Deno.exit(2);
}

const parsed = parseArgs(argv.slice(1), {
  string: [
    "agent",
    "rpc",
    "network",
    "blockhash",
    "payer",
    "label",
    "to",
    "sol",
    "lamports",
    "program",
    "data",
  ],
  boolean: ["send", "verbose"],
  collect: ["account"],
  default: { network: "mainnet", send: false, verbose: false },
});

const global: GlobalArgs = {
  agent: parsed.agent ?? Deno.env.get("SSH_AUTH_SOCK") ?? undefined,
  rpc: parsed.rpc,
  network: parsed.network,
  send: parsed.send,
  verbose: parsed.verbose,
};

let modeArgs: Mode;
if (mode === "transfer") {
  const lamports = parsed.lamports !== undefined
    ? parseInt(parsed.lamports, 10)
    : parsed.sol !== undefined
    ? parseLamports(parsed.sol)
    : (() => {
      throw new Error("a transfer needs --sol or --lamports");
    })();
  if (!parsed.to) throw new Error("a transfer needs --to");
  modeArgs = {
    mode: "transfer",
    to: parsed.to,
    lamports,
    blockhash: parsed.blockhash,
    payer: parsed.payer,
    label: parsed.label,
  };
} else {
  if (!parsed.program) throw new Error("a call needs --program");
  if (!parsed.data) throw new Error("a call needs --data");
  if (!parsed.account || parsed.account.length === 0) {
    throw new Error("a call needs at least one --account");
  }
  modeArgs = {
    mode: "call",
    program: parsed.program,
    accounts: parsed.account as string[],
    data: parsed.data,
    blockhash: parsed.blockhash,
    payer: parsed.payer,
    label: parsed.label,
  };
}

const endpoint = effectiveRPC(global.rpc, global.network);
const sockPath = global.agent;
if (!sockPath) {
  console.error("SSH_AUTH_SOCK is not set and --agent is empty; nothing to ask");
  Deno.exit(2);
}

if (global.verbose) {
  console.error(`[sol-tx] agent=${sockPath}`);
  console.error(`[sol-tx] rpc=${endpoint}`);
  console.error(`[sol-tx] mode=${modeArgs.mode}`);
}

// -- Build the instruction set -----------------------------------------------

// The wssh agent protocol sends raw instructions; the wallet builds and
// signs the transaction. Mirrors Go's client.NewSolanaTransfer.
const instructions: agent.SolanaInstruction[] = modeArgs.mode === "transfer"
  ? [instruction.transferLamports(modeArgs.to, modeArgs.lamports)]
  : [instruction.rawCall(modeArgs.program, modeArgs.accounts, modeArgs.data)];

// -- Fetch blockhash when needed --------------------------------------------

let blockhash = modeArgs.blockhash;
if (!blockhash) {
  if (global.verbose) console.error("[sol-tx] fetching blockhash");
  blockhash = await rpc.getLatestBlockhash(endpoint, global.verbose);
}

const req: agent.SolanaTxRequest = {
  blockhash,
  label: modeArgs.label,
  payer: modeArgs.payer,
  instructions,
};

// -- Ask the wallet ---------------------------------------------------------

if (global.verbose) console.error("[sol-tx] asking agent");
const resp = await agent.ask(sockPath, req, global.verbose);
if (resp.refusal) {
  console.error(resp.refusal);
  Deno.exit(1);
}
if (!resp.signedTransaction) {
  console.error("the agent returned no signed transaction");
  Deno.exit(1);
}

// -- Print or send -----------------------------------------------------------

if (!global.send) {
  // Print the signed transaction as base58 for human readability.
  const txBytes = agent.signedTransactionBytes(resp);
  console.log(encodeBase58(txBytes));
  Deno.exit(0);
}

if (global.verbose) console.error("[sol-tx] sending via RPC");
const txBytes = agent.signedTransactionBytes(resp);
const sig = await rpc.sendTransaction(endpoint, txBytes, global.verbose);
console.log(sig);
await rpc.confirmTransaction(endpoint, sig, global.verbose);
Deno.exit(0);

// ---------------------------------------------------------------------------

function _unused(): void {} // sentinel: keep file structure consistent