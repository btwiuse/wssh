# sol-tx, in Deno

A TypeScript reimplementation of `sol-tx` for debugging and learning.
It does the same job as the Go command (`cmd/sol-tx`) and is meant
to be the version a person can hand-step when the network or the wallet is
misbehaving. Every byte on the wire is logged in `--verbose` mode.

## Why

The Go implementation is the production tool. This script is for cases
where reading the protocol with your own eyes is more useful than reading
the Go source. Two real situations:

- **Diagnose the agent path.** With `--verbose`, every byte the script
  sends and receives on the SSH agent socket is logged. A wallet that
  hangs, an agent that does not implement the extension, and a refused
  signature are each visible at the line where they happen.
- **Run the same logic on a different runtime.** No Go toolchain, no
  install; just `deno run` from the repo root.

## Install / run

```
cd scripts/sol-tx
deno task start --help
```

`deno.json` declares all the permissions the script needs. The first run
downloads `@solana/web3.js` and `@scure/base` into Deno's module cache.

## Usage

```
deno task start transfer --to <addr> --sol 0.001 --send
deno task start transfer --to <addr> --lamports 1000000
deno task start call --program <id> --account <addr> --data <base58>
```

Flags mirror the Go command:

| flag           | meaning                                                |
|----------------|--------------------------------------------------------|
| `--agent <p>`  | agent socket (default `$SSH_AUTH_SOCK`)                |
| `--rpc <url>`  | RPC endpoint; overrides `--network`                    |
| `--network`    | `mainnet` (default), `testnet`, `devnet`, or a URL     |
| `--blockhash`  | build against this blockhash; fetch when empty         |
| `--payer`      | fee payer (base58); default is the connected wallet    |
| `--label`      | free text shown beside the transaction                 |
| `--send`       | broadcast through `--rpc` and wait for confirmation    |
| `--verbose`     | log every step on stderr                               |

Environment variables:

- `SSH_AUTH_SOCK` — agent socket (default for `--agent`)
- `WSSH_SOLANA_RPC` — default for `--rpc` when the flag is empty

## File layout

```
main.ts         arg parsing, top-level flow
agent.ts        SSH agent wire format + the solana-tx@wssh extension
rpc.ts          getLatestBlockhash, sendTransaction, confirmTransaction
instruction.ts  SystemProgram transfer + raw call builders
base58.ts       base58 encode/decode (via @scure/base)
```

## Wire format, in one paragraph

The agent speaks the upstream ssh-agent protocol: a 4-byte big-endian
length prefix followed by a message. The message for an extension call
is byte 27 (SSH_AGENT_EXTENSION), an SSH string naming the extension
(`"solana-tx@wssh"`), a 4-byte big-endian length, and the JSON-encoded
`SolanaTxRequest`. The reply is a single byte (5 = no such extension,
28 = extension said no, anything else = success) followed by the
JSON-encoded `SolanaTxResponse`. Both shapes are visible in
`agent.ts:readExtensionReply` and `agent.ts:marshalExtensionRequest`.