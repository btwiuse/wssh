# Commands

Read this when you need to build something, run the server, or run the tests.
The target names are in the `Makefile`; bare `make` lists them and builds
nothing.

The build entry point is the `Makefile`. Bare `make` lists targets; name one
explicitly. `make wssh` is the target that matters: the browser client is a
build artefact of `cmd/wssh/static/`, and a binary built while `ssh.wasm` is
missing still compiles, still runs, and serves a page whose worker dies on a
404. The Makefile turns that silent breakage into a build that either produces
the wasm or fails.

| Make target | What it does |
|---|---|
| `make wssh` | Builds `bin/wssh`, populating `cmd/wssh/static/{ssh.wasm,wasm_exec.js}` first via `client/build.sh`. |
| `make sol-tx` | Builds `bin/sol-tx`. |
| `make sol-keys` | Builds `bin/sol-keys`. |
| `make generate` | Runs every `//go:generate` directive (same effect as `go generate ./...`); `web.go` invokes `client/build.sh`. |
| `make install` | `go install ./cmd/wssh ./cmd/sol-tx ./cmd/sol-keys` into `$GOBIN`. |
| `make serve` | `make wssh` then runs `bin/wssh web`. |
| `make bin` | All three binaries. |
| `make test` | `go test ./...`. |
| `make vet` | `go vet ./...`. |
| `make fmt` | `gofmt -w .` over the tree. |
| `make check` | `vet` then `test`; the gate before committing. |
| `make clean` | Removes `bin/`, the wasm, and `wasm_exec.js`. |
| `make help` | Prints the list above. |

If you'd rather skip the Makefile:

```
go generate ./...                # build the browser client
go build -trimpath -o wssh ./cmd/wssh
```

`go.sum` is gitignored; `go build` regenerates it on demand, so expect a
download step the first time.

## Build the CLI binary with version metadata

```
go build -trimpath -ldflags "-X main.version=v1.2.3 -X main.commit=$(git rev-parse HEAD)" -o wssh ./cmd/wssh
```

`main.version` and `main.commit` are set with `-ldflags` (see
`cmd/wssh/main.go`). Without them you get `"dev"` and `""`. `cmd/sol-tx` and
`cmd/sol-keys` take the same two variables the same way, so all three binaries
report themselves consistently.

## Run the tests

```
go test ./...
```

Tests run a real `wssh.NewServer` on loopback and drive it with the real
`client.Dial`. The browser-only files (`client/wasm.go`, `client/wasmauth.go`)
are gated with `//go:build js && wasm` so they are excluded from native test
runs. `client/client_test.go` is `//go:build !js` so the same package compiles
both ways. Keep those build tags in place if you add files to `client/`.

`harness/` is `//go:build tools` and so is outside `go test ./...`; check it
with `go vet -tags tools ./harness/`.

There is no separate `golangci-lint` config; the project relies on
`go vet ./...` plus what CI runs. `nolint:errcheck` and similar are in use.

The Deno script has its own suite, in its own directory so its deno.json
applies:

```
cd scripts/sol-tx && deno task test
```

## Build only the browser WASM

```
./client/build.sh
```

Builds `client/cmd/webssh-web` to `cmd/wssh/static/ssh.wasm` and copies
`wasm_exec.js` from the same Go toolchain (`go env GOROOT`). Both files are
gitignored - they must come from the same Go release, otherwise the runtime
ABI disagrees and fails in confusing ways.

The script sets `CGO_ENABLED=0` before the cross-compile. Hosts that default
`CGO_ENABLED=1` (Termux is the common case) would otherwise make `os/user`
skip its js/wasm backend in `lookup_stubs.go` because of the file's `!cgo`
build tag, and the build dies with `undefined: current`. Upstream Go disables
cgo for targets that cannot use it; this only matters for cross-compile.

`selftest.html` exercises the browser end-to-end: visit
`http://localhost:8080/selftest.html` (with the server running) and watch for
the `SELFTEST PASS` banner. Useful after touching the front end. The page
fetches the wasm over HTTP, so a rebuilt client needs a hard reload before the
old one is out of the browser's hands.

## Build sol-tx

`make sol-tx` builds `bin/sol-tx`, which is its own binary - it does not speak
SSH and is not a wssh subcommand.

```
./bin/sol-tx memo --memo "hello" --send --verbose
./bin/sol-tx transfer --to <addr> --lamports 1000 --network devnet --send
```

With a wallet, the session's agent answers the Solana extension. With a plain
ssh-agent - `ssh -A` into the server, or `--agent-keys` - it does not, and the
command builds the transaction itself and asks the agent to sign it. With one
key in the agent the account is taken from it; with several, `--signer` says
which. See `solana.md` for how the two paths differ.

`--verbose` says what is going to sign **before** anything is built, which is
the only point at which it is worth knowing:

```
[sol-tx] signer=(not named; the wallet will sign; the account is whichever one its prompt has selected)
[sol-tx]   41AZvbsCJJoKT27SCLAd7HCNK7mdU2TA9LLUWwyjnyLA  ssh-ed25519 2026-10-10  <- unused unless --signer names it
[sol-tx]   5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5  solana:5cyyvrz…       <- the wallet
[sol-tx] asking agent
fee payer: 5cyyvrzC3N3Kz1vU1iA9symxyMpKWFPSU3AmBdt9XKC5
```

Four cases, and none of them is a prediction:

| On offer | What it says |
|---|---|
| `--signer` named | one line: it is settled, and the agent routes on it |
| a key labelled `solana:<addr>` | the wallet will sign; **which of its accounts it is is the person's choice at the popup**, and is not knowable before then. Every other key is marked unused. |
| one key, no wallet | that key signs |
| several keys, no wallet | the agent will refuse and ask for `--signer` |

The wallet is recognised by its label, `agentkey.WalletCommentPrefix`, which the
browser client writes and both `sol-tx` implementations read — one constant in
`auth/agentkey`, so the two sides cannot disagree about what the label means.

The `fee payer:` line stays where it is, after the fact and read out of the
bytes that were signed: the plan before, the fact after. `scripts/sol-tx` prints
the same lines from the same agent listing.

## Build sol-keys

`make sol-keys` builds `bin/sol-keys`, the `ssh-add -L` of this repository with
the second column filled in.

```
./bin/sol-keys
./bin/sol-keys --addresses          # just the addresses, one per line
./bin/sol-keys --json               # the whole listing as one document
./bin/sol-keys --agent /tmp/ssh-Ab3dEf/agent.4711
```

It prints the line ssh-add would print — comment included, exactly as the agent
sent it — and, underneath, the base58 account that key is on Solana. A wssh
session's agent labels its keys by where they came from, so the listing there
reads `ssh-ed25519 AAAA... solana.ed25519` rather than repeating the type;
`agent-forwarding.md` has where each label comes from.

The address is not looked up or derived: a Solana account *is* an ed25519
public key, so an ed25519 SSH key already is one and the address is those same
32 bytes. A key of any other kind names no account, and the output says which
kind it is instead of leaving a blank.

`--json` prints one object on stdout and nothing else:

```json
{
  "agent": "/tmp/ssh-Ab3dEf/agent.4711",
  "keys": [
    {
      "type": "ssh-ed25519",
      "authorizedKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... laptop@bastion",
      "comment": "laptop@bastion",
      "address": "HaLUkbGUZQhSVY36Tn6AG4hATC8o8h756o9LVwJCPN9W",
      "reason": ""
    }
  ]
}
```

Every field is always present, empty string included, and every key the agent
holds is an entry whether or not it names an account — a consumer never has to
tell "no account" from "this version does not say". An agent holding nothing
comes back as `"keys": []`, not `null`. `--addresses` and `--json` are two
different documents, so asking for both is refused before the agent is dialled.

That address is exactly the string `sol-tx --signer` wants for the key to sign,
and with a single-key agent it is exactly what `sol-tx` picks for itself - both
go through `solana.AddressFor`, so the two cannot disagree.

## Run the selftest

```
make wssh sol-tx
./bin/wssh web --forward-agent --hostkey ./hk
open "http://127.0.0.1:8131/selftest.html?bin=$PWD/bin/sol-tx"
```

`--forward-agent` is required: without it a session has no agent and the
transaction phase has nothing to sign with. `?bin=` points at the binary
because the session does not have one on its PATH by default. Pass `?rpc=` to
use an endpoint other than devnet; mainnet refuses browser requests with 403,
which is why devnet is the default even though nothing is broadcast.

## Run the server

```
./wssh server --addr :8080 --verbose            # bare transport
./wssh web    --addr :8080 --verbose --open     # server + browser UI
./wssh web --ui-only                            # browser-only, no sessions
./wssh keygen                                   # generate ed25519 key pair
./wssh client wss://host:8080/ws                # CLI client (no websocat)
./wssh client wss://host:8080/ws -- uptime      # CLI client, run one command
./wssh server --agent-keys ./signer.ed25519     # expose the key as an in-memory ssh-agent
./wssh client --agent ./id_ed25519 wss://host:8080/ws   # use the same key for pubkey auth and the agent channel
```

The default listen address is `$PORT` (if set) or `:8080`. Default host key
path is `$HOST_KEY` or `./host_ed25519`. Default session path is `""` for
`server` (any path opens a session) and `/ws` for `web` (so static assets
have the rest of the URL space).

`--open` opens the served page in the user's default browser. On Termux the
linux branch in `openBrowser` (`cmd/wssh/serve.go`) runs `xdg-open`, which
on Termux is a symlink to `termux-open` - it broadcasts an Android intent that
the user's default browser handles. No code change is needed for Termux; the
existing fallback path already works.