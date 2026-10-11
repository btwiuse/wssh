# File map

Read this when you need to know which file owns something, or whether a file
already exists for it.

| Path | Role |
|---|---|
| `.goreleaser.yml` | Release config: three binaries, macOS and Linux on amd64 and arm64, named `{binary}_{version}_{os}_{arch}` and stamped with the version. The name is not cosmetic — `wssh upgrade` matches assets on the platform suffix and takes the first that fits, so all three end up matching and the command checks the binary's own prefix itself. |
| `.github/workflows/release.yml` | Cuts a release when a `v` tag is pushed, which is the naming `wssh upgrade` parses. |
| `Makefile` | Build entry point. `make wssh` is the target that builds a working binary; bare `make` lists targets. `make sol-tx` and `make sol-keys` build the other two binaries, `make bin` builds all three. The wasm dependency list comes from `go list -deps` for the js/wasm target: a hand-kept list silently left the wasm stale when `auth/agentkey` changed, and a stale wasm runs the browser's transaction builder from a build that no longer exists. |
| `wssh.go`, `wssh_test.go` | `Server` (HTTP handler wrapping wish). Path/origin/auth tests. |
| `auth/auth.go`, `auth/auth_test.go` | `auth.Config`, key files (re-read each attempt), password file (bcrypt or plaintext). |
| `auth/agentkey/forward.go` | Client-agent forwarding, the `ssh -A` direction. `Forward()` is the middleware that, on session open, dials back over an `auth-agent@openssh.com` channel and relays it to a local socket. It asks `ssh.AgentRequested(sess)` whether to, not a request handler - see `agent-forwarding.md`. `--forward-agent` turns it on. |
| `auth/agentkey/` | Signing keys exposed to sessions as an ssh-agent, and the Solana transaction extension both sides implement. `KeyringWithComments([]Key)` attaches a label per key - the file it came from, the page that imported it, the wallet it belongs to - which is the only place any session can learn that. `Keyring` leaves them empty rather than inventing one. `Install(*ssh.Server, agent)` registers the auth-agent channel, the global request, and a per-connection local socket on a server already built. The keyring is fixed: `Add`/`Remove`/`Lock` report that. `--agent-keys` in `cmd/wssh/serve.go` parses key files with `gossh.ParsePrivateKey` and feeds the result. `solana.go` is the protocol; `solana/` is one caller of it. |
| `client/client.go`, `client/client_test.go` | `Session`, `Dial`, `Write`/`WriteContext`/`Resize`/`Close`/`CloseStdin`. Native tests over loopback. |
| `client/wasm.go` | `//go:build js && wasm`. JS bridge, parked forever, exports `connect`/`write`/`resize`/`disconnect`/`generateKey`/`keyInfo`. Reads the optional command from arg 6. |
| `client/wasmauth.go` | `//go:build js && wasm`. JSON-shaped `credentials`, `signerFor`, `buildAuth`, `jsGenerateKey`, `jsKeyInfo`. `buildAuth` returns `[]agentkey.Key` so each key's page-supplied name reaches the agent. |
| `client/wasmwallet.go` | `//go:build js && wasm`. The signer backed by a connected wallet, and `walletPublicKey` for declaring which key the wallet holds. |
| `client/build.sh` | WASM build + `wasm_exec.js` copy. Sets `CGO_ENABLED=0` so the cross-compile works on hosts (Termux) where cgo is on by default. |
| `client/cmd/webssh-web/main.go` | `//go:build js && wasm`. Just calls `client.Start()`. |
| `cmd/wssh/main.go` | Cobra root, fang executor, `--verbose`, `version`/`commit` from `-ldflags`. |
| `cmd/wssh/serve.go` | Shared `serveOptions`, `serve`, `drain`, `frontEnd`, `noCache`, `startRelays`, `addAuthFlags`, `addAgentFlags`, `openBrowser`, openssh-key-v1 parser (in `parseUnencryptedKey`). |
| `cmd/wssh/server.go` | `wssh server` subcommand (bare transport). |
| `cmd/wssh/web.go` | `wssh web` subcommand (server + front end, `--ui-only`, `--open`, `--path /ws`). Carries `//go:embed all:static` and `//go:generate bash ../../client/build.sh`; `wasmClientMissing` warns at startup if the wasm is absent. |
| `cmd/wssh/client.go` | `wssh client` subcommand (terminal raw mode, `known_hosts`, password/key auth, custom command via trailing args). |
| `cmd/wssh/keygen.go` | `wssh keygen` (ed25519/rsa/ecdsa, `--authorized-keys` to append). |
| `cmd/wssh/upgrade.go` | `wssh upgrade`, over `go-selfupdate`, reading releases from `btwiuse/wssh`. Three things about it are not obvious and each is a real failure: a binary built without the version ldflags reports `dev` and refuses rather than downloading over itself; the asset is chosen by a filter, because three binaries share the platform suffix and the library takes the first that fits; and the executable must be called `wssh`, because the library names the archive entry after the file it is overwriting. |
| `cmd/wssh/prompt.go` | Shared secret prompt helper (refuses non-terminal stdin). |
| `cmd/wssh/static/index.html` | xterm + React + htm (no bundler). Contains `__WSSH_SESSION_PATH__` placeholder. |
| `cmd/wssh/static/app.js` | React UI (terminal, endpoints, credentials panel, optional command field, `?cmd=` support). |
| `cmd/wssh/static/credentials.js` | Key storage, passphrase/password hooks, key generation UI. |
| `cmd/wssh/static/solana.js` | The wallet side: builds and shows the transaction in the browser. |
| `cmd/wssh/static/worker.js` | Hosts the Go/WASM SSH client, batches input, forwards the optional command as `api.connect`'s seventh argument. |
| `cmd/wssh/static/selftest.html` | End-to-end browser selftest. |
| `shell/shell.go` | Wish middleware: login shell, PTY with `WithJobControl`, window-change pump. |
| `solana/tx.go` | The client half of a Solana transaction: the agent conversation, RPC (`LatestBlockhash`, `SendTransaction`, `ConfirmTransaction`), and the instruction builders. Separate from `auth/agentkey` on purpose: that package is the protocol both sides implement, this is one caller of it. |
| `solana/build.go` | Assembles an unsigned versioned transaction from raw instructions, for signing with an agent that has never heard of Solana. Measured against `golden_test.go`; see `solana.md`. |
| `solana/agentsign.go` | The signing path for a plain ssh-agent: build here, then hand the message over as an ordinary `agent.Sign`. With one key in the agent it takes the signer from `solana.AddressFor`, so what it picks and what `sol-keys` prints cannot drift apart. |
| `solana/keys.go` | `AddressFor` - the one place a public key becomes a Solana account, and the only one that decides whether a key can be one - plus `ListAgentKeys`/`ListAgentKeysAt`/`SignerCandidates` over a real agent socket. |
| `solana/fee.go` | Reads the fee payer back out of a signed transaction, so what is reported is what was paid rather than what was asked for. |
| `cmd/sol-tx/` | Its own binary. It does not speak SSH and is not a wssh subcommand - it reads `SSH_AUTH_SOCK` the way any agent-using tool does. `planSigner` is the `--verbose` report of what is about to sign, kept separate from printing so it can be tested against a real agent. |
| `cmd/sol-keys/` | `ssh-add -L` with the Solana account under each key. `--addresses` prints only addresses, counted on stderr so stdout stays parseable. `--json` prints the whole listing as one object; every field is always present and every key the agent holds is an entry, including ones that name no account. `--addresses` with `--json` is refused rather than guessed at. |
| `scripts/sol-tx/` | The same command in Deno, for reading rather than trusting: it logs every byte that crosses the agent socket and every RPC call. `deno task test`. |
| `harness/main.go` | `//go:build tools`. A local stand-in for the wallet side: a real agent on a real socket, signing with a key it generates. Covers everything up to the browser, which is where the browser's own `selftest.html` takes over. |
| `memory/*.md` | The notes that used to live in `AGENTS.md`. One file per topic, each opening with when to read it. `AGENTS.md` is only the index; when something is worth writing down, it goes here. |