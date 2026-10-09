# AGENTS.md

Notes for working in this repository. Read this before touching anything that
the obvious file layout does not already make clear.

## What this is

`wssh` serves an SSH session over a WebSocket. The whole transport is a
reliable bidirectional pipe: SSH is a self-contained byte-stream protocol, so
the WebSocket does not have to understand key exchange, auth, or resizes -
they all travel in-band.

There are three pieces:

- **Server** (`wssh.go`, `cmd/wssh/server.go`, `cmd/wssh/web.go`,
  `cmd/wssh/serve.go`) - HTTP server that does a WebSocket upgrade per request
  and hands the bytes to a `wish/v2` SSH server.
- **Client library** (`client/client.go`) - opens a WebSocket, runs an SSH
  client over it, exposes a `Session` with `Write`, `WriteContext`, `Resize`,
  `Close`, `CloseStdin`. Same code is used by both the browser (WASM) and the
  CLI `client` subcommand.
- **Front end** (`cmd/wssh/static/`, `client/wasm.go`, `client/wasmauth.go`,
  `client/cmd/webssh-web/`) - a worker-hosted Go/WASM SSH client behind a React
  + xterm UI. `static/ssh.wasm` and `static/wasm_exec.js` are generated; the
  rest is hand-written.

`shell/` provides the wish middleware that runs the local user's login shell -
it manages the PTY itself rather than going through `wish.Command` because a
usable login shell needs the requested command, terminal resizes, and job
control (`^C`/`^Z` to the foreground job).

`auth/` is a separate config package for SSH authentication. Authentication is
**off by default**; see the warning below.

## Commands

The build entry point is the `Makefile`. Bare `make` lists targets; name one
explicitly. `make wssh` is the target that matters: the browser client is a
build artefact of `cmd/wssh/static/`, and a binary built while `ssh.wasm` is
missing still compiles, still runs, and serves a page whose worker dies on a
404. The Makefile turns that silent breakage into a build that either produces
the wasm or fails.

| Make target | What it does |
|---|---|
| `make wssh` | Builds `bin/wssh`, populating `cmd/wssh/static/{ssh.wasm,wasm_exec.js}` first via `client/build.sh`. |
| `make generate` | Runs every `//go:generate` directive (same effect as `go generate ./...`); `web.go` invokes `client/build.sh`. |
| `make install` | `go install ./cmd/wssh` into `$GOBIN`. |
| `make serve` | `make wssh` then runs `bin/wssh web`. |
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

### Build the CLI binary with version metadata

```
go build -trimpath -ldflags "-X main.version=v1.2.3 -X main.commit=$(git rev-parse HEAD)" -o wssh ./cmd/wssh
```

`main.version` and `main.commit` are set with `-ldflags` (see
`cmd/wssh/main.go`). Without them you get `"dev"` and `""`.

### Run the tests

```
go test ./...
```

Tests run a real `wssh.NewServer` on loopback and drive it with the real
`client.Dial`. The browser-only files (`client/wasm.go`, `client/wasmauth.go`)
are gated with `//go:build js && wasm` so they are excluded from native test
runs. `client/client_test.go` is `//go:build !js` so the same package compiles
both ways. Keep those build tags in place if you add files to `client/`.

There is no separate `golangci-lint` config; the project relies on
`go vet ./...` plus what CI runs. `nolint:errcheck` and similar are in use.

### Build only the browser WASM

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
the `SELFTEST PASS` banner. Useful after touching the front end.

### Run the server

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

## Security posture and the things that bite

Authentication is **off** until you turn it on. With no auth flags and
`--origins '*'` (the default), any page the user visits can open a shell on
the port. `cmd/wssh/serve.go` logs a warning when this combination is in
effect. Do not deploy without `--authorized-keys`, `--password-file`, or a
non-wildcard `--origins`.

`--allow-tcp-forwarding` enables the `direct-tcpip` channel behind `ssh -L`
and `ssh -D`. With it on, the client can name any destination and the server
dials it on the client's behalf - including loopback and cloud metadata
endpoints. Pair it with auth, or leave it off.

`--password` puts the password in `ps`. Use `--password-file` instead.

`--origins '*'` is the only origin setting that browsers and `ssh(1)` differ
on: `ssh(1)` sends no `Origin` header, so an empty `--origins` list lets ssh
through but rejects every browser. `$ALLOWED_ORIGINS` (comma-separated) sets
the same flag.

The host key must stay stable across restarts. Generate once on persistent
storage; point `$HOST_KEY` (or `--hostkey`) at it on ephemeral platforms.
Changing it makes every client report a host key mismatch.

`wssh client` prompts to trust an unknown host key the way `ssh(1)` does, then
appends it to `known_hosts`. `--insecure-host-key` skips this; the warning
is real.

## Layout notes that are easy to miss

- `wssh.Server` is an `http.Handler`; the caller owns the listener. The
  `serve` function in `cmd/wssh/serve.go` builds an `http.ServeMux`,
  mounts the server on the configured `Path`, and mounts the front end on
  `/`. The handler path `""` mounts on `/` in Go's mux (catch-all) - that is
  what makes a bare `wssh server` work for any URL.
- `cmd/wssh/web.go` embeds the whole `static/` directory with
  `//go:embed all:static`. The embed succeeds whether or not `ssh.wasm` is
  there, so a binary built before the wasm exists will not fail at compile
  time. The `wasmClientMissing` check in `web.go:40-43` runs at startup and
  warns when the wasm is absent - that warning is the only signal before
  someone opens a terminal and watches the worker die on a 404. The same
  file carries `//go:generate bash ../../client/build.sh`, which is what
  `make generate` and `go generate ./...` invoke.
- The default SSH channel/request/subsystem handlers must be installed by
  hand because `wish.NewServer` skips the `Serve` setup when only
  `HandleConn` is used. Without the `"session"` channel handler, every
  channel open is rejected with "unsupported channel type" right after auth
  succeeds. See `wssh.go:117-126`.
- `ssh.DefaultChannelHandlers` is a package-level variable - the code makes
  a copy before writing to it so the `direct-tcpip` handler does not leak
  across servers in the same process.
- The SSH WebSocket is opened with `CompressionDisabled`: the SSH payload is
  already encrypted, so compressing only leaks plaintext length and burns CPU.
- The WebSocket context is `context.Background()`, not `r.Context()` -
  `ServeHTTP` blocks for the whole session, and the session is what keeps
  it alive.
- `client.Session.Write` is non-blocking and returns `ErrInputFull` when the
  remote side is not draining - that suits a browser event loop. Use
  `WriteContext` for a terminal that must not drop keystrokes.
- `client.Session.stdin` is a channel that is never closed; closure travels
  on `s.done` instead. Closing the channel would let a later `Write` panic,
  and in WebAssembly an unrecovered panic takes the whole runtime down.
- The CLI's `client` subcommand already supports a custom command via
  trailing positional args (`cmd/wssh/client.go:81`):
  `strings.Join(args, " ")` becomes `opts.Command`, which `client.Dial`
  hands to `sshSess.Start` when non-empty. Empty means an interactive
  shell. The browser front end mirrors this with an optional command input
  in the header and a `?cmd=` query parameter; `app.js` sends it through
  `worker.js` to `client/wasm.go`'s `jsConnect`, which passes it as the
  seventh argument. `client/wasm.go:74-76` reads it. An empty value falls
  through to the existing interactive-shell path; a non-empty value runs
  the command on the remote side and ends the session when it exits.
- The CLI's `client --agent <keyfile>` flag uses the same key for two
  purposes: as a publickey auth method on the SSH handshake, and as the
  keyring of an in-band ssh-agent served over the
  `auth-agent@openssh.com` channel on the same connection. The same key
  does both jobs, so the server can authenticate the user with what it
  sees in the channel, and the channel can hand out signatures for things
  the user does on the remote side. `client.Session.Client()` returns the
  underlying `*ssh.Client`, which the test harness and the WASM bridge
  use to open additional channels. The unsafe trick in
  `auth/authfwd.ExtractSigner` reaches into the `wrappedSigner` struct
  that `ssh.ParsePrivateKey` produces to recover the inner
  `crypto.Signer` (the standard library hides it behind a private field
  that `reflect` cannot reach on Termux).
- `cmd/wssh/static/index.html` contains the literal placeholder
  `__WSSH_SESSION_PATH__`, which `cmd/wssh/serve.go`'s `frontEnd` replaces
  with the configured `--path` value before serving. The page resolves it
  relative to its own URL so the same build works on localhost, behind a
  relay, or on a domain.
- `client/wasm.go` parks forever on `<-make(chan struct{})` plus a
  `time.Sleep(time.Hour)` keep-alive: once every goroutine is parked with
  nothing pending, WebAssembly's single-threaded runtime calls `wasmExit`
  and the next call fails with "Go program has already exited". The sleep
  is what keeps `runtime.checkdead` from declaring deadlock - a blocked
  channel alone is not enough.
- `client/wasm.go` registers its bridge through the global
  `websshGoExportResolve` rather than owning a main. The page (`worker.js`)
  sets that global before `go.run` is called, so the wasm module can hand
  over its `js.Func`s without one side racing the other.
- Browser input is batched in `worker.js`: every crossing into Go resumes
  the WebAssembly runtime, and a fast typist produces one event per
  character. Two `setTimeout`-based flushes that each await can resume in
  the wrong order; the implementation coalesces into a single merged write.
- `--relay https://...` publishes the same handler through a remote relay
  via `github.com/webteleport/wtf`. `--relay :8080` is a local listener,
  useful for chaining. Relay failures are logged but do not kill the local
  server.
- `charm.land/ssh` (server-side) and `golang.org/x/crypto/ssh` (client-side)
  are both imported. The server is the wish SSH server; the client is the
  standard library. `cmd/wssh/client.go` aliases the latter as `gossh`.
- Agent forwarding is supported server-side via `auth/authfwd/`. The
  `--agent-keys` flag on the server subcommands loads private keys
  (PEM, unencrypted) into an in-memory keyring. The server installs
  the `auth-agent@openssh.com` channel handler and accepts the
  `auth-agent-req@openssh.com` global request. A client that opens
  the channel speaks the standard agent protocol against the
  in-memory keys; signatures are produced in this process and never
  reach the wire.
  Note that openssh's `ssh -A` is the *reverse* direction -- it
  forwards the *client's* local agent to the server. Talking to a
  server-side agent requires a custom client (the browser, a small
  Go program that opens the channel directly, or `wssh client
  --agent`).
  `authfwd.Install` also creates a per-connection local Unix socket
  in a temp dir and stashes its path on the per-connection
  context under `authfwd.SSHAuthSockKey`. The shell middleware
  reads that path and appends `SSH_AUTH_SOCK=<path>` to the
  session env, so any program on the remote side that talks to
  `SSH_AUTH_SOCK` (ssh-add, git push over SSH, etc) finds a working
  local agent backed by the in-memory keyring. The socket is
  created eagerly on every connection (not lazily when the
  channel opens) so the env can be set at exec time; cleanup
  watches the connection context and removes the temp dir on
  disconnect.
- The agent channel handler is installed AFTER the default channel
  handlers map is created. The `wish.NewServer` options run before
  that map is set, so any handler installed via `ssh.Option` would be
  wiped. `auth/authfwd.Install` mutates the map in place after it has
  been built, which is the only ordering that survives.

## File-by-file map

| Path | Role |
|---|---|
| `Makefile` | Build entry point. `make wssh` is the target that builds a working binary; bare `make` lists targets. |
| `wssh.go`, `wssh_test.go` | `Server` (HTTP handler wrapping wish). Path/origin/auth tests. |
| `auth/auth.go`, `auth/auth_test.go` | `auth.Config`, key files (re-read each attempt), password file (bcrypt or plaintext). |
| `auth/authfwd/`, `auth/authfwd/agent_e2e_test.go` | In-memory ssh-agent. `Keyring([]crypto.Signer)` builds it; `Install(*ssh.Server, agent)` registers the auth-agent channel and request handlers on a server already built (the option-style `Forwarding` exists for callers that wire from a fresh `wish.NewServer`). `--agent-keys` in `cmd/wssh/serve.go` loads PEM keys (ed25519/RSA) and feeds the result. |
| `client/client.go`, `client/client_test.go` | `Session`, `Dial`, `Write`/`WriteContext`/`Resize`/`Close`/`CloseStdin`. Native tests over loopback. |
| `client/wasm.go` | `//go:build js && wasm`. JS bridge, parked forever, exports `connect`/`write`/`resize`/`disconnect`/`generateKey`/`keyInfo`. Reads the optional command from arg 6. |
| `client/wasmauth.go` | `//go:build js && wasm`. JSON-shaped `credentials`, `signerFor`, `buildAuth`, `jsGenerateKey`, `jsKeyInfo`. |
| `client/build.sh` | WASM build + `wasm_exec.js` copy. Sets `CGO_ENABLED=0` so the cross-compile works on hosts (Termux) where cgo is on by default. |
| `client/cmd/webssh-web/main.go` | `//go:build js && wasm`. Just calls `client.Start()`. |
| `cmd/wssh/main.go` | Cobra root, fang executor, `--verbose`, `version`/`commit` from `-ldflags`. |
| `cmd/wssh/serve.go` | Shared `serveOptions`, `serve`, `drain`, `frontEnd`, `noCache`, `startRelays`, `addAuthFlags`, `addAgentFlags`, `openBrowser`, openssh-key-v1 parser (in `parseUnencryptedKey`). |
| `cmd/wssh/server.go` | `wssh server` subcommand (bare transport). |
| `cmd/wssh/web.go` | `wssh web` subcommand (server + front end, `--ui-only`, `--open`, `--path /ws`). Carries `//go:embed all:static` and `//go:generate bash ../../client/build.sh`; `wasmClientMissing` warns at startup if the wasm is absent. |
| `cmd/wssh/client.go` | `wssh client` subcommand (terminal raw mode, `known_hosts`, password/key auth, custom command via trailing args). |
| `cmd/wssh/keygen.go` | `wssh keygen` (ed25519/rsa/ecdsa, `--authorized-keys` to append). |
| `cmd/wssh/prompt.go` | Shared secret prompt helper (refuses non-terminal stdin). |
| `shell/shell.go` | Wish middleware: login shell, PTY with `WithJobControl`, window-change pump. |
| `cmd/wssh/static/index.html` | xterm + React + htm (no bundler). Contains `__WSSH_SESSION_PATH__` placeholder. |
| `cmd/wssh/static/app.js` | React UI (terminal, endpoints, credentials panel, optional command field, `?cmd=` support). |
| `cmd/wssh/static/credentials.js` | Key storage, passphrase/password hooks, key generation UI. |
| `cmd/wssh/static/worker.js` | Hosts the Go/WASM SSH client, batches input, forwards the optional command as `api.connect`'s seventh argument. |
| `cmd/wssh/static/selftest.html` | End-to-end browser selftest. |

## Naming and style conventions

- Packages are short and lowercase: `wssh`, `auth`, `client`, `shell`.
- Comments document intent and the non-obvious consequence, not what the
  next line of code does. Many comments explain why something is the way
  it is - keep that style.
- Errors are wrapped with `fmt.Errorf("...: %w", err)`. Library packages
  return wrapped errors; `cmd/wssh` mostly returns them unwrapped with
  `//nolint:wrapcheck`.
- Subcommand constructors return `*cobra.Command` and are named `newXxxCmd`.
  Shared flag wiring goes through helpers in `serve.go`.
- `Options` structs are configured by the caller, then handed to a single
  `New*` constructor; this is consistent across packages.

## Things that look like bugs but are deliberate

- The browser worker stops "responding" if you wait long enough with no
  input - that is the `time.Sleep(time.Hour)` keep-alive, not a hang.
- A server with no auth and `--origins '*'` accepts every connection that
  reaches the port. The startup warning is the only signal.
- `client/client_test.go` is in package `client_test` (external) and gated
  `//go:build !js`. The package compiles both natively (with tests) and as
  wasm (without). Do not unify them.
- `--path` defaults to `""` for `server` and `/ws` for `web`. Same option,
  two different defaults - `web` sets it explicitly in its `RunE` before
  calling `serve`.
- `serve` returns the first error from `auth.Options()` or
  `wssh.NewServer()` without wrapping; both branches use `//nolint:wrapcheck`.
  Match that pattern when adding a similar fail-fast branch.
- `make` with no target prints help and exits 0 having built nothing.
  Scripts and CI have to name a target; bare `make` is not a build alias.
- `go build ./cmd/wssh` succeeds even when `cmd/wssh/static/ssh.wasm` is
  absent, because the `//go:embed all:static` directive covers a directory
  rather than a file list. That is the whole reason `make wssh` is more
  than a convenience: it wires the wasm as a prerequisite of the binary,
  so a build that omits it fails instead of producing a quietly broken
  binary. The startup `wasmClientMissing` warning is the safety net for
  anyone who skipped the Makefile.

## Testing approach

- `wssh_test.go`: HTTP-level tests for path handling. `httptest.NewRecorder`
  cannot be hijacked, so a 501 response after the path check is the signal
  that the handler was reached.
- `auth_test.go`: exercises the handler functions directly against a real
  `ssh.Server` value (no listener). Uses real ed25519 keys and real
  bcrypt; no fixtures that pretend to be keys.
- `client/client_test.go`: spins up a real `wssh.NewServer` on
  `127.0.0.1:0`, dials it with `client.Dial`, asserts on stdout. `t.Setenv`
  swaps `$SHELL` for a fake shell script so the test is independent of the
  developer's login shell.
- No CI config is committed. Add one (or document where CI lives) if you
  start relying on a particular runner.
