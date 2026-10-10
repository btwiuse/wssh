# Layout notes that are easy to miss

Read this when something behaves in a way the code does not obviously explain.
Everything here is a consequence that is deliberate; the file reads like a list
of bugs because the reasoning does not sit next to the line it applies to.

## The pieces

Three, and they share almost nothing:

- **Server** (`wssh.go`, `cmd/wssh/server.go`, `cmd/wssh/web.go`,
  `cmd/wssh/serve.go`) - HTTP server that does a WebSocket upgrade per request
  and hands the bytes to a `wish/v2` SSH server.
- **Client library** (`client/client.go`) - opens a WebSocket, runs an SSH
  client over it, exposes a `Session`. Same code is used by both the browser
  (WASM) and the CLI `client` subcommand.
- **Front end** (`cmd/wssh/static/`, `client/wasm.go`, `client/wasmauth.go`,
  `client/cmd/webssh-web/`) - a worker-hosted Go/WASM SSH client behind a React
  + xterm UI. `static/ssh.wasm` and `static/wasm_exec.js` are generated; the
  rest is hand-written.

`shell/` is the wish middleware that runs the local user's login shell. It
manages the PTY itself rather than going through `wish.Command`, because a
usable login shell needs the requested command, terminal resizes, and job
control (`^C`/`^Z` to the foreground job) - all three of which `wish.Command`
does not give it.

`auth/` is a separate config package for SSH authentication, on purpose: the
browser client imports `auth/agentkey` and has no use for password files.

## The server side

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
- `--relay https://...` publishes the same handler through a remote relay
  via `github.com/webteleport/wtf`. `--relay :8080` is a local listener,
  useful for chaining. Relay failures are logged but do not kill the local
  server.

## The client library

- `client.Session.Write` is non-blocking and returns `ErrInputFull` when the
  remote side is not draining - that suits a browser event loop. Use
  `WriteContext` for a terminal that must not drop keystrokes.
- `client.Session.stdin` is a channel that is never closed; closure travels
  on `s.done` instead. Closing the channel would let a later `Write` panic,
  and in WebAssembly an unrecovered panic takes the whole runtime down.
- The CLI's `client` subcommand supports a custom command via trailing
  positional args (`cmd/wssh/client.go:81`):
  `strings.Join(args, " ")` becomes `opts.Command`, which `client.Dial`
  hands to `sshSess.Start` when non-empty. Empty means an interactive
  shell. The browser front end mirrors this with an optional command input
  in the header and a `?cmd=` query parameter; `app.js` sends it through
  `worker.js` to `client/wasm.go`'s `jsConnect`, which passes it as the
  seventh argument. `client/wasm.go:74-76` reads it. An empty value falls
  through to the existing interactive-shell path; a non-empty value runs
  the command on the remote side and ends the session when it exits.

## The browser client

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

## Two SSH libraries

`charm.land/ssh` (server-side) and `golang.org/x/crypto/ssh` (client-side)
are both imported. The server is the wish SSH server; the client is the
standard library. `cmd/wssh/client.go` aliases the latter as `gossh`.

The two confuse each other more easily than their names suggest, because both
call themselves "ssh". Everything in `client/`, `cmd/sol-tx/`,
`cmd/sol-keys/` and `solana/` is `golang.org/x/crypto`; everything under
`auth/`, `shell/` and the server options is `charm.land`.

Agent handling spans both and both directions - see `agent-forwarding.md`.