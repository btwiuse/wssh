# Gotchas

Read this before concluding that something in this tree is broken. Each entry
is behaviour that is deliberate, with the reason it cannot simply be changed
to look more reasonable.

- The browser worker stops "responding" if you wait long enough with no
  input - that is the `time.Sleep(time.Hour)` keep-alive in `client/wasm.go`,
  not a hang. See `layout.md`.
- A server with no auth and `--origins '*'` accepts every connection that
  reaches the port. The startup warning is the only signal. See
  `security.md`.
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
- The agent channel handler has to be installed after the default channel
  handlers map is built, by mutating it in place. Anything installed through
  a `ssh.Option` is wiped. See `agent-forwarding.md`.
- A refusal raised as an error from the agent has nowhere to go: the agent
  protocol allows a failure code and nothing else, so the sentence saying why
  never reaches the caller. Every refusal in the Solana extension travels as a
  `Refusal` in the answer instead, which is already on the wire and can
  carry text. See `solana.md`.