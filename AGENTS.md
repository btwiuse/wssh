# AGENTS.md

Notes for working in this repository. Read this before touching anything that
the obvious file layout does not already make clear.

`wssh` serves an SSH session over a WebSocket. The WebSocket is a reliable
bidirectional pipe and nothing more: SSH is self-contained, so key exchange,
auth, resizes and job control all travel in-band. There are three pieces — a
server that upgrades HTTP and hands the bytes to a wish SSH server, a client
library used by both the CLI and the browser, and a Go/WASM browser front end.
Which file is which: `memory/file-map.md`.

Three things that matter every time:

- **Authentication is off by default.** With no auth flags and `--origins '*'`,
  any page the user visits can open a shell on the port. Turn on
  `--authorized-keys`, `--password-file`, or a non-wildcard `--origins` before
  this goes anywhere. `memory/security.md`.
- **`make wssh` is the build, not `go build ./cmd/wssh`.** The browser client
  is a build artefact; without it the binary still compiles, still runs, and
  serves a page whose worker dies on a 404. `make check` before committing.
  `memory/commands.md`.
- **A note that earns its place goes in `memory/<topic>.md`, not here.** Every
  line in this file is paid for on every request, relevant or not. Add a line
  to the table when you add a file.

## Notes

| File | Read it when |
|---|---|
| [`memory/commands.md`](memory/commands.md) | Building, running, or testing anything. |
| [`memory/security.md`](memory/security.md) | Deploying, or changing auth, origins, or forwarding. |
| [`memory/layout.md`](memory/layout.md) | Something behaves in a way the code does not explain. |
| [`memory/agent-forwarding.md`](memory/agent-forwarding.md) | Touching `auth/agentkey/`, `Options.Agent`, `--agent-keys`, `ssh -A`, or `SSH_AUTH_SOCK`. |
| [`memory/solana.md`](memory/solana.md) | Touching `solana/`, the browser wallet side, `sol-tx`, or `sol-keys`. |
| [`memory/file-map.md`](memory/file-map.md) | You need to know which file owns something. |
| [`memory/conventions.md`](memory/conventions.md) | Writing code, or a note, that should look like it belongs here. |
| [`memory/gotchas.md`](memory/gotchas.md) | Before concluding something in this tree is broken. |
| [`memory/testing.md`](memory/testing.md) | Adding a test, or trusting one that passes. |