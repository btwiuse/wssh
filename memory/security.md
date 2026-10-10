# Security posture

Read this before deploying anything, and before changing how auth, origins, or
forwarding are wired.

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

## What keys reach the session

`--agent-keys` on the server loads private keys (PEM, unencrypted) into an
in-memory keyring and serves signatures from them for the life of the
connection. The key never travels, but anything the session asks the agent to
sign, it gets signed - that is the point, and also the risk. It is on the
server, so it is a server-side decision: do not turn it on for a server you
did not already trust with those keys.

Client-side agent forwarding (`ssh -A`) is the opposite direction and moves no
key at all. See `agent-forwarding.md`.

The agent channel is one more authenticated channel and inherits the
session's authentication. It is not a way around it: a session that did not
authenticate does not get an agent.