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

## Every server learns which keys you have, and one flag stops it

`publickey` auth puts the whole key blob in `SSH_MSG_USERAUTH_REQUEST` - type,
bits, comment - once as a query (`have_signature=false`) and again in the signed
offer. A server that refuses the `none` probe therefore gets every identity the
client tries, in order, until one matches: the agent's keys and every
`~/.ssh/id_*`. whoami.filippo.io is that, and no configuration stops it, because
`ssh -A` was never the mechanism - `-A` moves no public key, it moves the ability
to *sign*, which is the part actually worth protecting.

The client-side lever is real and it works against any server:

```
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=none host
```

Permission denied, nothing disclosed. Narrower but still authenticating:
`-o IdentitiesOnly=yes -i ~/.ssh/one_key`. Narrowing what the agent holds
(`ssh-add -d`) is the same lever for everything that reads the agent.

There is no server-side equivalent, and that is the point to remember when
reading a server's security notes: a server either refuses `none` and harvests
keys, or accepts `none` and has no reason to ask for them. Those are not two
settings, they are one.

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

## RouterCafe is the other way round

`cafe` authenticates everybody: `--authorized-key`, `--authorized-keys` and
`--authorized-addresses` all default to `*`, and anybody who reaches the port
can hold an account. That is a decision, not an oversight, and it is safe only
because a session there is a program rather than a command line: commands are
refused by name, subsystems are refused, and `direct-tcpip` is never installed.

The deposit path is the other thing worth reading before deploying it: a
transaction is signed by the client's own agent, so it is checked against what
was asked for before anything is broadcast. `--upstream-key` is the operator's
provider credential and is not a secret the protocol needs anybody else to see.
`memory/cafe.md`.
