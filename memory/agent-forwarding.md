# Agent forwarding and server-side agents

Read this when touching `auth/agentkey/`, `Options.Agent`, `--agent-keys`,
`ssh -A`, or anything that puts an `SSH_AUTH_SOCK` in a session.

## The two directions are not the same feature

Agent forwarding (`ssh -A`) is the *client* holding the key and the server
relaying requests back to it. `Options.Agent` (and `--agent-keys`) is the
*server* holding the key and handing out signatures itself. They must not be
conflated, and neither is a variation of the other.

`Options.AgentSigners` on the client is deliberately signer-based rather than
path-based so a caller can supply an `ssh.Signer` that asks the user before
signing; the private key never crosses, only signatures.

The CLI's `client --agent <keyfile>` flag uses the same key for two
purposes: as a publickey auth method on the SSH handshake, and as the
keyring of an in-band ssh-agent served over the `auth-agent@openssh.com`
channel on the same connection. The same key does both jobs, so the server can
authenticate the user with what it sees in the channel, and the channel can
hand out signatures for things the user does on the remote side.
`client.Session.Client()` returns the underlying `*ssh.Client`, which the test
harness and the WASM bridge use to open additional channels.

`auth/agentkey.Keyring` takes those `ssh.Signer` values as they are: the agent
protocol signs SSH data, so there is no reason to reach past them for the
`crypto.Signer` the library keeps in an unexported field.

## How OpenSSH asks

**As a request on the session channel, not as a global request.**
`client_channel_request_agent_forwarding(ssh, id)`, with the channel id. It
has always been this way; it is not a recent change. A handler registered in
`Server.RequestHandlers` therefore never sees it, and the failure is silent in
the worst way: charm/ssh answers the session request with success and leaves
the rest as a `// TODO`, so the client believes it was agreed to and the
session just has no `SSH_AUTH_SOCK`.

Ask `ssh.AgentRequested(sess)`. That is where charm/ssh records it.

The client must send `auth-agent-req@openssh.com` **before** opening the
shell: the server decides whether to dial back at session start. The agent
channel handler goes up first, because the server may dial back the moment it
agrees, but the request that asks goes on the session.

The client asks the same way on the session it opens, before the shell.

## The server-side agent

Signing keys are exposed to sessions server-side via `auth/agentkey/`. The
`--agent-keys` flag on the server subcommands loads private keys (PEM,
unencrypted) into an in-memory keyring. The server installs the
`auth-agent@openssh.com` channel handler and accepts the
`auth-agent-req@openssh.com` global request. A client that opens the channel
speaks the standard agent protocol against the in-memory keys; signatures are
produced in this process and never reach the wire.

Note that openssh's `ssh -A` is the *reverse* direction - it forwards the
*client's* local agent to the server. Talking to a server-side agent requires
a custom client (the browser, a small Go program that opens the channel
directly, or `wssh client --agent`).

`agentkey.Install` also creates a per-connection local Unix socket in a temp
dir and stashes its path on the per-connection context under
`agentkey.SSHAuthSockKey`. The shell middleware reads that path and appends
`SSH_AUTH_SOCK=<path>` to the session env, so any program on the remote side
that talks to `SSH_AUTH_SOCK` (ssh-add, git push over SSH, etc) finds a
working local agent backed by the in-memory keyring. The socket is created
eagerly on every connection (not lazily when the channel opens) so the env can
be set at exec time; cleanup watches the connection context and removes the
temp dir on disconnect.

The agent channel handler is installed AFTER the default channel handlers map
is created. The `wish.NewServer` options run before that map is set, so any
handler installed via `ssh.Option` would be wiped. `auth/agentkey.Install`
mutates the map in place after it has been built, which is the only ordering
that survives.

`auth/agentkey.Install` registers the auth-agent channel, the global request,
and a per-connection local socket on a server **already built**. There is no
`wish.Option` wrapper because wish pulls in bubbletea, which has no js build,
and the browser client imports this package.

Requests are serialised: `agent.NewClient` is one channel with one sequence
number, so a relay that ran requests concurrently would interleave them.
`auth/agentkey.Forward` must be appended **after** the shell middleware in
`Options.Middleware`, because wish composes last-one-outermost.

## The comment is the source, and it is set where the key is loaded

The comment at the end of a line — `ssh-add -l`, `ssh-add -L`, `sol-keys` — is
the only place any of them can say **where a key came from**, and only the code
that loaded the key knows that. So `agentkey.KeyringWithComments` takes it, and
each builder supplies what it actually knows:

| Builder | Comment |
|---|---|
| `cmd/wssh/serve.go buildAgent` (`--agent-keys`) | the key file's base name, as ssh-add prints for a key in `~/.ssh` |
| `client/wasmauth.go buildAuth` (browser) | the name the page gave the imported key |
| `client/wasm.go` (browser, connected wallet) | `solana:<address>`, or `wallet` with no address. |

An empty comment is the honest answer and is left empty. Nothing is invented in
its place, and in particular **not the algorithm name**: it used to be filled
with `pub.Type()`, which made every line in a wssh session read
`ssh-ed25519 AAAA... ssh-ed25519`. `ssh-add -l` already prints the type in
parentheses after the comment, and `sol-keys` reports it as a field of its own,
so it was never information anything could use — only the shape of a mistake
that looked deliberate.

**The wallet's prefix says the address is a Solana address, and that is why
there is a prefix at all.** ed25519 is not Solana's — Sui and Near wallets are
on the same curve — so a 32-byte key and its base58 are what any of them looks
like. The address on its own does not say which chain's encoding it is in, and
that is exactly what `solana:` adds. `solana.AgentKey.Comment` reports
whatever the agent said, verbatim, and `sol-keys` prints it unchanged — a line
that claims a key came from `solana.ed25519` is a claim the agent made.

`sol-keys` and `sol-tx` read that label to tell which of an agent's keys a
wallet will be asked about, which is why `WalletCommentPrefix` lives in
`auth/agentkey` rather than in the browser client: both sides have to agree on
what the label means, or one of them is reading a string the other never
wrote.

## What a session does with the agent

`sol-tx` is the main consumer, and it has two signing paths depending on
whether the agent knows the `solana-tx@wssh` extension. A plain ssh-agent
does not, and never will. See `solana.md`.

`sol-keys` reads the same socket without signing anything, and prints what
each key is on Solana.