# RouterCafe

Read this before touching `cafe/`, `cmd/cafe/`, or anything about how a
RouterCafe session is allowed to behave. The first thing here is a security
property and it is the reason the package is shaped the way it is.

## There is no shell, and that is structural

`ssh -A router.cafe` opens a full-screen program: a balance, an API key, and a
way to deposit SOL. It is not a shell, and no connection can turn it into one.

"We did not write a shell handler" is not a guarantee on its own, so this is
what actually enforces it, and all four are checked by `cafe/session_test.go`
against a real server on a real listener:

| Attempt | What happens |
|---|---|
| `ssh router.cafe uptime` | the command is printed back as refused, exit 1, nothing runs |
| `ssh router.cafe -t` with stdin | same: stdin goes nowhere, because there is no process |
| `ssh -s router.cafe sftp` | subsystem refused |
| `ssh -L …` / `ssh -D …` | the direct-tcpip channel is never installed, so the open fails |

The middleware list in `cmd/cafe/serve.go` is `[]wish.Middleware{sessions.Middleware()}`.
There is no `shell.Middleware()` and there is no flag that would add one: that
is the point. `cmd/cafe` deliberately does not even have `--allow-tcp-forwarding`.

**Authentication is on, and says so.** `--authorized-key`, `--authorized-keys`
and `--authorized-addresses` all default to `*`, so anybody who reaches the port
can hold an account. That is safe only because of the four rows above, and it is
a real decision rather than an oversight: refusing every key would make the
product unusable, and the session it gets is a program. A test asserts the
defaults, because a flag default is easy to change by accident on a public host.

## The account is the key

An ed25519 SSH key is already a Solana account address, so the key that
authenticates the session *is* the account a deposit credits and a balance
belongs to. `AccountFor` in `cafe/session.go` is the whole of that rule:

- the session's public key through `solana.AddressFor`, or
- the account a browser proved over the wallet sign-in, through
  `wssh.WalletAddress`.

The SSH username is never consulted: it is chosen by the client, so every
account would be the same account. A key that is not ed25519 names no account,
and the session says so rather than handing out a UI showing zeros.

## Deposits

`ssh -A` exists for this. `cafe/topup.go` builds a System transfer from the
caller's own account to the treasury and asks the agent it was handed for a
signature. The private key never crosses.

The signed bytes are then read back before anything is broadcast, and all four
checks matter because each is a way the answer could differ from the request in
a way that costs somebody money:

1. `solana.VerifySigned` — the signature is by the paying key over these bytes.
2. `solana.FeePayer` — read out of the signed bytes, not taken from the request.
3. `checkTransfer` — one instruction, the System Program, no writable account
   other than the source and the treasury, and the amount is the amount typed.
4. Credit happens only after the cluster confirms the signature.

A refusal is a refusal: the signature check is the one that assumes nothing
about the far end, because `ssh -A` puts the *client's* ssh-agent there and that
agent signs whatever it is handed.

`--dry-run-deposits` prices a deposit and reports what it would have done
without asking for a signature or moving a balance. `Treasury.Credits` rounds
**down**, always: rounding up would be a way to mint a little money out of many
small deposits.

## Money

Balances are `int64` counts of micro-USD (a millionth of a dollar). Never a
float. There is no rounding step anywhere near a balance decision.

An API request is billed by **reservation**: the most it could cost is held
before the provider is asked, and the difference is given back once the real
usage is known. `Ledger.Reserve` and `Ledger.Settle` are separate from `Debit`
because a hold is not spend, and the `spent` counter has to say what was really
served. A provider that reports no usage at all is charged the reservation,
which is the only answer that is not a loophole.

API keys are stored as SHA-256 digests and shown once, when minted. The ledger
file holds every balance, so it is not a file of live credentials.

## The two binaries share one front end

`cmd/cafe` serves the wssh browser terminal at `/app` with everything it
always had, and it reaches the same sessions, so it shows the same program.
Serving a shell behind `/app` and a UI behind `ssh` would make the browser the
way in, which is the one thing this design rules out.

The files live in package `webui` rather than under the old `cmd/wssh/static`, because
`//go:embed` can only see its own package's directory and two binaries now need
them. `client/build.sh` and the `Makefile` write there.

## Plain SSH is not the HTTP port

The documented way in is `ssh -A router.cafe`, which is plain SSH on port 22.
The HTTP listener answers WebSocket upgrades and nothing else, so `--tcp-addr
:22` (or a WebSocket proxy in front of `/ws`) is what makes that command work.
The server logs a line saying so when `--tcp-addr` is not set, because an
operator who starts it and then runs the command the landing page prints
otherwise gets an HTTP 400 with nothing to explain it.

## Upgrading

`cafe upgrade` replaces the running binary with the newest release, and shares
its implementation with `wssh upgrade` through package `selfupdate`. That
sharing is not tidiness: every rule in there is one that broke an upgrade once,
and a second copy of them is a second set to get wrong. A release carries four
binaries whose asset names all end with the same platform suffix, which is the
situation that produced the wrong-binary bug.

A ledger is a file, not a release artefact, so an upgrade never touches one.

## The tab icon

RouterCafe serves its own mark at `/favicon.ico` and `/favicon-256.png`, out of
the same embed as the landing page. `webui` carries a favicon placeholder that
is filled with wssh's own unless the binary serving it says otherwise, so
`/app` wears the same mark as the landing page rather than wssh's prompt.

## A key that names no account

Two different problems, and they are not the same message:

| What arrived | What is said |
|---|---|
| an ed25519 key | nothing; it names an account and the UI opens |
| an RSA or ECDSA key | this key names no account, and the command that fixes it |
| no key at all | the client is refused during authentication |

The third row is what `--allow-anonymous` exists for, and it is **on by
default**. It admits the connection and then works out who it is by asking the
forwarded agent to sign a nonce this process made up: the keys in the agent are
listed, one is picked, and a signature that verifies is what makes it an
account. With no agent there is nothing to prove and nowhere to keep a balance,
so the session is shown how to get a key and given nothing else.

**The cost, stated once and plainly**: a client sends `none` first as a probe,
so a server that accepts it ends the handshake before a public key is ever
offered. Every connection then arrives with `PublicKey() == nil`, including the
ones that carried a key, and **no client-side flag changes that** -
`-i ~/.ssh/id_ed25519` and `-o PreferredAuthentications=publickey` were both
measured and both still authenticated as "none". `-A` is what makes the
difference, because the agent is reachable after the handshake and the key file
is not.

| Connection | Result |
|---|---|
| `ssh -A` with the key in the agent | adopts it, signed, and opens the account |
| `ssh -A -i key` with the key in the agent | the same |
| `ssh -i key` with no `-A` | the notice: `-i` alone cannot work from now on |
| `ssh` with no key and no agent | the notice |

`--require-key` turns it off and restores a plain refusal, for an operator who
would rather nobody without a key hear from the server at all.

`wssh.Options.AllowNoAuth` is the switch underneath. It composes with the
wallet sign-in hook rather than replacing it, so opening the door does not
quietly stop a browser wallet from being let through.

The refusal screen wraps to the terminal it was given, command included: a
half-printed command is the one thing it must never show, since that is the
line somebody is about to copy.

## What is not built

The upstream is configured with one `--upstream` and one `--upstream-key`. With
exactly one upstream configured every route goes to it whatever provider the
catalogue names, which is the ordinary deployment; with two or more, a route
naming a provider that is not among them is refused by name rather than sent to
whichever endpoint happened to be there.