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

The third row is what `--allow-anonymous` exists for, and it is **off by
default**. It admits the connection and then works out who it is by asking the
forwarded agent to sign a nonce this process made up: the keys in the agent are
listed, one is picked, and a signature that verifies is what makes it an
account. With no agent there is nothing to prove and nowhere to keep a balance,
so the session is shown the merged screen: that same list, plus an address field
underneath.

**Why `none` is refused by default.** A client sends `none` first as a probe,
so a server that accepts it ends the handshake before a public key is ever
offered, and every connection arrives with `PublicKey() == nil` including the
ones carrying a key. No client-side flag changes that - `-i` and
`-o PreferredAuthentications=publickey` were both measured and both still
authenticated as "none". Refusing it is the only thing that makes the server see
a key, and seeing one is the whole of how `ssh router.cafe` gets you into your
own account with no flags at all.

**The variable is whether the server accepts `none`, not `-A`, and the
distinction is worth being exact about.** `publickey` auth sends the whole key
blob - type, bits, comment - in `SSH_MSG_USERAUTH_REQUEST`, first as a query
with `have_signature=false` and again in the signed offer. A server that
*rejects* the `none` probe therefore learns the identities the client tries, in
order, until one is accepted. What `-A` moves is the ability to *sign*, not a
public key anywhere. Naming a key is free; proving you hold it is not, and only
the second is worth protecting - a public key is public already, in `id_*.pub`,
in GitHub, in commit signatures.

| Server | `none` probe | Public keys the server sees |
|---|---|---|
| cafe, default | refused | the ones before the ed25519 it accepts |
| cafe, `--allow-anonymous` | accepted | none - the handshake ends at the probe |
| `wssh`, no auth flags | refused | all of them, each rejected |
| `wssh --authorized-keys` | refused | up to and including the one that matches |

**The auth loop hands over one key, never a list, and that shapes the whole
screen.** A client offers its identities in order and stops at the first one the
server accepts, so `publickey` auth cannot enumerate. To see several ed25519
keys a client must reject all of them, and then nothing authenticates and the
client gives up with "Permission denied". The agent is the only thing in SSH
that can enumerate, which is why choosing among several keys needs `-A` and
detecting one does not. This is the whole of what whoami.filippo.io does: refuse
`none`, reject the rsa offer, accept the ed25519.

**Only ed25519 is accepted, and refusing the rest is not tidiness.** `--authorized-key`
defaults to `*`, so an accept-anything handler is installed; without a filter an
rsa key that comes first opens the session on a key that cannot name an
account, and the connection only discovers that once the UI is already up.
`ed25519Only` (`cmd/cafe/serve.go`) is the gate, applied through
`auth.Config.KeyFilter` before the authorized_keys list is consulted. It is why
an agent holding `id_rsa` and `id_ed25519` gets in on the second.

**`MaxAuthTries` is raised to 64** (`wssh.go`). Refusing keys is what lets a
later one through, so the ceiling has to clear the client's whole identity list
rather than the first few entries. x/crypto's default of 6 refuses a connection
whose sixth identity is the good one, which to the person on the other end is
indistinguishable from a wrong password.

**What refusing `none` costs, stated once:** a client with no ed25519 cannot
connect at all. It is told so by the only message that means anything -
`Permission denied (publickey)` - and `--allow-anonymous` is the switch that
gives those connections the merged screen instead.

**The username outranks the key, because now every connection has one.** Nearly
every session carries a key now, so if the key won `ssh <someone-else>@host`
would open the account of whoever was holding the connection and say nothing -
the worst possible answer, because it is a real balance belonging to somebody
else. `AccountFor` reads the username first for that reason: a name there is the
client asking for a view, and it gets one, unproved. A username that is not an
account changes nothing and the key is still the account.

Named is not proved. Somebody can type any address they can find, so:

| Can look | Cannot |
|---|---|
| balance, deposits, spend, the price list | spend the balance |
| | mint or revoke an API key |
| | deposit |

Anything that changes the account is behind proof. Proof is the same nonce
signature as above, run against an address that is already known rather than
chosen from a list, so the agent is asked whether it holds that address's key
and then asked to sign. If it does, the session owns the account and the
banner stops saying read-only. If it does not, nothing is said: an agent that
does not hold the key is the ordinary case for someone reading someone else's
balance.

| Connection | Result |
|---|---|
| `ssh router.cafe` | your own account, read-write, no flags |
| `ssh <address>@host` | that account, read-only - the name wins over the key |
| `ssh -i other_key host` | whichever key `ssh(1)` offers that the server accepts |
| a client with no ed25519 | `Permission denied (publickey)` |
| `--allow-anonymous`, no key | the merged screen below |
| `--allow-anonymous` with `-A` | the agent's keys listed, pick one and it signs |

**That screen exists only under `--allow-anonymous`, and that is the point of
it.** One screen, not two. The rows above the address field are the keys the
forwarded agent holds, and picking one signs for it; the field at the bottom
takes an address somebody pasted, and picking that opens it read-only. With no
agent the list is empty and the field is the whole screen, which is why the two
paths are one screen rather than a picker and a landing page: the difference
between them is one boolean, `Proven`, and it is set by whether something was
signed rather than by which screen you are on.

The default never reaches it, because refusing `none` means the connection
arrives already authenticated and `newModel` routes straight to the account. The
screen is the answer to a client that proved nothing, and the default is the
answer to one that proved itself.

```
  Which of these is yours?

  > /Users/gear/GitHub/wssh/id_ed25519
    gear@gear.local

  address  █

  up/down to choose, enter to sign with a key or open an address
```

## `cafe tui`: the same program with no SSH in it

`cmd/cafe/tui.go`, over `cafe.RunLocal` in `cafe/local.go`. It builds the same
model through the same constructor an ssh connection goes through, handed an
empty identity.

That identity is the whole design rather than an implementation detail: a local
run has proved nothing exactly as a connection that arrived without a key has
proved nothing, so both get `anonymousModel` and the same rules about what may
be done with what. `who` (`cafe/session.go`) is the three facts a session
carries - key, wallet, username - pulled out so one constructor serves both.
`SessionAccount` went with it, since `AccountFor` already took those three
values and a second wrapper over them was a second place for the rule to live.

| | Over ssh | Locally |
|---|---|---|
| agent | forwarded by the client, dialed back over a channel | `$SSH_AUTH_SOCK`, already running |
| host key | the identity you are trusting | none, so nothing to trust |
| proving an account | the handshake key, or a nonce the agent signs | a nonce the agent signs |
| getting in | `ssh -A router.cafe` | `cafe tui` |

**The one asymmetry is the agent, and it runs in the local one's favour**: a
deposit works here without `-A` because there is nothing to forward. That is
also the only difference, and it is a difference in transport rather than in
permission - `deps.Local` changes wording and nothing else. Making the local
path *more* permissive is the one way this could go wrong, so the proof rules
are shared code rather than a copy.

With no agent running it does not refuse to start: the address field works with
nothing at all, so it warns and opens read-only.

## Navigation: a bar, not a list of letters

There are no keys that jump between pages. The top of every screen carries a
bar of all five and highlights the one you are on, and `tab` walks it:

```
╭─────────╮╭─────────╮╭──────────╮╭────────╮╭──────╮
│ balance ││ deposit ││ api keys ││ routes ││ help │
│         └┴─────────┴┴──────────┴┴────────┴┴──────┤
│  account    6YSosJ…AsrUKL                            │
│  balance    $0.00                                    │
```

The bar is drawn with the bubbletea tabs example's borders: a rounded top, and
a bottom edge that is either `┴─┴` when inactive or `┘ └` when active. The page
sits in a box with **no top edge**, so the active tab's blank bottom opens into
it. That second half is the whole of the effect: a bar floating above a wall of
text reads as chrome, and a bar whose current tab opens into the page reads as
navigation. The ends close the run rather than each closing themselves, so the
first tab keeps its left wall and only its corner changes.

`shift+tab` goes back, wrapping at both ends. `esc` puts a caret down without
leaving the page. This replaced a footer listing what `b`, `d`, `k`, `m` and
`?` did, and the reason to replace it rather than extend it is that a footer
has to be *correct on every screen*: a list component that wanted `b`, `d`, `f`
and `u` for paging could not coexist with a footer promising those letters were
pages. The bar cannot go stale that way, because it is the navigation rather
than a description of it.

Inside the ring, one asymmetry that is deliberate:

| Page | Arrives | Because |
|---|---|---|
| balance, help | nothing focused | nothing on them takes keys |
| api keys, routes | focused | `hjkl` is only ever wanted by something already looking at a list, so arriving live saves a press |
| deposit | **not** focused | a field that eats keystrokes the moment you look at it is the trap the focus exists to prevent |

So `tab` from balance goes to deposit without touching the amount, and a second
`tab` puts the caret in it. `enter` acts on the cursor, or sends the deposit.

### Clicks, and what they cost

Mouse mode is on, cell motion rather than all motion. Over ssh that is the
difference between a program that responds and one that floods the connection -
and it also means **the terminal loses its own text selection**, which is the
trade and the reason it is deliberate rather than a default nobody thought
about.

A click becomes an intent through a `clicks` value rebuilt on every frame,
holding where each tab and each list row actually landed. It cannot be a fixed
map: the bar's width changes with the names in it and the list's height with how
many rows are on the page. The pages carrying a list report their own row
position **counted as they write it**, so a title that grows a line does not
silently move every click target down with it.

| Click | Does |
|---|---|
| a tab | switch to it |
| a row in a list | move the cursor there **and** focus it - a cursor that moved without lighting up leaves it impossible to tell what the next keypress will do |
| a key in the anonymous picker | adopt it, the same as enter |

Clicks on the box border, above the list, below the last visible row, or on a
row that is on another page select nothing, deliberately.

Two details that are decisions rather than conveniences:

- **A printable character always goes to the address field and takes the
  selection with it**, so somebody who has started typing never has to know
  which row they were on.
- **`q` does not quit from this screen.** It is a base58 character and the
  field is most of what the screen does, so `ctrl+c` is the quit and `esc`
  clears the field, quitting only once it is already empty. The same reason the
  field is filtered to base58 on the way in rather than validated on the way
  out.

`--require-key` turns anonymous access back off, for an operator who has turned it
on and changed their mind.

### What is still impossible, and why

**A list of the keys you have.** `ssh -A router.cafe` with three ed25519 keys in
the agent authenticates with whichever one `ssh(1)` offers first, and the session
goes straight to that account. The merged screen lists keys only under
`--allow-anonymous`, and it lists them by asking the agent - which is the only
way in SSH to ask. `publickey` auth cannot enumerate: the client stops offering
at the first key the server accepts, so to see three keys a server would have to
refuse all three, and then nothing authenticates.

So: **detecting one key needs no flags, choosing between several needs `-A`, and
no server-side change turns the second into the first.**

`wssh.Options.AllowNoAuth` is the switch underneath, and it composes with the
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