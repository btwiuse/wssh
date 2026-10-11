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

### One frame, filling the window

All three screens - the account screen, the one a connection that proved
nothing gets, and the refusal - are drawn by one `frame` in `cafe/frame.go`,
and it fills the window rather than the contents.

That is not tidiness. A frame the height of its content is a different shape
from a frame the height of the window, so moving between a screen with a lot on
it and one with a little changes the size of everything. The moment somebody
notices is the moment **after signing**, when the box they were typing an
address into is replaced by one twice as tall: it reads as the program having
been swapped rather than the same program having changed page.

Two consequences that are easy to get wrong again:

- **`Height`/`Width` in lipgloss v2 are the total including the border**, so
  `Width(m.width)` really does reach the edge.
- **`bodyWidth` is `width - 2`, not `width - 4`.** `wrapText` indents every
  line by two of its own and subtracts two again, so passing `width - 4` counts
  the indent twice and quietly cuts a token that used to fit - which is how an
  eighteen-character key path stopped fitting on a twenty-column terminal.

`wrapText` drops its own indent below 24 columns for the same reason: on a
narrow terminal the indent is the first thing that should go, because it is the
thing a path cannot spare.

**`MaxHeight` is gone from the frame, and that was the point.** `MaxHeight`
cuts from the bottom of the *rendered box*, and the last thing it takes is the
bottom edge: a page with more on it than the window can show left the frame
open along one whole side, which reads as the terminal having scrolled rather
than as a page being long. The page is now wrapped to the inside of the box and
cut to `box-1` lines **before** the border goes on. Wrapping first matters for
its own reason: lipgloss wraps whatever is too wide on the way into the border,
and counting the lines before it has done that is how a page of long sentences
came out several lines taller than its window.

The same care is in the screens that have no bar at all. The box has no top
edge of its own - on the account screen the bar's bottom edge *is* it - so
`frame` draws one in the box's own colour when there is no bar, and `chrome`
counts that line. Leaving it out is how the frame ends up one line taller than
the window it is filling, which is the bug `TestTheFrameIsClosedAtAnySize`
exists for. On the bar's side, `carryBarEdge` runs the bottom edge on to the
right-hand corner: the bar is as wide as the names in it and the box is as
wide as the window, and without it the top of the frame simply stops a third of
the way across the terminal.

### What fits, and who decides

Nothing guesses. The list on a page is sized by **the page that owns it, every
frame**, not at the window resize: the room it gets is what is left of the box
after the title above it and the prose under it, and those change underneath
it. A notice wraps to a second line when a key is minted, and a page with a
fresh key on it has two more lines under the list than one without. Sized once,
a list is right until the first time somebody does something, and then it is
either scrolling off the bottom of the box or leaving a hole under it - both of
which look like the frame is broken.

The size is asked and checked rather than derived (`fitted`): the component
grows past the height it was given instead of cutting itself at it, and its
arithmetic around a status bar, a blank between rows and a margin above the page
dots is not something to reimplement here. Ask, look, correct, twice at most.

**Order on a page is a policy, and the api keys page has one.** The reassurance
underneath the list - that a key is printed once, and that losing one costs
nothing - is dropped first on a short terminal. Everything below it in the frame
is a notice, and on that page a notice can be the only copy of a key that will
never be printed again. The refusal does the same a paragraph at a time: the
first paragraph is the sentence saying what happened, the second is why ed25519
is the shape an account takes, and the commands are never the thing that gets
cut. `KeyCommand`'s own note says a half-printed command is the one thing it
must never show.

The footer drops bindings that will not fit rather than wrapping, because the
frame is a fixed height and a two-line footer would push it past the terminal.
Both are discoverable losses: the help screen lists everything.

### countLines and the trailing newline

Every chunk of a page here ends with a newline, because they are concatenated.
So `countLines` - which is what every layout decision in the TUI is measured in -
counts a trailing newline as closing a line rather than starting one, and
returns zero for the empty string. Getting this wrong puts every measurement of
a page one line out, which is a list drawn a line lower than the frame thinks
it is and a click one row out. `trimLines` in `frame.go` does the same thing on
the way out.

## Navigation: a bar, not a list of letters

There are no keys that jump between pages. The top of every screen carries a
bar of all five and highlights the one you are on, and `tab` walks it. **The
name and the address are on the bar's own line**, not on one above it:

```
              ╭─────────╮╭─────────╮╭──────────╮╭────────╮╭──────╮
  RouterCafe  │ balance ││ deposit ││ api keys ││ routes ││ help │   router.cafe 0.1.6
──────────────┘         └┴─────────┴┴──────────┴┴────────┴┴──────┴─────────────┐
│                             _ \            |            __|        _|          │
│                              /  _ \ |  |  _|  -_)  _|(     _` |  _|-_)         │
│                           _|_\\___/\_,_|\__|\___|_| \___|\__,_|_|\___|         │
│                                                                        │
│  account    6YSosJ…AsrUKL                                                │
│  balance    $0.00                                                        │
```

**The bar's bottom line is the box's top edge, so it is built the whole width
of the window** and not padded out of blocks that happen to add up. A gap in it
is a hole in the top of the frame with the page showing through, which is the
one thing a frame cannot have - and it is invisible to a test that only checks
the box lines, so `TestTheBarsEdgeSpansTheWholeWindow` checks that line is
exactly as wide as the window on every screen at every size, and that nothing
but rule and the active tab's opening is on it. The three rows are therefore
assembled one at a time out of the tab run's own three rows; splicing the run
in whole brings its other two rows with it.

That is also why **no corner is corrected**, which is the one thing the tabs
example has to do. The example overrides both ends because there the page is
exactly as wide as the bar, so the run of edge stops where the last tab stops.
Here the rule continues either side of the tabs, and the corners the style
gives are already the right ones for a rule that continues: `┴` where it passes
under an inactive tab, and `┘` and `└` where the active tab opens into the page.

A line of chrome that changes nothing is a line somebody has to look past, and
the brand line above the bar was exactly that. Folding it in gives the page one
more line for content, which it wanted.

**The version is on the bar, not at the bottom of the help screen.** It was
there once, which put it on one screen of five and below the fold on exactly the
terminals with least room - the same terminals that cut the bottom off
everything else. It is on every screen now, and the help screen says what this
is rather than what build of it. A build with no version ldflags prints no
version: a bare `dev`, or a blank, reads as a bug rather than as an unversioned
build.

The bar is drawn with the bubbletea tabs example's borders: a rounded top, and
a bottom edge that is either `┴─┴` when inactive or `┘ └` when active. The page
sits in a box with **no top edge**, so the active tab's blank bottom opens into
it. That second half is the whole of the effect: a bar floating above a wall of
text reads as chrome, and a bar whose current tab opens into the page reads as
navigation. Only the first tab's corner is corrected, and it keeps its left
wall.

What the bar sheds when the terminal is too narrow, in order: the version, then
the address, then **the name**, then the whole thing either side of the tabs.
The name goes last on purpose - it is the one piece of the line that is also
the way back to the balance screen, and a logo dropped for want of room is a
logo nobody can get home from.

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

### Who gets the keyboard, and why n did nothing

The rule is **a text field gets all of it, a list gets only what it claims.**
Both halves are load-bearing and they are the reason `n` on the api keys screen
did nothing at all.

`list.Model.Update` swallows every key it has no binding for. The keys page
arrives **focused** - that is what makes `hjkl` work without a keystroke - so
`n`, `q`, `r`, `?` and `y` were all being handed to a list that discarded them.
`n` was the one somebody noticed, because it is the key that page exists to
offer. `listClaims` asks the keymap whether a key is the list's at all, and only
hands it over when it is; everything else falls through to `onProgramKey`. Write
the claim list out beside the keymap instead and it drifts the first time
upstream adds a binding.

The other half is the reason the same rule does not apply to the amount field:
a field that disconnects the session because somebody typed `q` into an amount
is exactly the trap the focus was added to remove. `tab` never reaches either
widget - `onKey` handles it before dispatch - which is why `tab` from a focused
deposit leaves the page rather than being swallowed.

### Clicks, and what they cost

Mouse mode is on, cell motion rather than all motion. Over ssh that is the
difference between a program that responds and one that floods the connection -
and it also means **the terminal loses its own text selection**, which is the
trade and the reason it is deliberate rather than a default nobody thought
about.

A click becomes an intent through a `clicks` value rebuilt on every frame,
holding where each tab and each list row actually landed. It cannot be a fixed
map: the bar's width changes with the names in it and the list's height with how
many rows are on the page.

**The rows are recorded by the delegate as they are drawn**, not counted
afterwards. `rowDelegate` is a pointer - the only delegate here that is - and
keeps the line each row starts on, counting from the top of the list's own view
plus the two lines the component puts above the first row. It also records the
**item index** rather than the row number, because a list pages: the third row
on the second page is not the third item, and a click that selected the third
item would revoke a key on a different page from the one under the cursor.

The arithmetic this replaced (`off / linesPerRow`) was a guess about a component
that puts a status bar above its rows and a blank between them, and it was wrong
by a line and a half - which on this screen is a revoke of somebody else's key.
`TestAClickLandsOnTheRowThatWasDrawn` finds each key's line in the drawn frame
and clicks it, so the arithmetic is checked against the screen rather than
against itself.

| Click | Does |
|---|---|
| a tab | switch to it |
| the name at the left of the bar | switch to the balance screen, which is what the balance tab does |
| the wordmark on the balance screen | switch to the balance screen, the same act by the same code path |
| a row in a list | move the cursor there **and** focus it - a cursor that moved without lighting up leaves it impossible to tell what the next keypress will do |
| a key in the anonymous picker | adopt it, the same as enter |

Both links go through `clicks.link`, and the destination is carried with the
area rather than worked out from the position. The name at the left of the bar
goes somewhere and is not one of the pages in the ring, so a bar whose clicks
are indexed against `screens` navigates to the wrong page the moment anything is
added to either side of it.

**The wordmark is a wordmark, not a layout**: `RouterCafe` in a fixed-width
face, generated once with figlet and pasted in. Clickable, like the name on the
bar - where that one is a way of getting back, this one is what somebody lands
on, and a logo you cannot click is a logo that is only decoration. It is left
out entirely below 52 columns rather than shrunk or cut: a wordmark wrapped to
two half-words is worse than none, and the balance is on the same screen
either way. `m.mark` records where it landed, because that is a fact about what
was drawn and `frame` is where the click map is built.

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

## The help screen scrolls

It is the one page with more on it than a terminal shows, and it used to be
drawn in full and cut by the frame - which meant the bottom of every page,
including the version line, was invisible on exactly the terminals that had
least room, and missing text read as a broken screen rather than as more of it.

It is a `bubbles` viewport now (`cafe/help.go`), sized to the box, with a
keymap narrowed to the keys a pager's default would collide with: the default
claims `space`, `b`, `d`, `f` and `u`, and this program means something else by
two of those letters. `j`/`k`, the arrows, pgup/pgdown, and `g`/`G` - the last
two handled here, because a viewport has no binding for them.

**The pager is sized in `sizeHelp`, from the window size, and not by
`renderHelp`.** This program's `View` is a value receiver: anything a render
touches is thrown away when the frame is printed. A pager sized and filled
during the draw is a pager of height zero with no content in it by the time the
next keystroke arrives, and a pager that believes it has no room does not
scroll. Same trap the two lists were nearly caught by, which is why the lists
are sized by the page that draws them.

The footer says `hjkl scroll` only when there is actually something below the
fold. A hint that claims a page scrolls on a terminal where it does not is worse
than no hint, because the person presses `j` and then wonders why nothing
happened.

## What is not built

The upstream is configured with one `--upstream` and one `--upstream-key`. With
exactly one upstream configured every route goes to it whatever provider the
catalogue names, which is the ordinary deployment; with two or more, a route
naming a provider that is not among them is refused by name rather than sent to
whichever endpoint happened to be there.