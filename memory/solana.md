# Solana: signing, addresses, and the wire format

Read this when touching `solana/`, `auth/agentkey/solana.go`,
`cmd/sol-tx/`, `cmd/sol-keys/`, `cmd/wssh/static/solana.js` or
`scripts/sol-tx/`.

## Signing a transaction from a session

There are two ways a session can get a transaction signed, and they are not
variants of each other - they share no code beyond the wire format.

**With a wallet** (a browser page, or the wasm client). The agent answers the
`solana-tx@wssh` extension: the wallet builds the transaction, shows it to a
person, and returns it signed. Nothing is built here.

**With a plain ssh-agent** (`ssh -A`, `--agent-keys`). No ssh-agent has ever
heard of the extension, and none ever will. The work splits: `solana/build.go`
builds the transaction, because the format is not something an agent has
reason to know, and `solana/agentsign.go` hands the message over as an
ordinary `agent.Sign` request, because that is the one thing an agent is for.
`Ask` tries the extension first and falls back on `ErrExtensionUnsupported`.

The fallback exists because `ssh -A` into a wssh session used to produce a
session with an `SSH_AUTH_SOCK` and nothing able to do anything with it.

**Who signs is decided by the request, not by whether a wallet exists.** A
browser forwards the imported SSH keys *and* the wallet in one agent, so
"there is a wallet" says nothing about who should sign a given transaction.
`--signer` decides:

| `--signer` | Who signs |
|---|---|
| empty | the wallet, which picks its own account |
| the wallet's own account | the wallet — only a person can approve that key |
| some other account this agent holds | signed here: the page builds the transaction (the serialisation belongs to the library that tracks the chain) and this side signs it |
| an account this agent does not hold | refused, with a sentence |

The field is called `signer`, not `payer`, and the distinction is not
cosmetic. It answers *which key signs*; the fee payer follows from that
because Solana requires the fee payer to be a required signer, so with one
signer the two are the same account. Naming the signer is the question a
caller has. Naming the payer would have been asking for a consequence, and
would have read as though the two could be told apart.

Two rules the routing rests on, both of which were violated at once:

- **A named payer has to be the one that signs.** The wallet choosing a
  different account than the one asked for is an answer to a different
  question, and the caller would be handed a signature whose fee payer is not
  the account it named. This is checked on the *answer*, not the request, so
  it holds even for a caller that never declared which key is the wallet's.
- **The fee payer has to sign.** Solana requires it, so `solana/agentsign.go`
  refuses a payer the agent does not hold, and so does the extension. A payer
  passed through to be built anyway produced a transaction the cluster
  rejected for a reason pointing nowhere near this.

`WithSolana` takes the wallet's public key for the routing: it is the only way
to tell the wallet's key from an imported one, and without it a named payer
cannot be attributed and goes to the wallet.

**A refusal raised as an error goes nowhere.** The agent protocol allows a
failure code and nothing else, so a sentence saying why never reaches the
caller - the command sees one byte and reports a generic failure. Every
refusal the extension makes therefore travels as a `Refusal` in the answer,
which is already on the wire and can carry text.

The same message has no key-type field: the algorithm is inside the blob.
A reader expecting `type, blob, comment` reads the blob as the type and then
walks off the end, which the Deno script did until it was pinned to real
bytes. See `testing.md`.

## What an agent key means on Solana

A Solana account address is an ed25519 public key written in base58. That is
the whole correspondence, and it is easy to get wrong in the direction of
assuming there is machinery: an ed25519 SSH key is not hashed into an address,
derived, or looked up. It already is one. `solana.AddressFor` is the only place
in the tree that turns a key into an account, and both `sol-tx` (when it has to
pick a signer out of a single-key agent) and `sol-keys` go through it, so the
signer a transaction is built with and the address a listing prints are the
same string by construction.

Everything else names no account, and the only correct answer to "what is the
Solana address of this RSA key" is none. Do not reach for a hash of it, or a
point on the curve derived from it: those would be strings that look like
addresses and belong to nobody.

Two related details that are easy to get wrong:

- **A certificate names the key inside it.** `AddressFor` follows
  `*ssh.Certificate` to `cert.Key` first. Reporting the outer algorithm instead
  would say a certificate signs for nothing, which is wrong.
- **The agent's comment survives, verbatim.** OpenSSH sends `user@host` in the
  identities answer; this repository's own keyring is handed a comment by
  whoever loaded the key — a file name, a wallet's address. `AgentKey.Comment`
  carries it through to the end of the line exactly where ssh-add puts it, and
  adds nothing. `solana` does not get to label a key here: only the code that
  loaded it knows where it came from. See `agent-forwarding.md`.

## Several signers

A transaction has **one** fee payer — it is the first required signer — but
any number of required signers, and the request carries one `Signer`.

The page collects every account marked as a signer and allocates a slot for
each, so the *builder* is ready for several. The agent is not: the response
carries a single signature, and signing one means filling the first slot. It
says so rather than declaring the count the page asked for and appending one
signature, which produced a transaction short by whole signatures with the
message glued to the end of the signature region, and reported no error.

Nothing in the built-in instructions marks a second signer today, so this is
latent rather than live — but `SolanaAccount.IsSigner` exists, and the refusal
is what makes it safe to reach for.

## The versioned transaction message

The layout is fixed, shallow, and easy to get wrong in ways that only show up
on chain. `solana/golden_test.go` holds bytes a Solana library produced, and
`TestBuildTransactionMatchesTheLibrary` compares against them byte for byte.
That test is why the builder is right; do not "fix" it to match intuition
without changing the fixture too.

A v0 message, in order:

```
0x80 version | 3 header bytes | compact-u16 numStaticAccounts | account keys
  | blockhash (32 bytes) | compact-u16 numInstructions
  | instructions: progIdIndex, accounts, data each
  | compact-u16 numLookupTables (0)
```

The full transaction is that message with `compact-u16 sigCount` and a 64-byte
signature slot in front of it.

- **The blockhash comes before the instructions.** A message that puts it last
  is rejected as an `invalid transaction discriminator`. It reads oddly and it
  is not a mistake.
- **The header is three separate bytes** - required signatures, readonly
  signed, readonly unsigned - not one packed byte. Reading it as one byte puts
  everything after it out of position and returns a plausible account that is
  not the payer. Both readers got this wrong at different times, and both of
  their tests were green, because each fixture was written beside the reader
  and shared its mistake.
- **An agent key blob is double length-prefixed**: `[4][name][4][key body]`.
  The key body for ed25519 is the 32 raw bytes an account address is made of,
  behind both lengths.
- **A transaction has one signature region.** The signature fills the empty
  slot the build left; it does not follow it.

## Errors worth not getting wrong

- **`skipPreflight` must stay off.** With it on, the node accepts a
  transaction it will never include and hands back a signature that never
  confirms, so the session polls for ninety seconds and reports a problem with
  a signature. The cluster's reason for refusing is in the JSON-RPC error's
  `data`, not in `message` - read it out or the only thing a reader gets is
  "Transaction simulation failed".
- **A transfer to your own address cannot be expressed.** SystemProgram's
  transfer takes a source and a destination and the runtime requires them to
  differ; a transaction to yourself is one account where two are expected and
  the chain answers `MissingAccount`. The fee is still charged. The selftest
  does this deliberately - it is testing shape, not money.
- **`ssh.Marshal(pub)` panics on an ed25519 key.** In `golang.org/x/crypto/ssh`
  it reaches for struct tags by reflection and the ed25519 key type is a defined
  `[]byte`, not a struct:
  `reflect: Field of non-struct type ssh.ed25519PublicKey`. The method on the
  key is the working call: `pub.Marshal()`, which is also what an agent's
  `List()` uses to build each `agent.Key.Blob`. Use the method, and keep
  `ssh.MarshalAuthorizedKey` for the authorized_keys line - that one has its own
  writer and is fine.
- **mainnet-beta.solana.com returns 403 to a browser `fetch`.** CORS. devnet
  does not, which is why the selftest defaults to it even though nothing is
  broadcast. A command-line client is not affected.

## The three implementations

There are three of this logic, deliberately, and they are not redundant:

- `solana/` (Go) - the real one. Builds, signs, sends, confirms.
- `cmd/wssh/static/solana.js` (browser) - the wallet side. Builds the
  transaction where the wallet is and shows it to a person before approving.
- `scripts/sol-tx/` (Deno) - for reading rather than trusting. It logs every
  byte that crosses the agent socket and every RPC call. `deno task test`.

`harness/main.go` is the fourth: a real agent on a real socket, signing with a
key it generates, covering everything up to the browser. Where the browser
takes over, `selftest.html` is the check.

The browser one is the reason a signature can be checked against the
transaction it signs: the response is verified before it is printed, so what
you see is what the browser signed.

Both `sol-tx` implementations print the same verbose plan, from the same
agent listing. A named signer is settled; a key labelled `solana:<addr>` means
the wallet will sign, and which of its accounts that is belongs to the person
at the popup and is not knowable before then; one key and no wallet means that
key; several and no wallet means the agent will refuse. Every key that will not
sign says so, because a marker on the one that will leaves the reader working
out the rest.