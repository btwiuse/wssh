# Testing

Read this before adding a test, and before trusting one that passes.

There is no CI config committed. Add one (or document where CI lives) if you
start relying on a particular runner.

The house style is **real things, not fixtures that pretend**: a real agent on
a real socket, real ed25519 keys, real bcrypt, bytes a Solana library actually
produced. `httptest.NewRecorder` is the one stand-in, and only because it
cannot be hijacked.

## What each test file is for

- `wssh_test.go`: HTTP-level tests for path handling. A 501 response after the
  path check is the signal that the handler was reached.
- `auth_test.go`: exercises the handler functions directly against a real
  `ssh.Server` value (no listener). Real ed25519 keys and real bcrypt.
- `client/client_test.go`: spins up a real `wssh.NewServer` on
  `127.0.0.1:0`, dials it with `client.Dial`, asserts on stdout. `t.Setenv`
  swaps `$SHELL` for a fake shell script so the test is independent of the
  developer's login shell.
- `solana/agentsign_test.go`: drives a real agent on a real socket, because the
  thing being tested is a conversation with one.
- `cmd/sol-tx/plan_test.go`: what `--verbose` says it will do, against a real
  agent holding labelled keys. A unix socket path caps at about 104 bytes and
  `t.TempDir` embeds the test name, so these use a short temp directory.
- `cmd/wssh/serve_test.go`: `buildAgent`, over real PEM keys and a real agent
  protocol connection over `net.Pipe`, so the comment is pinned as well as the
  signing.
- `solana/keys_test.go` and `cmd/sol-keys/main_test.go`: the listing, over a
  real agent.

## Fixtures that are pinned, and why

A fixture and a reader agreeing is not evidence. It is the failure mode that
actually happens here, twice: the Deno fee-payer reader skipped one byte of a
versioned message header, its fixture wrote a one-byte header, and both were
green. So wherever a reader and a fixture meet, the fixture is either real
bytes or shared with the other implementation.

- `solana/golden_test.go` holds transaction bytes a Solana library produced, and
  `TestBuildTransactionMatchesTheLibrary` compares a Go-built message against
  them byte for byte. Hand-written serialisation is exactly the thing that is
  right locally and wrong on chain, so the comparison is against real bytes
  rather than against another hand-written copy. Do not "fix" the builder to
  match intuition without changing the fixture too.
- `solana/keys_test.go` pins one ed25519 key's authorized_keys line and its
  address as literals, then decodes the address back and compares bytes. Both
  halves are there because either alone is weak: a base58 alphabet that drifted
  would still round-trip through this tree's own encoder, and the base58 here is
  not the only thing that could have moved. Every listed address is also checked
  to belong to a key that was actually held, which catches a key body being
  read at the wrong offset inside the agent's wire blob - otherwise a very
  plausible wrong address comes out and nothing compares it against anything.
- `solana/fee_test.go` and `scripts/sol-tx/fee_test.ts` pin **the same**
  transaction, one built by the Go builder. Two readers, one transaction: a
  versioned header read short produced an address belonging to nobody, and
  both readers being wrong in the same direction is not something separate
  fixtures would have caught.
- `scripts/sol-tx/identities_test.ts` parses bytes captured off a real OpenSSH
  agent, because the identities message has **no separate key-type field** - the
  algorithm is inside the blob - and a reader expecting `type, blob, comment`
  reads the blob as the type and walks off the end.

The pattern in all of them: pin the literal, and independently check the
property the literal is standing in for. The browser selftest below is the
case where no fixture could have helped, because the thing that was wrong was
in code no fixture touched.

## The browser selftest

`cmd/wssh/static/selftest.html` checks the two things no unit test can: that
the page's builder and the Go reader agree, and that the fee payer `sol-tx`
reports is the key that actually signed. That second check caught a real bug -
the reader had the header one byte out and returned a plausible account that
was not the signer - which every fixture had agreed with, because the fixtures
were written from the same wrong assumption.

It reports the reason through a `CANARY_TX`, because fang prints its error
after the failure and a selftest that gives up before the reason arrives looks
like a hang. See `commands.md` for how to run it.

A Go test cannot cover the browser path because `client/wasm.go` and
`client/wasmauth.go` are `//go:build js && wasm` and are excluded from native
runs. That exclusion is deliberate; do not "fix" it by dropping the tags.

## Both implementations of sol-tx

`scripts/sol-tx` exists to be read rather than trusted, so when one changes a
line of output the other has to change with it. They are checked side by side
against one real agent when the work needs it - which is how the wording of the
verbose plan was caught differing by a single word ("two" against "2"), and
how the Deno key listing was found to disagree with the Go one at all.