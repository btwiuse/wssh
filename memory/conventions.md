# Conventions

Read this before writing code that should look like it belongs here.

## Naming and style

- Packages are short and lowercase: `wssh`, `auth`, `client`, `shell`.
- Comments document intent and the non-obvious consequence, not what the
  next line of code does. Many comments explain why something is the way
  it is - keep that style.
- Errors are wrapped with `fmt.Errorf("...: %w", err)`. Library packages
  return wrapped errors; `cmd/wssh` mostly returns them unwrapped with
  `//nolint:wrapcheck`.
- Subcommand constructors return `*cobra.Command` and are named `newXxxCmd`.
  Shared flag wiring goes through helpers in `serve.go`.
- `Options` structs are configured by the caller, then handed to a single
  `New*` constructor; this is consistent across packages.

## Errors and fail-fast branches

`serve` returns the first error from `auth.Options()` or
`wssh.NewServer()` without wrapping; both branches use `//nolint:wrapcheck`.
Match that pattern when adding a similar fail-fast branch.

An error message that a person will read should say what would let them
continue, not just what went wrong. "SSH_AUTH_SOCK is not set, so nothing here
can ask for a signature" is worth four more words than "no agent". The rule
that falls out of it: when a command refuses, name the thing that is missing
or the thing to pass.

## Deliberate strangeness

Some of this code looks wrong and is not. Before "fixing" anything here,
check `gotchas.md` - it is the list of things that behave oddly on purpose,
and each entry says what would break if it were made to look reasonable.

The same applies to the notes in `layout.md` and `agent-forwarding.md`. They
are not commentary on old code; each one records a consequence that the
current design depends on.

## Where notes go

`AGENTS.md` is an index and nothing else: it says what the project is and
links to the topic files under `memory/`. A note that earns its place goes in
one of those files, or in a new `memory/<topic>.md` with one added to the
index. It does not go in `AGENTS.md`, because every line there is read on
every request whether or not it is relevant.

Each memory file opens with a "Read this when" line, so a reader can tell in
one line whether to keep going.