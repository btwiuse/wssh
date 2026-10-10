// sol-keys lists the keys an ssh-agent holds and the Solana account each one
// names.
//
// It is the ssh-add -L of this repository, with the second column filled in:
// the authorized_keys line is exactly the line ssh-add would print, and under
// it is the base58 address that key is on Solana as. The address is not looked
// up anywhere - a Solana account *is* an ed25519 public key, so for an
// ed25519 key the two are the same 32 bytes written twice, and for any other
// key there is no address and this says so.
//
// It is its own binary rather than a wssh subcommand for the reason sol-tx is:
// nothing here is about carrying SSH. It reads a socket, prints what came
// back, and never touches a host key.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"charm.land/fang/v2"
	"github.com/btwiuse/wssh/solana"
	"github.com/spf13/cobra"
)

// Set with -ldflags at build time, the same way cmd/wssh and cmd/sol-tx do, so
// every binary out of this tree reports itself the same way.
var (
	version = "dev"
	commit  = ""
)

func main() {
	options := []fang.Option{
		fang.WithVersion(version),
	}
	if commit != "" {
		options = append(options, fang.WithCommit(commit))
	}

	// fang prints the error itself, in its own styled form, so what is left
	// here is the exit status.
	if err := fang.Execute(context.Background(), newSolKeysCmd(), options...); err != nil {
		os.Exit(1)
	}
}

func newSolKeysCmd() *cobra.Command {
	var (
		sockPath  string
		addresses bool
		asJSON    bool
	)

	cmd := &cobra.Command{
		Use:   "sol-keys",
		Short: "List the keys an ssh-agent holds, and the Solana address each names",
		Long: `List the keys an ssh-agent holds, and the Solana address each one is.

Every line is the line ssh-add -L prints, followed by the account that key
signs for on Solana. The account is not derived from the key and is not
looked up: a Solana address is an ed25519 public key written in base58, so an
ed25519 key already is an account and the two are the same 32 bytes. That is
why the address here is the string sol-tx wants as --signer for this key to sign
a fee.

A key that is not ed25519 names no account, and this says which kind it is
rather than leaving a blank: an RSA key in an agent is an SSH key and nothing
more.

Examples:
  # Everything the agent in this session holds
  sol-keys

  # Against another agent
  sol-keys --agent /tmp/ssh-Ab3dEf/agent.4711

  # Just the addresses, one per line, for a script
  sol-keys --addresses

  # The whole listing as a document, for jq or for anything else
  sol-keys --json
  sol-keys --json | jq -r '.keys[] | select(.address != "") | .address'

Output:
  The key lines go to stdout, since they are the thing being asked for and
  they are what a paste wants. --addresses prints nothing but addresses, one
  per line, and counts what it left out on stderr. --json prints one object
  and nothing else on stdout; every key is an entry whether or not it names an
  account, so a consumer never has to infer an answer from a missing field.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,

		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Refused before the agent is touched. These are two
			// different documents and picking one silently would hand
			// back something the caller did not ask to parse. The
			// message starts with a word rather than a flag because
			// fang capitalises the first one, and "--Addresses" is
			// not a flag anybody can type.
			if addresses && asJSON {
				return errors.New(
					"two output formats were asked for: --addresses is one " +
						"address per line and --json is the whole listing; pick one")
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			keys, err := solana.ListAgentKeysAt(ctx, sockPath)
			if err != nil {
				return err //nolint:wrapcheck
			}
			if sockPath == "" {
				sockPath = os.Getenv("SSH_AUTH_SOCK")
			}

			// cobra defaults both of these to the process streams, so
			// nothing changes for a person running it; going through the
			// command is what lets a test see the output at all.
			out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
			switch {
			case asJSON:
				return writeJSON(out, keys, sockPath)
			case addresses:
				printAddresses(out, errOut, keys)
				return nil
			default:
				printKeys(out, keys, sockPath)
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&sockPath, "agent", os.Getenv("SSH_AUTH_SOCK"),
		"the agent socket to ask; empty means $SSH_AUTH_SOCK")
	cmd.Flags().BoolVar(&addresses, "addresses", false,
		"print only the account addresses, one per line, and say nothing about keys that have none")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"print the listing as one JSON object on stdout instead of the human listing")

	return cmd
}

// keyReport is one key as a consumer sees it.
//
// Every field is always present, empty string included. A consumer should not
// have to distinguish "this key names no account" from "this version of the
// tool does not say", and omitting the field would make those two the same
// thing in a typed client and the same null in jq.
//
// comment is the agent's own, kept verbatim: what a line says about a key's
// origin is something an agent claimed, not something this tool decided.
type keyReport struct {
	Type          string `json:"type"`
	AuthorizedKey string `json:"authorizedKey"`
	Comment       string `json:"comment"`
	Address       string `json:"address"`
	Reason        string `json:"reason"`
}

// listing is the whole document: which agent was asked, and everything it
// holds. The agent path is in there because two agents are ordinary - a
// workstation one and the one forwarded into a session - and a listing with no
// record of its source cannot say which it was.
type listing struct {
	Agent string      `json:"agent"`
	Keys  []keyReport `json:"keys"`
}

// writeJSON prints the listing as one JSON object.
//
// keys is built non-nil so an agent holding nothing comes back as "keys": []
// rather than "keys": null. Both parse; only one of them is something a
// consumer can loop over without a nil check.
func writeJSON(out io.Writer, keys []solana.AgentKey, sockPath string) error {
	report := listing{
		Agent: sockPath,
		Keys:  make([]keyReport, 0, len(keys)),
	}
	for _, key := range keys {
		report.Keys = append(report.Keys, keyReport{
			Type:          key.Type(),
			AuthorizedKey: key.AuthorizedKey(),
			Comment:       key.Comment,
			Address:       key.Address,
			Reason:        key.Reason,
		})
	}

	// Indented, because the person most likely to run this once is a person
	// reading the output, and the person most likely to run it twice is
	// piping it into jq, which does not care either way.
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the listing: %w", err)
	}
	_, err = fmt.Fprintln(out, string(encoded))
	return err //nolint:wrapcheck
}

// printKeys writes the listing: the same lines ssh-add prints, with the
// account each key names underneath.
//
// The header says which agent was asked. Two agents are ordinary - a
// workstation one and the one forwarded into a session - and the difference
// between them is the whole question a person usually has, so it is worth one
// line rather than a footnote.
func printKeys(out io.Writer, keys []solana.AgentKey, sockPath string) {
	if len(keys) == 0 {
		fmt.Fprintf(out, "no keys in the agent at %s\n", sockPath)
		return
	}
	// "1 keys" is the kind of thing that costs a command its credibility
	// on the one line everybody reads, so the plural is worth the branch.
	plural := "keys"
	if len(keys) == 1 {
		plural = "key"
	}
	fmt.Fprintf(out, "%d %s in the agent at %s\n\n", len(keys), plural, sockPath)
	for _, key := range keys {
		line := key.AuthorizedKey()
		if line == "" {
			// Nothing to paste and no address to name: the only thing
			// worth saying is why the key did not make it into the list.
			fmt.Fprintf(out, "(a key this could not read: %s)\n\n", key.Reason)
			continue
		}
		fmt.Fprintln(out, line)
		if key.Address != "" {
			fmt.Fprintf(out, "  solana  %s\n", key.Address)
		} else {
			fmt.Fprintf(out, "  solana  (none: %s)\n", key.Reason)
		}
	}
}

// printAddresses writes only the addresses, one per line.
//
// Keys with no account are left out entirely rather than printed as an empty
// line, so the output is something a script can feed straight into a command
// that wants an address. The count that was dropped goes to the second writer
// rather than to out, because a script should not have to parse a warning off
// stdout to count its own results.
func printAddresses(out, errOut io.Writer, keys []solana.AgentKey) {
	skipped := 0
	for _, key := range keys {
		if key.Address == "" {
			skipped++
			continue
		}
		fmt.Fprintln(out, key.Address)
	}
	if skipped > 0 {
		fmt.Fprintf(errOut, "%d of %d keys name no account and were left out\n", skipped, len(keys))
	}
}
