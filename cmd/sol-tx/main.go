// sol-tx asks the browser wallet behind a wssh session to sign a Solana
// transaction, and optionally broadcasts it.
//
// It is its own binary rather than a wssh subcommand because nothing it does
// is about carrying SSH. It never opens a connection, never serves a page, and
// never touches the host key: it reads an instruction list, hands it to the
// agent that SSH_AUTH_SOCK points at, and prints or sends what comes back.
// Shipping it inside wssh would mean anyone who wanted a transaction signer
// installed a WebSocket transport to get it.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"charm.land/fang/v2"
	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
	"github.com/btwiuse/wssh/solana"
	"github.com/spf13/cobra"
)

// Set with -ldflags at build time, the same way cmd/wssh does, so the two
// binaries report themselves consistently.
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

	// fang reports the error itself, in its own styled form, so what is left
	// here is the exit status.
	if err := fang.Execute(context.Background(), newSolTxCmd(), options...); err != nil {
		os.Exit(1)
	}
}

func newSolTxCmd() *cobra.Command {
	var (
		sockPath  string
		rpcURL    string
		network   string
		blockhash string
		label     string
		signer    string
		to        string
		sol       string
		lamports  uint64
		program   string
		accounts  []string
		data      string
		memo      string
		send      bool
		verbose   bool
	)

	cmd := &cobra.Command{
		Use:   "sol-tx",
		Short: "Ask the browser's wallet to sign a Solana transaction",
		Long: `Ask the browser's wallet to sign a Solana transaction, through the agent
that a wssh session is given.

The session talks to the browser the same way anything else would: over
SSH_AUTH_SOCK. This command is only the other end of that conversation. It
builds the instructions, hands them over, and prints what comes back, which is
a signed transaction ready to broadcast.

Nothing here is trusted to have come from the wallet unaltered: the response
is checked against the signature it carries before it is printed, so what you
see is what the browser signed.

The transaction itself is built in the browser, where the wallet is, and is
shown to whoever holds it before they approve it. This command never
constructs one.

By default the signed transaction is printed, not sent. Pass --send to
hand it to the RPC endpoint instead, and wait for confirmation. The endpoint
is whichever --rpc points at, falling back to --network when --rpc is empty,
so a transfer built against devnet goes to devnet.

Examples:
  # Transfer on mainnet, signed but not sent
  sol-tx transfer --to 5cyy... --sol 1 --network mainnet

  # Transfer on devnet, signed and broadcast
  sol-tx transfer --to 5cyy... --sol 0.001 --network devnet --send

  # Transfer against a blockhash you already have
  sol-tx transfer --to 5cyy... --lamports 1000000000 --blockhash 9xQe...

  # Custom RPC endpoint, taking precedence over --network
  sol-tx call --program 9xQe... --account 5cyy... --data 3Bxs... --rpc https://my-rpc.example.com

  # Any instruction at all
  sol-tx call --program 9xQe... --account 5cyy... --data 3Bxs...

  # Attach a note and reach a block, without moving anything
  sol-tx memo --memo "deployed" --send

Output:
  The account that paid is read back out of the signed transaction and
  printed to stderr, because it is not always the one that was asked
  for: with --signer empty the wallet chooses, and which wallet chose is
  worth seeing after the fact. With --send the signature goes to stdout
  on its own and the explorer's link to stderr, so
  SIG=$(sol-tx ... --send) is one clean line.`,
		// "transfer" and "call" are read as a leading word rather than
		// subcommands, because both share every flag and a person should
		// not have to say which. The help has always shown them this way, so
		// making them real would only be catching up with the examples.
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,

		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			mode := "transfer"
			if len(args) == 1 && args[0] != "" {
				mode = args[0]
			}
			if mode != "transfer" && mode != "call" && mode != "memo" {
				return fmt.Errorf(
					"unknown instruction %q: this asks for a transfer (--to, --sol or --lamports), "+
						"a memo (--memo), or a call (--program, --account, --data)", mode)
			}

			endpoint := effectiveRPC(rpcURL, network)
			logf(verbose, "[sol-tx] agent=%s", sockPath)
			logf(verbose, "[sol-tx] rpc=%s", endpoint)
			logf(verbose, "[sol-tx] mode=%s", mode)

			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
			defer cancel()

			req, err := buildSolTxRequest(solTxRequest{
				mode:     mode,
				sockPath: sockPath, rpcURL: effectiveRPC(rpcURL, network), blockhash: blockhash, label: label,
				to: to, sol: sol, lamports: lamports,
				program: program, accounts: accounts, data: data, signer: signer,
				memo:    memo,
				verbose: verbose,
			})
			if err != nil {
				return err //nolint:wrapcheck
			}

			// The browser may be waiting on a person to read a wallet
			// prompt, so nothing here should time out in a hurry.
			logf(verbose, "[sol-tx] asking agent")
			resp, err := solana.Ask(ctx, sockPath, req)
			if err != nil {
				return err //nolint:wrapcheck
			}

			// Which account actually paid, read out of the bytes that were
			// signed rather than out of the request. Those differ whenever
			// --signer was empty and the wallet chose, and which wallet chose
			// is the thing worth being able to see after the fact.
			if resp.SignedTransaction != nil {
				if who, ferr := solana.FeePayer(resp.SignedTransaction); ferr == nil {
					fmt.Fprintf(os.Stderr, "fee payer: %s\n", who)
				}
			}

			// Printing the transaction rather than broadcasting it: this
			// command has no opinion about when or whether it should be
			// sent, and handing back something signed and not sent keeps
			// that decision with the caller. --send reverses that and posts
			// to the RPC endpoint, so the wallet signs once and the money
			// moves once, instead of being shuffled between two commands.
			if send {
				logf(verbose, "[sol-tx] sending via RPC")
				sig, err := solana.SendTransaction(ctx, endpoint, resp.SignedTransaction)
				if err != nil {
					return err //nolint:wrapcheck
				}
				// The signature goes to stdout on its own so that
				// `SIG=$(sol-tx ... --send)` yields exactly one line.
				// Everything meant for a person reading the terminal goes to
				// stderr, including the link to look the transaction up in.
				fmt.Println(sig)
				logf(verbose, "[rpc] POST %s  getSignatureStatuses", endpoint)
				if err := solana.ConfirmTransaction(ctx, endpoint, sig); err != nil {
					return err //nolint:wrapcheck
				}
				// Only after the confirmation lands: a signature on its own says
				// the cluster accepted the bytes, not that the instructions ran,
				// and a link to a failed transaction is a worse thing to print
				// than no link at all.
				if url := explorerTxURL(endpoint, sig); url != "" {
					fmt.Fprintln(os.Stderr, url)
				}
				return nil
			}
			fmt.Println(siws.Base58Encode(resp.SignedTransaction))
			return nil
		},
	}

	cmd.Flags().StringVar(&sockPath, "agent", os.Getenv("SSH_AUTH_SOCK"),
		"the agent socket to ask; empty means $SSH_AUTH_SOCK")
	cmd.Flags().StringVar(&rpcURL, "rpc", os.Getenv("WSSH_SOLANA_RPC"),
		"RPC endpoint; takes precedence over --network when both are set, "+
			"or empty to fall through to --network's default. "+
			"$WSSH_SOLANA_RPC sets this when the flag is empty")
	cmd.Flags().StringVar(&network, "network", "mainnet",
		"named cluster to use when --rpc is empty: mainnet, testnet, devnet, or a custom URL")
	cmd.Flags().StringVar(&blockhash, "blockhash", "",
		"blockhash to build against; fetched from --rpc when absent")
	cmd.Flags().StringVar(&signer, "signer", "",
		"base58 account whose key signs, and therefore pays the fee; "+
			"defaults to the connected wallet, or with no wallet to the one key in the agent")
	cmd.Flags().StringVar(&label, "label", "",
		"one line of text shown beside the transaction; not trusted")

	cmd.Flags().StringVar(&to, "to", "", "destination account, for transfer")
	cmd.Flags().StringVar(&sol, "sol", "", "amount in SOL, for transfer")
	cmd.Flags().Uint64Var(&lamports, "lamports", 0, "amount in lamports, for transfer")

	cmd.Flags().StringVar(&program, "program", "", "program to call, for call")
	cmd.Flags().StringArrayVar(&accounts, "account", nil, "an account to pass, repeatable")
	cmd.Flags().StringVar(&data, "data", "", "instruction data in base58, for call")
	cmd.Flags().StringVar(&memo, "memo", "",
		"text to attach to the transaction, for memo; costs one signature fee and moves nothing")
	cmd.Flags().BoolVar(&verbose, "verbose", false,
		"log every step on stderr: which agent, which endpoint, which RPC call")
	cmd.Flags().BoolVar(&send, "send", false,
		"broadcast the signed transaction through --rpc and wait for confirmation, "+
			"instead of printing it")

	return cmd
}

type solTxRequest struct {
	mode                                                string
	sockPath, rpcURL, network, blockhash, label, signer string
	to, sol, memo                                       string
	lamports                                            uint64
	program                                             string
	accounts                                            []string
	data                                                string
	send                                                bool
	verbose                                             bool
}

// resolveNetwork turns the friendly --network name into an RPC URL. The
// empty string and the named clusters all have a default; anything else
// is treated as a custom URL, which is what makes the same flag useful
// for a private cluster or a paid provider.
//
// The named values use the same endpoints the official Solana CLI does;
// flipping --network changes both the blockhash source and the
// destination for --send, which is what makes one switch cover both.
func resolveNetwork(name string) string {
	return solana.ResolveNetwork(name)
}

// effectiveRPC picks the URL the rest of the command will use. --rpc wins
// when set, --network fills in when it is empty, and the call site never
// has to think about which was passed: one source of truth keeps --send
// and the blockhash fetch pointing at the same endpoint.
// logf writes one step to stderr when --verbose is on. Everything a person
// reads goes to stderr rather than stdout, so that stdout stays the
// signature alone and `SIG=$(sol-tx ... --send)` is one clean line.
func logf(verbose bool, format string, args ...any) {
	if !verbose {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func effectiveRPC(rpcURL, network string) string {
	if strings.TrimSpace(rpcURL) != "" {
		return rpcURL
	}
	return resolveNetwork(network)
}

// explorerTxURL is the block explorer's link to a confirmed transaction, or
// "" when the cluster behind the endpoint cannot be named.
//
// Only the public Solana endpoints are recognised. Someone's own RPC carries no
// cluster in its URL, and calling that mainnet would print a link to a page
// that says the transaction does not exist, which is worse than printing no
// link at all.
//
// solscan picks the cluster with a query parameter rather than a path, so
// mainnet is the bare URL and the other two carry ?cluster=.
func explorerTxURL(endpoint, signature string) string {
	var query string
	switch hostOfURL(endpoint) {
	case "api.mainnet-beta.solana.com":
		query = ""
	case "api.devnet.solana.com":
		query = "?cluster=devnet"
	case "api.testnet.solana.com":
		query = "?cluster=testnet"
	default:
		return ""
	}
	return "https://solscan.io/tx/" + signature + query
}

func hostOfURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func buildSolTxRequest(in solTxRequest) (agentkey.SolanaTxRequest, error) {
	// Naming the signer is what lets the session sign for itself: with no
	// wallet behind it, the account that authenticated the session is the one
	// that can sign, and a transaction whose fee payer is anybody else will
	// not send - Solana requires the fee payer to sign.
	req := agentkey.SolanaTxRequest{
		Blockhash: in.blockhash,
		Label:     in.label,
		Signer:    in.signer,
	}

	switch {
	case in.mode == "memo":
		// A note, not a transfer. The instruction carries no accounts at
		// all, which is the one shape both the agent and the wallet have
		// to be told to expect.
		instructions, err := solana.NewMemo(in.memo)
		if err != nil {
			return req, err //nolint:wrapcheck
		}
		req.Instructions = instructions

	case in.mode == "call":
		// A raw call. The account list and data are passed through as given:
		// deciding what they mean is the browser's job, and it is the one that
		// shows them to a person.
		if len(in.accounts) == 0 {
			return req, errUsage("a call needs at least one account")
		}
		if in.data == "" {
			return req, errUsage("a call needs some data")
		}
		accounts := make([]agentkey.SolanaAccount, 0, len(in.accounts))
		for _, address := range in.accounts {
			// A raw call cannot know what role an account plays, so it is
			// passed as writable and non-signing and the browser shows it
			// as such. Anything needing a signer is not something this
			// command can express on the caller's behalf.
			accounts = append(accounts, agentkey.SolanaAccount{
				Address:    address,
				IsSigner:   false,
				IsWritable: true,
			})
		}
		req.Instructions = []agentkey.SolanaInstruction{{
			ProgramID:  in.program,
			Accounts:   accounts,
			DataBase58: in.data,
		}}

	case in.to != "" || in.sol != "" || in.lamports != 0:
		amount := in.lamports
		if amount == 0 {
			if in.sol == "" {
				return req, errUsage("a transfer needs an amount: --sol or --lamports")
			}
			parsed, err := solana.ParseLamports(in.sol)
			if err != nil {
				return req, err //nolint:wrapcheck
			}
			amount = parsed
		}
		instructions, err := solana.NewTransfer(solana.TransferInstruction{
			Lamports: amount,
			To:       in.to,
		})
		if err != nil {
			return req, err //nolint:wrapcheck
		}
		req.Instructions = instructions

	default:
		return req, errUsage("nothing to do: give a transfer (--to) or a call (--program)")
	}

	if req.Blockhash == "" {
		logf(in.verbose, "[sol-tx] fetching blockhash")
		logf(in.verbose, "[rpc] POST %s  getLatestBlockhash", in.rpcURL)
		blockhash, err := solana.LatestBlockhash(context.Background(), in.rpcURL)
		if err != nil {
			return req, err //nolint:wrapcheck
		}
		req.Blockhash = blockhash
	}
	return req, nil
}

// errUsage is a plain message rather than a wrapped error, because it is about
// what was asked for rather than about anything that went wrong.
func errUsage(msg string) error {
	return errors.New(msg)
}
