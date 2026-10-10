package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
	"github.com/btwiuse/wssh/client"
	"github.com/spf13/cobra"
)

func newSolTxCmd() *cobra.Command {
	var (
		sockPath  string
		rpcURL    string
		blockhash string
		label     string
		payer     string
		to        string
		sol       string
		lamports  uint64
		program   string
		accounts  []string
		data      string
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

Examples:
  # Transfer, with the blockhash fetched from an RPC endpoint
  wssh sol-tx transfer --to 5cyy... --sol 1 --rpc https://api.mainnet-beta.solana.com

  # Transfer against a blockhash you already have
  wssh sol-tx transfer --to 5cyy... --lamports 1000000000 --blockhash 9xQe...

  # Any instruction at all
  wssh sol-tx call --program 9xQe... --account 5cyy... --data 3Bxs...`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := buildSolTxRequest(solTxRequest{
				sockPath: sockPath, rpcURL: rpcURL, blockhash: blockhash, label: label,
				to: to, sol: sol, lamports: lamports,
				program: program, accounts: accounts, data: data, payer: payer,
			})
			if err != nil {
				return err //nolint:wrapcheck
			}

			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
			defer cancel()

			// The browser may be waiting on a person to read a wallet
			// prompt, so nothing here should time out in a hurry.
			resp, err := client.SolanaTxAt(ctx, sockPath, req)
			if err != nil {
				return err //nolint:wrapcheck
			}

			// Printing the transaction rather than broadcasting it: this
			// command has no opinion about when or whether it should be
			// sent, and handing back something signed and not sent keeps
			// that decision with the caller.
			fmt.Println(siws.Base58Encode(resp.SignedTransaction))
			return nil
		},
	}

	cmd.Flags().StringVar(&sockPath, "agent", os.Getenv("SSH_AUTH_SOCK"),
		"the agent socket to ask; empty means $SSH_AUTH_SOCK")
	cmd.Flags().StringVar(&rpcURL, "rpc", "https://api.mainnet-beta.solana.com",
		"RPC endpoint to fetch a blockhash from when one was not given")
	cmd.Flags().StringVar(&blockhash, "blockhash", "",
		"blockhash to build against; fetched from --rpc when absent")
	cmd.Flags().StringVar(&payer, "payer", "",
		"base58 account to pay the fee with; defaults to the connected wallet")
	cmd.Flags().StringVar(&label, "label", "",
		"one line of text shown beside the transaction; not trusted")

	cmd.Flags().StringVar(&to, "to", "", "destination account, for transfer")
	cmd.Flags().StringVar(&sol, "sol", "", "amount in SOL, for transfer")
	cmd.Flags().Uint64Var(&lamports, "lamports", 0, "amount in lamports, for transfer")

	cmd.Flags().StringVar(&program, "program", "", "program to call, for call")
	cmd.Flags().StringArrayVar(&accounts, "account", nil, "an account to pass, repeatable")
	cmd.Flags().StringVar(&data, "data", "", "instruction data in base58, for call")

	return cmd
}

type solTxRequest struct {
	sockPath, rpcURL, blockhash, label, payer string
	to, sol                                   string
	lamports                                  uint64
	program                                   string
	accounts                                  []string
	data                                      string
}

func buildSolTxRequest(in solTxRequest) (agentkey.SolanaTxRequest, error) {
	// Naming the payer is what lets the session sign for itself: with no wallet
	// behind it, the account that authenticated the session is the one that can
	// pay, and a transaction whose fee payer it is not will not send.
	req := agentkey.SolanaTxRequest{
		Blockhash: in.blockhash,
		Label:     in.label,
		Payer:     in.payer,
	}

	switch {
	case in.program != "":
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
			parsed, err := client.ParseLamports(in.sol)
			if err != nil {
				return req, err //nolint:wrapcheck
			}
			amount = parsed
		}
		instructions, err := client.NewSolanaTransfer(client.TransferInstruction{
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
		blockhash, err := client.LatestBlockhash(context.Background(), in.rpcURL)
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
