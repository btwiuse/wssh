package main

import (
	"errors"
	"fmt"
	"os"

	"charm.land/log/v2"
	"github.com/routercafe/routercafe/cafe"
	"github.com/spf13/cobra"
)

// `cafe tui` is the same program with no SSH in it.
//
// It exists because the interesting parts of this are not the transport: they
// are which account you are, whether you can prove it, and what a balance is
// allowed to do. All three are decided by a session that arrives having proved
// nothing, which is exactly what a local run is. So this is the same model
// built by the same constructor, handed an empty identity and the agent
// already running on this machine.
//
// What you give up is the transport's two conveniences. There is no host key
// to trust and no forwarded agent, because there is nothing to forward - which
// is why a deposit works here without `-A` and would not have worked there
// without one. What you get is a balance, a key and a deposit, on the terminal
// you are already sitting at, with no port open.
func newTUICmd() *cobra.Command {
	var (
		opts     serveOptions
		solPrice = solPriceFlag
	)

	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Run the program here, with no SSH",
		Long: `Run RouterCafe on this terminal, with no server and no SSH.

The same program: the same accounts, the same keys, the same balance, the
same rules about what needs proof. Nothing is listening on a port and
nothing is forwarded, because there is no other end.

It opens with the same screen a connection that proved nothing gets. Pick
one of the ed25519 keys in $SSH_AUTH_SOCK and the agent signs for it, and
you own that account; or type an address and you get to look at it. With
no agent running you can still look, and not change anything.

    ssh-add ~/.ssh/id_ed25519 && cafe tui

--ledger chooses the accounts file, as it does for the server.`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runTUI(&opts, solPrice)
		},
	}

	cmd.Flags().StringVar(&opts.LedgerPath, "ledger", defaultLedgerPath(),
		"the file the accounts live in; $ROUTERCAFE_LEDGER sets this")
	cmd.Flags().StringVar(&opts.Treasury.Address, "treasury", "",
		"where deposits go; required, as it is for the server, or set $ROUTERCAFE_TREASURY")
	cmd.Flags().Float64Var(&solPrice, "sol-price", solPriceFlag,
		"what one SOL buys in USD, which is what a deposit is worth")
	cmd.Flags().BoolVar(&opts.DryRunDeposits, "dry-run-deposits", false,
		"price and show deposits without signing or broadcasting anything")

	return cmd
}

// runTUI does what serve does for the parts that are about accounts, and then
// runs the program rather than listening for somebody to connect.
//
// The treasury checks are shared deliberately rather than restated. A local
// run that skipped the validation would get a different failure later and in a
// worse place, and "works locally, fails on deploy" is not a trade anybody
// wants for a few lines.
func runTUI(opts *serveOptions, solPrice float64) error {
	opts.SolPriceMicroUSD = cafe.MicroUSD(solPrice * float64(cafe.PerMicroUSD))
	opts.Treasury.SolPriceUSD = opts.SolPriceMicroUSD

	if opts.Treasury.Address == "" {
		opts.Treasury.Address = os.Getenv("ROUTERCAFE_TREASURY")
	}
	if opts.Treasury.Address == "" {
		return errors.New("--treasury is required: an account with nowhere to send money " +
			"cannot be funded, or set $ROUTERCAFE_TREASURY")
	}
	if err := cafe.ValidateAddress(opts.Treasury.Address); err != nil {
		return fmt.Errorf("the treasury address: %w", err)
	}

	ledger, err := cafe.OpenLedger(opts.LedgerPath)
	if err != nil {
		return err //nolint:wrapcheck
	}

	// No agent is not an error. The first screen is the one a connection that
	// proved nothing gets, and its address field works with nothing at all -
	// you can look at any account without a key. Refusing to start would take
	// away a thing this can do, and replace it with an error.
	if sock := cafe.LocalAgent(); sock == "" {
		log.Warn("no ssh-agent, so this session can look at an account but not change it",
			"hint", "eval $(ssh-agent -s) && ssh-add ~/.ssh/id_ed25519")
	}

	return cafe.RunLocal(cafe.LocalOptions{ //nolint:wrapcheck
		Ledger:    ledger,
		Treasury:  opts.Treasury,
		Catalogue: cafe.DefaultCatalogue(),
		SockPath:  cafe.LocalAgent(),
		Version:   version,
	})
}
