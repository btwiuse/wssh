package main

import (
	"context"

	"github.com/btwiuse/wssh/selfupdate"
	"github.com/spf13/cobra"
)

// The releases carry every binary this repository publishes, from one
// repository. See the wssh counterpart: the rules are shared, and only these
// two names are this binary's to say.
const (
	releaseSlug = "btwiuse/wssh"
	binaryName  = "cafe"
)

func newUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade",
		Short: "Replace this binary with the latest release",
		Long: `Replace this binary with the latest release.

Asks GitHub for the newest published release, compares it with the version
this binary was built at, and downloads the asset for this platform over the
running executable if there is anything newer.

A release carries wssh, cafe, sol-tx and sol-keys, one archive each. This
takes only the one named ` + "`cafe`" + ` and refuses anything else: the library
matches assets on their platform suffix, which all four satisfy, and an
upgrade that wrote the wrong one over this binary would leave a server that
answers the wrong requests.

A ledger is a file, not a release artefact, so an upgrade never touches one.
The new binary reads the same file the old one did.

The version compared against comes from the build. A binary built with plain
` + "`go build`" + ` reports "dev", and that takes the newest release rather than
refusing.

Nothing is replaced until the download has finished and the new binary is in
place, so a failed upgrade leaves the old one running.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return selfupdate.Run(context.Background(), selfupdate.Options{
				Slug:    releaseSlug,
				Binary:  binaryName,
				Version: version,
			})
		},
	}
}
