package main

import (
	"context"

	"github.com/routercafe/routercafe/selfupdate"
	"github.com/spf13/cobra"
)

// The releases carry every binary this repository publishes, from one
// repository. Both names are here rather than in the shared package because
// they are what is specific to this binary: the package knows how to replace
// one, and which one is the caller's to say.
const (
	releaseSlug = "routercafe/routercafe"
	binaryName  = "wssh"
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
takes only the one named ` + "`wssh`" + ` and refuses anything else: the library
matches assets on their platform suffix, which all four satisfy.

The version compared against comes from the build. A binary built with plain
` + "`go build`" + ` reports "dev", and that takes the newest release rather than
refusing: it is older than everything and behind nothing, and it is exactly
what somebody running this on a local build has.

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