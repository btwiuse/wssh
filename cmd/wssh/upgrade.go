package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/creativeprojects/go-selfupdate"
	"github.com/spf13/cobra"
)

// releaseSlug is where the binaries are published. go-selfupdate reads the
// release assets from here, so the name has to be the repository the releases
// are cut from and nothing else.
const releaseSlug = "btwiuse/wssh"

// binaryName is the name of the executable inside a release archive, and
// therefore the name this binary has to have for it to be able to replace
// itself.
//
// go-selfupdate takes the entry it wants out of the archive from the name of
// the file it is overwriting, so an executable called something else cannot
// find its own replacement in an archive that holds `wssh`. That is checked
// below rather than left to fail as a truncated tar.
const binaryName = "wssh"

// assetPrefix is the name every wssh asset starts with.
//
// This exists because the same release also carries sol-tx and sol-keys, and
// go-selfupdate picks the **first** asset whose name ends with
// `<os>_<arch>.tar.gz`. All three do. Without this check a wssh upgrade can
// download a sol-keys archive and write it over the wssh binary, and nothing
// about that looks wrong until wssh stops starting.
const assetPrefix = "wssh_"

func newUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade",
		Short: "Replace this binary with the latest release",
		Long: `Replace this binary with the latest release.

Asks GitHub for the newest published release, compares it with the version
this binary was built at, and downloads the asset for this platform over the
running executable if there is anything newer.

The version compared against comes from the build. A binary built with plain
` + "`go build`" + ` reports "dev", and this refuses rather than guessing: "dev"
is older than every release and older than none, and downloading something
over a binary someone built on purpose is not what they asked for. Build with
the version ldflags - see the Makefile - and this compares properly.

Nothing is replaced until the download has finished and the new binary is in
place, so a failed upgrade leaves the old one running.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return upgrade(context.Background(), version)
		},
	}
}

// archiveExtensions are the forms a release asset can take. A checksum file
// next to an archive starts with the same prefix, so a prefix on its own is
// not enough to say an asset is the binary.
var archiveExtensions = []string{".tar.gz", ".tgz", ".gz", ".zip", ".xz", ".bz2"}

// isWsshAsset reports whether a release asset is a wssh binary archive.
//
// Both halves matter, and on their own rather than because something upstream
// happens to have filtered first: the prefix says which of the three binaries
// this is, and the extension says it is the binary rather than its checksum.
// assetPattern is the asset this binary can be replaced with: one of ours, for
// this platform, in a form that unpacks to a binary.
//
// Anchored at both ends on purpose. A prefix match alone would take the first
// wssh asset for any platform, and a suffix match alone would take the first
// asset of any binary for this platform - which is how the wrong one was being
// chosen.
func assetPattern() string {
	return fmt.Sprintf(`^%s.*_%s_%s(\.tar\.gz|\.zip)$`,
		regexp.QuoteMeta(assetPrefix), runtime.GOOS, runtime.GOARCH)
}

func isWsshAsset(name string) bool {
	if !strings.HasPrefix(name, assetPrefix) {
		return false
	}
	for _, ext := range archiveExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// canReplaceItself reports whether this executable can find its replacement.
//
// The name has to match what the archive holds, because the library reads the
// entry it wants out of the archive from the name of the file it is
// overwriting. The .exe form is the Windows one and is not built here, but
// refusing a renamed binary on Windows would be a rule this could not justify.
func canReplaceItself(exe string) bool {
	name := filepath.Base(exe)
	return name == binaryName || name == binaryName+".exe"
}

func upgrade(ctx context.Context, currentVersion string) error {
	// Before the network, not after it. A binary that does not know its own
	// version has nothing to compare a release against, so asking GitHub is a
	// request whose answer cannot be used. It also turns a local build into a
	// network failure, which reads as somebody else's problem.
	if currentVersion == "" || currentVersion == "dev" {
		return fmt.Errorf(
			"this binary reports no version, so there is nothing to compare against; " +
				"build with -X main.version=<version>, or run the published asset")
	}

	// The filter is not an optimisation. Without one, go-selfupdate matches on
	// the platform suffix alone and takes the first asset that fits - and a
	// release carries three binaries whose names all end in
	// `<os>_<arch>.tar.gz`. On the first release published here it picked
	// sol-keys, which is why the check below exists at all. A filter replaces
	// the suffix matching rather than adding to it, so it has to carry the
	// platform itself.
	updater, err := selfupdate.NewUpdater(selfupdate.Config{
		Filters: []string{assetPattern()},
	})
	if err != nil {
		return fmt.Errorf("could not prepare the updater: %w", err)
	}

	latest, found, err := updater.DetectLatest(ctx, selfupdate.ParseSlug(releaseSlug))
	if err != nil {
		return fmt.Errorf("could not reach %s to find the latest release: %w", releaseSlug, err)
	}
	if !found {
		// Said with the platform in it, because the usual reason is that the
		// release was cut without an asset for this one, and "not found"
		// on its own sends people looking at the wrong end of it.
		return fmt.Errorf(
			"no release of %s has an asset for %s/%s; "+
				"a release has to publish one for the upgrade to find it",
			releaseSlug, runtime.GOOS, runtime.GOARCH)
	}

	if latest.LessOrEqual(currentVersion) {
		return fmt.Errorf("%s is already the latest release", currentVersion)
	}

	// The release carries all three binaries, and go-selfupdate matched this
	// asset only on its platform suffix - which all three satisfy. Refusing
	// here is the difference between an upgrade and an accident.
	if !isWsshAsset(latest.AssetName) {
		return fmt.Errorf(
			"release %s offered %q, which is not the wssh binary; "+
				"an upgrade will not replace wssh with something else",
			latest.Version(), latest.AssetName)
	}

	exe, err := os.Executable()
	if err != nil {
		return errors.New("could not find the running executable, so there is nothing to replace")
	}
	if !canReplaceItself(exe) {
		// Said here because the alternative is a tar error naming an
		// archive this command never had trouble with before, and a
		// renamed binary is an ordinary thing to have.
		return fmt.Errorf(
			"this executable is called %s and a release holds %s; "+
				"go-selfupdate finds the file to replace by the name of the "+
				"file it is overwriting, so rename it or take the asset by hand",
			filepath.Base(exe), binaryName)
	}
	// The asset name, because the library reads its extension off this to
	// decide how to unpack it. Anything without an archive suffix - "wssh",
	// say - takes the "this is not compressed" path and the downloaded file
	// is written over the executable whole.
	if err := selfupdate.UpdateTo(ctx, latest.AssetURL, latest.AssetName, exe); err != nil {
		return fmt.Errorf("could not replace the binary at %s from %s: %w", exe, latest.AssetName, err)
	}
	fmt.Fprintf(os.Stderr, "upgraded %s to %s\n", currentVersion, latest.Version())
	return nil
}
