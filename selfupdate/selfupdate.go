// Package selfupdate replaces a running binary with the newest release of it.
//
// Every binary this repository publishes upgrades itself through here, and
// that is not tidiness for its own sake. Each of the rules below exists
// because leaving it out broke an upgrade once:
//
//   - The asset is matched on a pattern anchored at both ends. The library's
//     own matching is on the platform suffix alone, and every binary in a
//     release ends with that suffix, so it would hand one binary the archive
//     of another and write it over the running executable.
//   - The archive is unpacked by the name of the asset rather than by its
//     extension alone. Handed a name with no archive suffix the library
//     decides the download is not compressed and writes the file over the
//     executable whole, tarball and all, and reports success.
//   - A binary with no version takes the newest release rather than refusing.
//     "dev" is what a build without the version stamped in reports, it is not
//     a version the library can parse, and it is exactly what somebody
//     running this on a local build has.
//   - The running executable has to be called what the archive holds, because
//     the library finds the entry to extract from the name of the file it is
//     overwriting.
//
// A second copy of any of these is a second thing to get wrong, which is why
// there is one and both binaries call it.
package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	goselfupdate "github.com/creativeprojects/go-selfupdate"
)

// Options is what to upgrade, and to what.
type Options struct {
	// Slug is owner/repo of the repository the releases are cut from.
	Slug string

	// Binary is the name of the executable inside a release archive, and
	// therefore the name the running one has to have.
	Binary string

	// Version is what this binary was built at. Empty and "dev" mean the
	// build carries none, and both take the newest release.
	Version string
}

// archiveExtensions are the forms a release asset can take. A checksum file
// sits next to an archive and starts with the same prefix, so a prefix on its
// own is not enough to say an asset is the binary.
var archiveExtensions = []string{".tar.gz", ".tgz", ".gz", ".zip", ".xz", ".bz2"}

// AssetPattern is the asset a given binary can be replaced with: one of ours,
// for this platform, in a form that unpacks to a binary.
//
// Anchored at both ends on purpose. A prefix match alone would take the first
// asset of that binary for any platform, and a suffix match alone would take
// the first asset of any binary for this platform.
func AssetPattern(binary string) string {
	return fmt.Sprintf(`^%s.*_%s_%s(\.tar\.gz|\.zip)$`,
		regexp.QuoteMeta(binary+"_"), runtime.GOOS, runtime.GOARCH)
}

// IsBinaryAsset reports whether a release asset is the named binary's archive.
//
// Both halves matter and are checked here rather than because something
// upstream happened to have filtered first: the prefix says which binary this
// is, and the extension says it is the binary rather than its checksum.
func IsBinaryAsset(name, binary string) bool {
	// An empty name would otherwise leave just the separator to match on, and
	// anything starting with one would pass. The callers pass a constant, so
	// this is not reachable today; it is here because this is the last check
	// before an archive is written over a running executable, and a guard at
	// that point costs one comparison.
	if binary == "" {
		return false
	}
	if !strings.HasPrefix(name, binary+"_") {
		return false
	}
	for _, ext := range archiveExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// IsUnversioned reports whether a build carries no version to compare with.
//
// Only the two a build in this repository actually produces: the empty string
// and the "dev" it defaults to. Anything else is taken at its word and handed
// to the comparison, which is the point - a version this repository does not
// know how to stamp is not a reason to refuse to upgrade.
func IsUnversioned(version string) bool {
	return version == "" || version == "dev"
}

// CanReplaceItself reports whether this executable can find its replacement.
//
// The name has to match what the archive holds, because the library reads the
// entry it wants out of the archive from the name of the file it is
// overwriting. The .exe form is the Windows one and is not built here, but
// refusing a renamed binary on Windows would be a rule this could not justify.
func CanReplaceItself(exe, binary string) bool {
	name := filepath.Base(exe)
	return name == binary || name == binary+".exe"
}

// Run replaces the running binary with the newest release of it.
func Run(ctx context.Context, opts Options) error {
	// The filter is not an optimisation. Without one the library matches on
	// the platform suffix alone and takes the first asset that fits, and
	// every binary in a release ends with that suffix. The filter replaces
	// that matching rather than adding to it, so it has to carry the platform
	// itself.
	updater, err := goselfupdate.NewUpdater(goselfupdate.Config{
		Filters: []string{AssetPattern(opts.Binary)},
	})
	if err != nil {
		return fmt.Errorf("could not prepare the updater: %w", err)
	}

	latest, found, err := updater.DetectLatest(ctx, goselfupdate.ParseSlug(opts.Slug))
	if err != nil {
		return fmt.Errorf("could not reach %s to find the latest release: %w", opts.Slug, err)
	}
	if !found {
		// Said with the platform in it, because the usual reason is that the
		// release was cut without an asset for this one, and "not found" on
		// its own sends people looking at the wrong end of it.
		return fmt.Errorf(
			"no release of %s has an asset for %s/%s; "+
				"a release has to publish one for the upgrade to find it",
			opts.Slug, runtime.GOOS, runtime.GOARCH)
	}

	// The comparison is skipped when this binary does not know its version.
	// "dev" is what a build without the version ldflags reports, and it is not
	// a version: the library parses it and panics. It is also exactly what
	// somebody running this on a local build has - nothing published is
	// behind it - so the answer is the newest release rather than a refusal.
	if !IsUnversioned(opts.Version) && latest.LessOrEqual(opts.Version) {
		return fmt.Errorf("%s is already the latest release", opts.Version)
	}

	if !IsBinaryAsset(latest.AssetName, opts.Binary) {
		return fmt.Errorf(
			"release %s offered %q, which is not the %s binary; "+
				"an upgrade will not replace %s with something else",
			latest.Version(), latest.AssetName, opts.Binary, opts.Binary)
	}

	exe, err := os.Executable()
	if err != nil {
		return errors.New("could not find the running executable, so there is nothing to replace")
	}
	if !CanReplaceItself(exe, opts.Binary) {
		// Said here because the alternative is a tar error naming an archive
		// this command never had trouble with before, and a renamed binary is
		// an ordinary thing to have.
		return fmt.Errorf(
			"this executable is called %s and a release holds %s; "+
				"the file to replace is found by the name of the file being "+
				"overwritten, so rename it or take the asset by hand",
			filepath.Base(exe), opts.Binary)
	}

	// The asset name, because the library reads its extension off this to
	// decide how to unpack it. Anything without an archive suffix takes the
	// "this is not compressed" path and the downloaded file is written over
	// the executable whole.
	if err := goselfupdate.UpdateTo(ctx, latest.AssetURL, latest.AssetName, exe); err != nil {
		return fmt.Errorf("could not replace the binary at %s from %s: %w", exe, latest.AssetName, err)
	}
	fmt.Fprintf(os.Stderr, "upgraded %s to %s\n", opts.Version, latest.Version())
	return nil
}
