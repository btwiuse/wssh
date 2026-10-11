package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A build without the version ldflags reports "dev", which is not a version.
// The library would parse it and panic on it, so the comparison has to be
// skipped - and skipping it means the newest release, not a refusal. Someone
// running upgrade on a local build is asking for exactly that.
func TestABinaryWithNoVersionTakesTheNewestRelease(t *testing.T) {
	for _, current := range []string{"", "dev"} {
		t.Run("version="+current, func(t *testing.T) {
			if !isUnversioned(current) {
				t.Errorf("%q should count as carrying no version", current)
			}
		})
	}
	// And a real version is not treated as unknown, which is what lets the
	// command say "already the latest" instead of downloading over itself.
	for _, current := range []string{"0.0.2", "v0.0.2", "1.0.0-beta.1"} {
		if isUnversioned(current) {
			t.Errorf("%q is a version and must be compared, not skipped", current)
		}
	}
}

// The slug is the whole mechanism: go-selfupdate reads the releases from it,
// and a wrong one reports "no releases" rather than "wrong repository", which
// is a miserable thing to debug.
func TestTheReleaseSlugIsThisRepository(t *testing.T) {
	if releaseSlug != "btwiuse/wssh" {
		t.Errorf("release slug is %q, want the repository the releases are cut from", releaseSlug)
	}
	owner, repo, ok := strings.Cut(releaseSlug, "/")
	if !ok || owner == "" || repo == "" {
		t.Fatalf("release slug %q is not owner/repo, which is what selfupdate parses", releaseSlug)
	}
}

// The asset a release offers is chosen on its platform suffix alone, and a
// release carries three binaries whose names all end in that suffix. This is
// the check that stops wssh being replaced by sol-keys - and it has to stand on
// its own rather than rely on something upstream having filtered first, because
// a checksum file carries the same prefix as the archive it sits next to.
func TestOnlyTheWsshBinaryIsAccepted(t *testing.T) {
	cases := map[string]bool{
		"wssh_0.0.1_darwin_arm64.tar.gz":        true,
		"wssh_0.0.1_linux_amd64.tar.gz":         true,
		"wssh_0.0.1_windows_amd64.zip":          true,
		"sol-tx_0.0.1_darwin_arm64.tar.gz":      false,
		"sol-keys_0.0.1_darwin_arm64.tar.gz":    false,
		"checksums.txt":                         false,
		"wssh_0.0.1_darwin_arm64.tar.gz.sha256": false,
		"wssh_0.0.1_darwin_arm64.tar.gz.pem":    false,
	}
	for name, want := range cases {
		if got := isWsshAsset(name); got != want {
			t.Errorf("isWsshAsset(%q) = %v, want %v", name, got, want)
		}
	}
}

// The prefix the command checks and the one the release config produces have
// to be the same string. They are two files, which is exactly how they drift.
func TestTheAssetPrefixIsWssh(t *testing.T) {
	if assetPrefix != "wssh_" {
		t.Errorf("asset prefix is %q, which the release config does not produce", assetPrefix)
	}
	// And the release config has to produce it.
	config, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yml"))
	if err != nil {
		t.Fatalf("read the release config: %v", err)
	}
	if !strings.Contains(string(config), "{{ .Binary }}_") {
		t.Errorf("the release config does not name assets %s<version>_<os>_<arch>, which is what the upgrade looks for", assetPrefix)
	}
}

// go-selfupdate takes the file it replaces out of the archive by the name of
// the file it is overwriting, so a renamed binary cannot find its own
// replacement in an archive that holds `wssh`. The alternative is a tar error
// naming an archive this command had no trouble with a moment earlier.
func TestARenamedBinarySaysSoRatherThanReportingATarError(t *testing.T) {
	if binaryName != "wssh" {
		t.Errorf("binary name is %q, which the release archives do not hold", binaryName)
	}
	// canReplaceItself, so true means "this one can upgrade itself".
	for exe, want := range map[string]bool{
		"/usr/local/bin/wssh": true,
		"wssh":                true,
		"wssh.exe":            true,
		"renamed-wssh":        false,
		"wssh-old":            false,
		"sol-tx":              false,
	} {
		if got := canReplaceItself(exe); got != want {
			t.Errorf("canReplaceItself(%q) = %v, want %v", exe, got, want)
		}
	}
}
