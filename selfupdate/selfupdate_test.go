package selfupdate

import (
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Every rule in this package exists because leaving it out broke an upgrade,
// so each one is pinned here rather than only in whichever binary happens to
// call it today.

// The asset has to be matched on a pattern anchored at both ends. Matching on
// the platform suffix alone - which is what the library does - takes the first
// asset of any binary in the release, and on the first release published here
// that was sol-keys being written over wssh.
func TestAssetPatternMatchesOnlyThisBinaryOnThisPlatform(t *testing.T) {
	for _, binary := range []string{"wssh", "cafe", "sol-tx", "sol-keys"} {
		re, err := regexp.Compile(AssetPattern(binary))
		if err != nil {
			t.Fatalf("%s: pattern does not compile: %v", binary, err)
		}
		ours := binary + "_0.0.4_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
		if !re.MatchString(ours) {
			t.Errorf("%s: the pattern does not match its own asset %q", binary, ours)
		}

		// Every other binary's asset for this platform must not match, and
		// neither must a checksum file or another platform's.
		for _, other := range []string{"wssh", "cafe", "sol-tx", "sol-keys"} {
			if other == binary {
				continue
			}
			theirs := other + "_0.0.4_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
			if re.MatchString(theirs) {
				t.Errorf("%s: the pattern matched %s's asset %q", binary, other, theirs)
			}
		}
		// Another platform's asset, named by flipping the architecture
		// rather than hard-coded, so this holds on whatever it runs on.
		otherArch := map[string]string{"amd64": "arm64", "arm64": "amd64"}[runtime.GOARCH]
		for _, near := range []string{
			"checksums.txt",
			binary + "_0.0.4_" + runtime.GOOS + "_" + runtime.GOARCH,
			binary + "_0.0.4_" + runtime.GOOS + "_" + otherArch + ".tar.gz",
			"prefix" + binary + "_0.0.4_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz",
		} {
			if re.MatchString(near) {
				t.Errorf("%s: the pattern matched %q, which it should not", binary, near)
			}
		}
	}
}

// Handed a name with no archive suffix the library decides the download is not
// compressed and writes the file over the executable whole. That is a real
// failure this repository shipped once: the tarball landed as the executable
// and the command reported success.
func TestIsBinaryAsset(t *testing.T) {
	cases := []struct {
		name, binary string
		want         bool
	}{
		{"wssh_0.0.4_darwin_arm64.tar.gz", "wssh", true},
		{"wssh_0.0.4_darwin_arm64.zip", "wssh", true},
		{"cafe_0.0.4_darwin_arm64.tar.gz", "cafe", true},
		{"sol-tx_0.0.4_darwin_arm64.tar.gz", "sol-tx", true},
		{"checksums.txt", "wssh", false},
		{"wssh_0.0.4_darwin_arm64", "wssh", false},
		{"cafe_0.0.4_darwin_arm64.tar.gz", "wssh", false},
		{"sol-keys_0.0.4_darwin_arm64.tar.gz", "wssh", false},
		{"wsshx_0.0.4_darwin_arm64.tar.gz", "wssh", false},
	}
	for _, c := range cases {
		if got := IsBinaryAsset(c.name, c.binary); got != c.want {
			t.Errorf("IsBinaryAsset(%q, %q) = %v, want %v", c.name, c.binary, got, c.want)
		}
	}
}

// A build with no version must take the newest release. "dev" is what a build
// without the version stamped in reports, the library cannot parse it, and it
// is exactly what somebody running this on a local build has.
func TestABinaryWithNoVersionTakesTheNewestRelease(t *testing.T) {
	for _, unversioned := range []string{"", "dev"} {
		if !IsUnversioned(unversioned) {
			t.Errorf("%q was treated as a version to compare against", unversioned)
		}
	}
	for _, versioned := range []string{"0.0.1", "v1.2.3", "1.0.0-rc1", "development"} {
		if IsUnversioned(versioned) {
			t.Errorf("%q was treated as having no version", versioned)
		}
	}
}

// The library finds the entry to extract from the name of the file it is
// overwriting, so a renamed binary cannot find its own replacement and would
// report a truncated tar instead of the real reason.
func TestCanReplaceItself(t *testing.T) {
	cases := []struct {
		exe, binary string
		want        bool
	}{
		{"/usr/local/bin/wssh", "wssh", true},
		{"/usr/local/bin/wssh.exe", "wssh", true},
		{"/usr/local/bin/cafe", "cafe", true},
		{"/usr/local/bin/wssh.exe", "cafe", false},
		{"/opt/router/bin/routercafe", "cafe", false},
		{"./wssh", "wssh", true},
	}
	for _, c := range cases {
		if got := CanReplaceItself(c.exe, c.binary); got != c.want {
			t.Errorf("CanReplaceItself(%q, %q) = %v, want %v", c.exe, c.binary, got, c.want)
		}
	}
}

// The two binaries that can upgrade themselves must both be spelled the way
// their archives are, and must not be spelled the same way.
func TestTheBinaryNamesAreDistinctAndMatchTheirArchives(t *testing.T) {
	names := map[string]bool{}
	for _, binary := range []string{"wssh", "cafe"} {
		if names[binary] {
			t.Errorf("%q appears twice; an upgrade would take the wrong archive", binary)
		}
		names[binary] = true
		if !IsBinaryAsset(binary+"_0.0.4_"+runtime.GOOS+"_"+runtime.GOARCH+".tar.gz", binary) {
			t.Errorf("%s: the release does not hold an asset this would accept", binary)
		}
	}
}

func TestAnEmptyBinaryNameDoesNotAcceptAnything(t *testing.T) {
	// Not a network test. This pins that a caller who forgot to set the
	// binary name cannot accept an arbitrary asset, which is the difference
	// between a refused upgrade and one that writes the wrong thing over the
	// running executable.
	if IsBinaryAsset("anything.tar.gz", "") {
		t.Error("an empty binary name accepted an arbitrary archive")
	}
	if IsBinaryAsset("_0.0.4_darwin_arm64.tar.gz", "") {
		t.Error("an empty binary name accepted an archive that merely starts with the separator")
	}
	// The pattern still carries the platform, so an unset name narrows to
	// nothing rather than to everything.
	if !strings.Contains(AssetPattern(""), runtime.GOOS) {
		t.Errorf("the pattern does not carry the platform: %q", AssetPattern(""))
	}
}
