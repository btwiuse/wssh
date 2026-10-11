package main

import (
	"context"
	"strings"
	"testing"
)

// The GitHub call is not reachable from a test, so what is tested here is the
// part that decides whether to make it: the guard on a binary that does not
// know its own version.
//
// That guard is not decoration. This help text once said the opposite - that
// a "dev" build would treat every release as newer - and the code refused.
// Whichever of the two is right, the two have to be the same.
func TestABinaryWithNoVersionIsRefusedRatherThanDowngraded(t *testing.T) {
	for _, current := range []string{"", "dev"} {
		t.Run("version="+current, func(t *testing.T) {
			err := upgrade(context.Background(), current)
			if err == nil {
				t.Fatal("a binary with no version upgraded itself")
			}
			if !strings.Contains(err.Error(), "no version") {
				t.Errorf("the refusal does not say why: %v", err)
			}
			// It must not look like a network problem, or someone will go
			// looking at their connection instead of at their build.
			if strings.Contains(err.Error(), "reach") {
				t.Errorf("the refusal blames the network: %v", err)
			}
		})
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
