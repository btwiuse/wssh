package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/routercafe/routercafe/cafe"
)

// The landing page is the product's front door and its pitch deck, and it is
// the one page here whose content comes from configuration: the treasury, the
// SOL price and the provider are all an operator's command line rendered into
// the page. That is a hole worth a test.

func treasuryForTest(addr string) cafe.Treasury { return cafe.Treasury{Address: addr} }

func testLanding() http.Handler {
	return landingHandler(&serveOptions{
		Treasury: treasuryForTest("So11111111111111111111111111111111111111112"),
		Upstream: "https://api.openai.com/v1/",
	})
}

func TestLandingPageIsServedAtTheRoot(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	testLanding().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Errorf("Content-Type is %q", got)
	}
	body := rec.Body.String()
	for _, want := range []string{"RouterCafe", "ssh -A router.cafe", "SOL"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not mention %q", want)
		}
	}
}

// No placeholder may reach a browser. A page showing __ROUTERCAFE_TREASURY__
// is worse than a page showing nothing, because it looks like a real value.
func TestLandingPageHasNoPlaceholdersLeft(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	testLanding().ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, placeholder := range []string{
		"__ROUTERCAFE_TREASURY__",
		"__ROUTERCAFE_SOL_PRICE__",
		"__ROUTERCAFE_UPSTREAM__",
		"__WSSH_SESSION_PATH__",
	} {
		if strings.Contains(body, placeholder) {
			t.Errorf("the page still contains %s", placeholder)
		}
	}
}

func TestLandingPageRendersTheConfiguration(t *testing.T) {
	rec := httptest.NewRecorder()
	testLanding().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()

	if !strings.Contains(body, "So11111111111111111111111111111111111111112") {
		t.Error("the treasury address is not on the page")
	}
	// The scheme and the trailing slash are dropped: what belongs on a page is
	// the host a reader would recognise, not the URL a config file holds.
	if strings.Contains(body, "https://api.openai.com") {
		t.Error("the provider is rendered as a full URL")
	}
	if !strings.Contains(body, "api.openai.com/v1") {
		t.Error("the provider host is missing from the page")
	}
}

// An address from a command line is operator configuration, and configuration
// does not get to be markup. This is the one place a configured value reaches
// HTML without a template engine in front of it.
func TestLandingPageEscapesWhatItRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	handler := landingHandler(&serveOptions{
		// Not an address, so it is not rendered at all; the escaping that
		// matters is checked on the provider, which takes any string.
		Upstream: "https://openai.example/<script>alert(1)</script>",
	})
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("the upstream was rendered as markup")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the upstream was not escaped at all: %q", snippet(body, "script"))
	}
}

func TestLandingPageIsNotAFileServer(t *testing.T) {
	rec := httptest.NewRecorder()
	testLanding().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code == http.StatusOK {
		t.Error("an unknown path was served; this host has three routes, not a document tree")
	}
}

func TestUpstreamName(t *testing.T) {
	cases := map[string]string{
		"https://api.openai.com/v1/": "api.openai.com/v1",
		"https://api.openai.com/v1":  "api.openai.com/v1",
		"api.openai.com":             "api.openai.com",
		"":                           "",
	}
	for in, want := range cases {
		if got := upstreamName(in); got != want {
			t.Errorf("upstreamName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLandingIsEmbedded(t *testing.T) {
	if LandingMissing() {
		t.Error("the landing page did not embed; the server would serve nothing but a 500")
	}
}

func TestListenAddr(t *testing.T) {
	t.Setenv("PORT", "")
	if got := listenAddr(""); got != ":8080" {
		t.Errorf("listenAddr(\"\") = %q, want :8080", got)
	}
	if got := listenAddr(":2222"); got != ":2222" {
		t.Errorf("an explicit address was not used: %q", got)
	}
	t.Setenv("PORT", "9999")
	if got := listenAddr(""); got != ":9999" {
		t.Errorf("listenAddr with PORT=9999 = %q, want :9999", got)
	}
	t.Setenv("PORT", ":7777")
	if got := listenAddr(""); got != ":7777" {
		t.Errorf("listenAddr with PORT=:7777 = %q, want :7777", got)
	}
}

// The two defaults that make the product work at all: anyone may hold an
// account, and the agent is forwarded so a deposit can be signed. Both are
// checked here rather than only in the flag defaults, because a flag default
// is easy to change by accident and this is a public service.
func TestDefaultsAreTheOnesTheProductNeeds(t *testing.T) {
	if LandingMissing() {
		t.Skip("no landing page in this build")
	}
	cmd := newCafeCmd()
	if err := cmd.Flags().Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cmd.Flags().Lookup("forward-agent").DefValue; got != "true" {
		t.Errorf("--forward-agent defaults to %s; a deposit has nothing to ask without it", got)
	}
	for _, name := range []string{"authorized-key", "authorized-addresses"} {
		got, err := cmd.Flags().GetStringSlice(name)
		if err != nil {
			t.Fatalf("read --%s: %v", name, err)
		}
		if len(got) != 1 || got[0] != "*" {
			t.Errorf("--%s defaults to %q, want [*]", name, got)
		}
	}
	// And there is no way to ask for a shell, because there is no flag for it.
	for _, name := range []string{"allow-tcp-forwarding", "shell", "command"} {
		if cmd.Flags().Lookup(name) != nil {
			t.Errorf("--%s exists; this server has no configuration in which a command runs", name)
		}
	}
}

func snippet(s, needle string) string {
	i := strings.Index(s, needle)
	if i < 0 {
		return ""
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	end := i + 60
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

// A visitor who reaches this host with no key is a visitor to be shown how to
// become a user. That is the default, so it is a default worth pinning: it is
// also the switch that admits every connection with no key, and an operator who
// would rather hear nothing from them has to be able to say so.
func TestAnonymousAccessIsOnUnlessAskedOtherwise(t *testing.T) {
	cmd := newCafeCmd()
	if err := cmd.Flags().Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cmd.Flags().Lookup("allow-anonymous").DefValue; got != "true" {
		t.Errorf("--allow-anonymous defaults to %s", got)
	}
	if cmd.Flags().Lookup("require-key") == nil {
		t.Error("there is no way to turn it off")
	}
}
