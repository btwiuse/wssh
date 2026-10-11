package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	charmssh "charm.land/ssh"
	"github.com/routercafe/routercafe/auth"
	"github.com/routercafe/routercafe/cafe"
	gossh "golang.org/x/crypto/ssh"
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

// The page prints the routing table, and the binary serves a different one from
// cafe.DefaultCatalogue. Those are the same list written down twice, which is how
// a page ends up quoting prices for models the router retired - the failure this
// test is here to catch, and the reason it walks the catalogue rather than
// grepping for a few names.
//
// Every route must be on the page with its price, in the unit the page uses.
// A route the page omits is not an error - a page may choose to show a subset -
// but a price on the page that no route has is a page lying about what will be
// billed.
func TestTheLandingPagesPricesAreTheCatalogues(t *testing.T) {
	rec := httptest.NewRecorder()
	testLanding().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()

	shown := map[string]bool{}
	for _, m := range cafe.DefaultCatalogue().Models() {
		if !strings.Contains(body, ">"+m.ID+"<") {
			continue
		}
		shown[m.ID] = true
		for _, price := range []string{priceForPage(m.InputPerMTok), priceForPage(m.OutputPerMTok)} {
			if !strings.Contains(body, ">"+price+"<") {
				t.Errorf("%s is on the page but its price %q is not", m.ID, price)
			}
		}
	}
	if len(shown) == 0 {
		t.Error("the page shows none of the routes the router actually serves")
	}
	t.Logf("the page quotes %d of %d routes", len(shown), len(cafe.DefaultCatalogue().Models()))
}

// A price is "free" or it is money, never $0.00 - the same rule the TUI's own
// price column follows, so a reader moving between the page and the terminal
// does not have to wonder whether one of them is charging for the free route.
func priceForPage(v cafe.MicroUSD) string {
	if v == 0 {
		return "free"
	}
	return cafe.FormatUSD(v)
}

// The page tells a reader which keys to press, so a key it names must be one the
// program binds. These are the letters the session UI has: the tab bar replaced
// the old single-letter navigation, and a page still saying `b` and `k` is
// describing a program that no longer exists.
//
// Written as the letters that must NOT appear rather than the ones that must, so
// a retired binding is caught on the day it is retired rather than the day
// somebody notices the page is stale.
func TestTheLandingPageNamesNoRetiredKeys(t *testing.T) {
	rec := httptest.NewRecorder()
	testLanding().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()

	for _, gone := range []string{"Press <code>d</code>", "Press <code>k</code>", "<code>b</code> balance"} {
		if strings.Contains(body, gone) {
			t.Errorf("the page still says %q; navigation is the tab bar now", gone)
		}
	}
	// And it must still say how to get a key, which is the one key a reader
	// genuinely needs spelled out.
	if !strings.Contains(body, "<code>n</code>") {
		t.Error("the page does not say that n mints a key")
	}
}

// The FAQs are written down twice - once here for the browser, once in
// cafe/help.go for the terminal - and the file comment there says so: "the same
// questions answered twice is how the two stop agreeing". Nothing enforced it,
// which is how a "Can I self-host it?" survived in one copy after being dropped
// from the other, and how the landing page went on telling readers to press `k`
// for months after the tab bar replaced it.
//
// Checked by question, in both directions: a question in the terminal the page
// does not have, and a question on the page the terminal does not have. A shared
// answer is not compared word for word - the page marks up its own - but a
// question is a question.
func TestTheLandingPageAndTheTerminalCarryTheSameQuestions(t *testing.T) {
	rec := httptest.NewRecorder()
	testLanding().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()

	onPage := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?s)<summary>(.*?)</summary>`).FindAllStringSubmatch(body, -1) {
		onPage[stripTags(m[1])] = true
	}
	if len(onPage) == 0 {
		t.Fatal("the page has no questions at all; the check below would pass on anything")
	}

	for _, f := range cafe.FAQs() {
		if !onPage[f.Question] {
			t.Errorf("the terminal asks %q and the page does not", f.Question)
		}
	}
	for q := range onPage {
		if !cafe.HasFAQ(q) {
			t.Errorf("the page asks %q and the terminal does not", q)
		}
	}
}

func stripTags(s string) string {
	return strings.TrimSpace(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(s, ""))
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

// Refusing "none" is the default, and it is a default worth pinning twice over.
// It is what lets the server see a client's key at all - accepting "none" ends
// the handshake before one is offered - and it is also the switch that turns
// away everybody without an ed25519, so an operator who wants those connections
// has to be able to say so.
func TestAnonymousAccessIsOffUnlessAskedOtherwise(t *testing.T) {
	cmd := newCafeCmd()
	if err := cmd.Flags().Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cmd.Flags().Lookup("allow-anonymous").DefValue; got != "false" {
		t.Errorf("--allow-anonymous defaults to %s", got)
	}
	if cmd.Flags().Lookup("allow-anonymous") == nil {
		t.Error("there is no way to turn it on")
	}
}

// Only ed25519 can authenticate, and it has to: a client offers its identities
// in order and stops at the first one accepted, so an rsa key accepted first
// would open the session on a key that cannot name an account.
func TestOnlyEd25519KeysAuthenticate(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	edSSH, err := gossh.NewPublicKey(edPub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rsaSSH, err := gossh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	cfg := auth.Config{Keys: []string{auth.AnyKey}}
	cfg.KeyFilter = ed25519Only
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("got %d options, want just the key handler", len(opts))
	}
	srv := &charmssh.Server{}
	for _, o := range opts {
		o(srv)
	}
	if srv.PublicKeyHandler == nil {
		t.Fatal("no key handler installed")
	}
	if !srv.PublicKeyHandler(nil, edSSH) {
		t.Error("an ed25519 key was refused")
	}
	if srv.PublicKeyHandler(nil, rsaSSH) {
		t.Error("an rsa key was accepted as something that can name an account")
	}
}

// The treasury used to be required, which met the common case - somebody
// running their own instance to try it - with a flag they had to go and invent
// an address for before anything happened. It has a default now, and the order
// is the thing worth holding: what you typed beats what your shell exported
// beats the built-in.
func TestTheTreasuryHasADefaultAndTheFlagStillWins(t *testing.T) {
	t.Setenv("ROUTERCAFE_TREASURY", "")

	if got := treasuryFor(&serveOptions{}); got != DefaultTreasury {
		t.Errorf("with nothing set the treasury is %q, want the default %q", got, DefaultTreasury)
	}
	// And the default has to be an address, because the whole point of having
	// one is that a deposit can actually be signed for it.
	if err := cafe.ValidateAddress(DefaultTreasury); err != nil {
		t.Errorf("the built-in treasury is not a valid address: %v", err)
	}

	const mine = "So11111111111111111111111111111111111111112"
	if got := treasuryFor(&serveOptions{Treasury: cafe.Treasury{Address: mine}}); got != mine {
		t.Errorf("the flag was overridden: got %q, want %q", got, mine)
	}

	t.Setenv("ROUTERCAFE_TREASURY", mine)
	if got := treasuryFor(&serveOptions{}); got != mine {
		t.Errorf("the environment was ignored: got %q, want %q", got, mine)
	}
	if got := treasuryFor(&serveOptions{Treasury: cafe.Treasury{Address: DefaultTreasury}}); got != DefaultTreasury {
		t.Errorf("the flag lost to the environment: got %q", got)
	}
}
