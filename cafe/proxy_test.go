package cafe

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The router is the only part of RouterCafe that hands out anything a caller
// wants, so these are the tests about what a credential can reach and what it
// costs to get there.

// fakeUpstream stands in for a provider: it records what it was asked for and
// answers with whatever usage the test wants it to report.
type fakeUpstream struct {
	server *httptest.Server
	last   map[string]any
}

func newFakeUpstream(t *testing.T, answer string) *fakeUpstream {
	t.Helper()
	up := &fakeUpstream{}
	up.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &up.last)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(up.server.Close)
	return up
}

func testCatalogue() *Catalogue {
	return NewCatalogue(
		Model{ID: "cheap", Name: "cheap", Provider: "default", Upstream: "cheap-1",
			InputPerMTok: PerMicroUSD / 10, OutputPerMTok: PerMicroUSD / 5},
		Model{ID: "dear", Name: "dear", Provider: "default", Upstream: "dear-1",
			InputPerMTok: PerMicroUSD, OutputPerMTok: PerMicroUSD * 2},
	)
}

func testRouter(t *testing.T, up *fakeUpstream, l *Ledger) *Router {
	t.Helper()
	base := ""
	if up != nil {
		base = up.server.URL
	}
	r, err := NewRouter(RouterOptions{
		Ledger:             l,
		Catalogue:          testCatalogue(),
		Upstreams:          Upstreams{"default": {Name: "default", BaseURL: base, Key: "sk-provider"}},
		MaxReserveMicroUSD: PerMicroUSD,
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return r
}

const answerWithUsage = `{"model":"cheap-1","usage":{"prompt_tokens":1000,"completion_tokens":500},"choices":[]}`

func call(t *testing.T, r *Router, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)
	return rec
}

func TestRouterRefusesWithoutAKey(t *testing.T) {
	l := testLedger(t)
	r := testRouter(t, nil, l)

	rec := call(t, r, "", `{"model":"cheap","messages":[]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key gave %d, want 401", rec.Code)
	}
	if _, err := l.MintKey("acct", ""); err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	rec = call(t, r, "rc_nope", `{"model":"cheap","messages":[]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("an unknown key gave %d, want 401", rec.Code)
	}
	if got := l.Account("acct").Balance; got != 0 {
		t.Errorf("a refused request changed a balance to %d", got)
	}
}

func TestRouterChargesWhatTheProviderReported(t *testing.T) {
	up := newFakeUpstream(t, answerWithUsage)
	l := testLedger(t)
	key, err := l.MintKey("acct", "")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	// $10 on the balance.
	if err := l.Credit("acct", 10*PerMicroUSD); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	r := testRouter(t, up, l)

	rec := call(t, r, key, `{"model":"cheap","messages":[{"role":"user","content":"hello"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}

	// 1000 input tokens at $0.10 per million is $0.0001; 500 output at $0.20
	// per million is $0.0001. Both round up, which is the only direction that
	// cannot undercharge.
	want := MicroUSD(100) + MicroUSD(100)
	if got := l.Account("acct").Balance; got != 10*PerMicroUSD-want {
		t.Errorf("balance is %d, want %d", got, 10*PerMicroUSD-want)
	}
	if got := l.Account("acct").Spent; got != want {
		t.Errorf("spent is %d, want %d", got, want)
	}

	// The model name that comes back is the router's, not the provider's.
	var answer map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the answer is not JSON: %v", err)
	}
	if answer["model"] != "cheap" {
		t.Errorf("the answer names model %v, want cheap", answer["model"])
	}
	// And the request went upstream under the provider's name.
	if up.last["model"] != "cheap-1" {
		t.Errorf("the upstream was asked for %v, want cheap-1", up.last["model"])
	}
}

// A request that would cost more than the balance is refused before the
// provider is touched, and nothing is charged for the attempt.
func TestRouterRefusesWhatTheBalanceCannotCover(t *testing.T) {
	up := newFakeUpstream(t, answerWithUsage)
	l := testLedger(t)
	key, err := l.MintKey("acct", "")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	if err := l.Credit("acct", PerMicroUSD/100); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	r := testRouter(t, up, l)

	// dear is $1 per million in and $2 per million out, so 40000 output tokens
	// would hold $0.08 against a balance of $0.01.
	rec := call(t, r, key, `{"model":"dear","messages":[{"role":"user","content":"hello"}],"max_tokens":40000}`)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("got %d, want 402: %s", rec.Code, rec.Body.String())
	}
	if up.last != nil {
		t.Error("the provider was asked anyway; the reservation is meant to stop that")
	}
	if got := l.Account("acct").Balance; got != PerMicroUSD/100 {
		t.Errorf("a refused request changed a balance to %d", got)
	}
}

// The reservation has to come back. A balance that only ever goes down by the
// estimate would quietly steal from every caller.
func TestReservationIsRefundedWhenNothingIsReported(t *testing.T) {
	up := newFakeUpstream(t, `{"model":"cheap-1","choices":[]}`) // no usage at all
	l := testLedger(t)
	key, err := l.MintKey("acct", "")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	if err := l.Credit("acct", PerMicroUSD); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	r := testRouter(t, up, l)

	if rec := call(t, r, key, `{"model":"cheap","messages":[{"role":"user","content":"hello"}]}`); rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	// No usage means the reservation is kept, which is the only answer that is
	// not a way to avoid being charged.
	if got := l.Account("acct").Balance; got >= PerMicroUSD {
		t.Errorf("balance is %d: nothing was charged for a request that reported no usage", got)
	}
	if got := l.Account("acct").Spent; got <= 0 {
		t.Error("nothing was charged at all")
	}
}

func TestRouterRefusesAnUnknownModelByName(t *testing.T) {
	up := newFakeUpstream(t, answerWithUsage)
	l := testLedger(t)
	key, err := l.MintKey("acct", "")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	if err := l.Credit("acct", PerMicroUSD); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	r := testRouter(t, up, l)

	rec := call(t, r, key, `{"model":"gpt-4o-minii","messages":[]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404: %s", rec.Code, rec.Body.String())
	}
	// The refusal names what was asked for and what exists, because a typo is
	// the likely cause and a bare 404 does not help with that.
	body := rec.Body.String()
	if !strings.Contains(body, "gpt-4o-minii") || !strings.Contains(body, "cheap") {
		t.Errorf("the refusal does not name both the ask and the alternatives: %s", body)
	}
	if up.last != nil {
		t.Error("the provider was asked for a model this router does not have")
	}
}

// A route naming a provider that is not configured is the operator's problem,
// not the caller's, and it is a 502 rather than a 404 so a client can tell
// "wrong name" from "ours is broken".
func TestRouterReportsAnUnconfiguredProvider(t *testing.T) {
	l := testLedger(t)
	key, err := l.MintKey("acct", "")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	if err := l.Credit("acct", PerMicroUSD); err != nil {
		t.Fatalf("Credit: %v", err)
	}
	catalogue := NewCatalogue(Model{ID: "x", Provider: "somewhere-else", Upstream: "x"})
	r, err := NewRouter(RouterOptions{
		Ledger:    l,
		Catalogue: catalogue,
		Upstreams: Upstreams{"default": {Name: "default", BaseURL: "http://example.invalid"}},
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	rec := call(t, r, key, `{"model":"x","messages":[]}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if got := l.Account("acct").Balance; got != PerMicroUSD {
		t.Errorf("a request that went nowhere charged %d", PerMicroUSD-got)
	}
}

func TestListModels(t *testing.T) {
	l := testLedger(t)
	key, err := l.MintKey("acct", "")
	if err != nil {
		t.Fatalf("MintKey: %v", err)
	}
	r := testRouter(t, nil, l)

	req := httptest.NewRequest(http.MethodGet, "/models", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	var answer struct {
		Object string `json:"object"`
		Data   []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if answer.Object != "list" || len(answer.Data) != 2 {
		t.Fatalf("got %+v, want a list of two", answer)
	}
}

func TestModelCostRoundsUp(t *testing.T) {
	m := Model{InputPerMTok: 1_500_000, OutputPerMTok: 3_000_000} // $1.50 and $3.00 per million
	cases := []struct {
		in, out int
		want    MicroUSD
	}{
		{0, 0, 0},
		{1_000_000, 0, 1_500_000}, // exactly one million
		{1, 0, 2},                 // one token rounds up to two micro-dollars
		{0, 1, 3},
		{1_000_001, 1, 1_500_002 + 3},
	}
	for _, c := range cases {
		if got := m.Cost(c.in, c.out); got != c.want {
			t.Errorf("Cost(%d, %d) = %d, want %d", c.in, c.out, got, c.want)
		}
	}
}

// The reservation is bounded twice: by what the request asks for, and by the
// operator's ceiling. A request asking for a million tokens must not be able
// to lock an account out.
func TestReservationIsCapped(t *testing.T) {
	l := testLedger(t)
	r := testRouter(t, nil, l)
	r.opts.MaxReserveMicroUSD = PerMicroUSD / 10

	body := map[string]any{"model": "dear", "messages": []any{}, "max_tokens": float64(1_000_000)}
	cost, err := r.reserve("acct", mustLookup(t, r, "dear"), body)
	if err == nil {
		t.Fatalf("an account with nothing reserved %d", cost)
	}
	if cost != r.opts.MaxReserveMicroUSD {
		t.Errorf("reserved %d, want the cap %d", cost, r.opts.MaxReserveMicroUSD)
	}
}

func mustLookup(t *testing.T, r *Router, id string) Model {
	t.Helper()
	m, err := r.opts.Catalogue.Lookup(id)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", id, err)
	}
	return m
}

func TestUpstreamsForRefusesToGuess(t *testing.T) {
	one := Upstreams{"default": {Name: "default", BaseURL: "https://a.example"}}
	// One endpoint is the ordinary deployment, so every route goes to it
	// whatever the catalogue calls its provider.
	if _, err := one.For("openai"); err != nil {
		t.Errorf("a single configured upstream did not serve every route: %v", err)
	}
	if _, err := one.For(""); err != nil {
		t.Errorf("the empty provider name is the default one: %v", err)
	}

	// With more than one, a name that is not among them is a refusal rather
	// than a guess about which endpoint was meant.
	two := Upstreams{
		"openai":    {Name: "openai", BaseURL: "https://a.example"},
		"anthropic": {Name: "anthropic", BaseURL: "https://b.example"},
	}
	if _, err := two.For("somewhere-else"); err == nil {
		t.Error("an unconfigured provider was resolved; a request could be sent to the wrong endpoint")
	}
	if up, err := two.For("anthropic"); err != nil || up.Name != "anthropic" {
		t.Errorf("a configured provider did not resolve to itself: %v %q", err, up.Name)
	}
	if _, err := (Upstreams{"default": {Name: "default"}}).For("default"); err == nil {
		t.Error("an upstream with no base URL was accepted")
	}
}

// The 402 carries the ledger's own sentence. When the two were joined the way
// every other error is, the condition was stated twice in one line.
func TestJoinMessageDoesNotRepeatItself(t *testing.T) {
	cases := []struct{ message, detail, want string }{
		{"no route", "nothing named that", "no route: nothing named that"},
		{"", "not enough balance: this call could cost $1.00", "not enough balance: this call could cost $1.00"},
		{"just the summary", "", "just the summary"},
	}
	for _, c := range cases {
		if got := joinMessage(c.message, c.detail); got != c.want {
			t.Errorf("joinMessage(%q, %q) = %q, want %q", c.message, c.detail, got, c.want)
		}
	}
}
