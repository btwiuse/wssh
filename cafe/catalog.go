package cafe

import (
	"fmt"
	"sort"
	"strings"
)

// The catalogue: what RouterCafe routes to, and what it charges.
//
// Prices are per million tokens, in micro-USD, which is the unit this whole
// package counts in. Storing them that way rather than as "dollars per
// million" is what makes Cost an integer multiply: a balance can then be
// refused for being a micro-dollar short without a rounding step anywhere near
// the decision.
//
// A model is a name plus where it goes. The router never invents an upstream:
// a request naming a model this catalogue does not have is refused by name,
// because guessing at a close match is how a request meant for one model
// quietly gets billed as another.

// Model is one route: a name people ask for, and where that name goes.
type Model struct {
	// ID is what a request puts in "model". It is the router's own name for
	// the route, not the upstream's: the point of a router is that the name
	// a client has to know does not change when a provider does.
	ID string

	// Name is what the TUI shows.
	Name string

	// Provider is who serves it, shown so a person can see what they are
	// actually talking to.
	Provider string

	// Upstream is the model name at the provider this route goes to.
	Upstream string

	// InputPerMTok and OutputPerMTok are the prices, in micro-USD per
	// million tokens.
	InputPerMTok  MicroUSD
	OutputPerMTok MicroUSD
}

// Cost is what a request of this shape costs, in micro-USD.
//
// Rounded up, because the alternative is a rounding rule that gives away
// fractions of a micro-dollar on small requests and every request is small:
// billing must never come out below what was served.
func (m Model) Cost(inputTokens, outputTokens int) MicroUSD {
	return ceilDiv(int64(inputTokens)*m.InputPerMTok, 1_000_000) +
		ceilDiv(int64(outputTokens)*m.OutputPerMTok, 1_000_000)
}

// ceilDiv divides rounding up, on integers only. There is no float anywhere on
// the path from a token count to a balance, and that is what makes the result
// reproducible.
func ceilDiv(a, b int64) int64 {
	if a <= 0 {
		return 0
	}
	return (a + b - 1) / b
}

// Catalogue is the set of routes, and the one place a model name is resolved.
type Catalogue struct {
	models []Model
	byID   map[string]Model
}

// NewCatalogue builds a catalogue from a list, keeping the first definition of
// any name that appears twice.
//
// First wins rather than last, and silently, because a duplicate id is a
// configuration mistake rather than a request to override: the routes are
// listed in one place and a person reads that list, so a later duplicate that
// quietly replaced an earlier one would be a price change nobody made.
func NewCatalogue(models ...Model) *Catalogue {
	c := &Catalogue{byID: make(map[string]Model, len(models))}
	for _, m := range models {
		if strings.TrimSpace(m.ID) == "" {
			continue
		}
		if _, seen := c.byID[m.ID]; seen {
			continue
		}
		c.models = append(c.models, m)
		c.byID[m.ID] = m
	}
	sort.SliceStable(c.models, func(i, j int) bool {
		if c.models[i].InputPerMTok != c.models[j].InputPerMTok {
			return c.models[i].InputPerMTok < c.models[j].InputPerMTok
		}
		return c.models[i].ID < c.models[j].ID
	})
	return c
}

// Lookup finds a route by the name a request asked for.
//
// The match is exact. An unknown name is an error naming the name, not a
// guess at the nearest one: this is a router, and the whole of its promise is
// that the model you name is the model you get.
func (c *Catalogue) Lookup(id string) (Model, error) {
	m, ok := c.byID[strings.TrimSpace(id)]
	if !ok {
		return Model{}, fmt.Errorf("no route named %q; %s", id, c.names())
	}
	return m, nil
}

// Models returns every route, cheapest first, which is the order a TUI wants
// them in.
func (c *Catalogue) Models() []Model {
	return append([]Model(nil), c.models...)
}

func (c *Catalogue) names() string {
	names := make([]string, 0, len(c.models))
	for _, m := range c.models {
		names = append(names, m.ID)
	}
	switch len(names) {
	case 0:
		return "this router has no routes configured"
	case 1:
		return "the only one here is " + names[0]
	default:
		return "the ones here are " + strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}

// DefaultCatalogue is what RouterCafe serves with no configuration.
//
// Prices are the public list prices of each model at the time of writing, in
// micro-USD per million tokens, which is the same unit OpenRouter publishes in
// so the two can be compared by eye. They are a default and not a promise: an
// operator whose own agreement with a provider differs sets its own catalogue,
// and the TUI shows the rate that is actually in force rather than a number
// from a website.
//
// A ladder rather than a list of everything: free at the bottom, the three
// providers represented at every tier, and the expensive end reachable without
// scrolling far. The cheap end matters most and is deliberately first — the
// models people actually run all day are the ones a routing table should make
// obvious.
func DefaultCatalogue() *Catalogue {
	return NewCatalogue(
		Model{
			ID: "routercafe/free", Name: "routercafe/free", Provider: "pooled",
			Upstream:      "",
			InputPerMTok:  0,
			OutputPerMTok: 0,
		},
		Model{
			ID: "gpt-6-luna", Name: "GPT-6 Luna", Provider: "openai",
			Upstream:      "gpt-6-luna",
			InputPerMTok:  100_000,
			OutputPerMTok: 500_000,
		},
		Model{
			ID: "claude-haiku-5-5", Name: "Claude Haiku 5.5", Provider: "anthropic",
			Upstream:      "claude-haiku-5-5",
			InputPerMTok:  100_000,
			OutputPerMTok: 500_000,
		},
		Model{
			ID: "gemini-3.8-flash", Name: "Gemini 3.8 Flash", Provider: "google",
			Upstream:      "gemini-3.8-flash",
			InputPerMTok:  750_000,
			OutputPerMTok: 3_750_000,
		},
		Model{
			ID: "claude-sonnet-5-5", Name: "Claude Sonnet 5.5", Provider: "anthropic",
			Upstream:      "claude-sonnet-5-5",
			InputPerMTok:  2_000_000,
			OutputPerMTok: 10_000_000,
		},
		Model{
			ID: "gpt-6.1-sol", Name: "GPT-6.1 Sol", Provider: "openai",
			Upstream:      "gpt-6.1-sol",
			InputPerMTok:  2_000_000,
			OutputPerMTok: 10_000_000,
		},
		Model{
			ID: "claude-opus-5-5", Name: "Claude Opus 5.5", Provider: "anthropic",
			Upstream:      "claude-opus-5-5",
			InputPerMTok:  4_000_000,
			OutputPerMTok: 20_000_000,
		},
		Model{
			ID: "gemini-3.1-pro-preview", Name: "Gemini 3.1 Pro", Provider: "google",
			Upstream:      "gemini-3.1-pro-preview",
			InputPerMTok:  2_000_000,
			OutputPerMTok: 12_000_000,
		},
		Model{
			ID: "gpt-6-astra", Name: "GPT-6 Astra", Provider: "openai",
			Upstream:      "gpt-6-astra",
			InputPerMTok:  10_000_000,
			OutputPerMTok: 50_000_000,
		},
	)
}

// perMTok renders a price the way a price list reads.
func perMTok(v MicroUSD) string {
	if v == 0 {
		return "free"
	}
	return FormatUSD(v) + " / 1M"
}
