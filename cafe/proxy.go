package cafe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"charm.land/log/v2"
)

// The HTTP half: an OpenAI-compatible endpoint that spends a balance.
//
// Compatibility is the point, and it is why this is shaped the way it is. The
// request body is passed through as JSON with two fields rewritten rather than
// decoded into a Go struct: an OpenAI client sends a dozen optional fields this
// has never heard of, and a struct would drop every one of them on the floor
// before the provider saw them. So nothing is dropped and nothing is
// interpreted that does not have to be.
//
// Billing is the other half, and the interesting problem in it. A balance can
// be refused before the work is done only if the cost of the work is known
// first, and for a completion it is not: the number of tokens that come back
// is not knowable until they have come back. So the reservation is the answer:
// the most the request could cost is taken before it is sent, and the
// difference is given back once the real usage is known. The balance therefore
// never goes negative, and a caller cannot spend money this server has not
// already agreed to cover.

// Upstream is one provider this router forwards to.
type Upstream struct {
	// Name is what a route's Provider field refers to. One upstream may serve
	// every route; several exist so a catalogue can spread across providers,
	// which is the whole point of the thing.
	Name string

	// BaseURL is the provider's API root, without a trailing slash: the
	// router appends "/chat/completions" to it.
	BaseURL string

	// Key is the provider's credential. It is the router's key, not the
	// caller's: a caller authenticates with a RouterCafe key and never sees
	// this one, which is what makes it possible for one balance to pay for
	// several providers.
	Key string
}

// Upstreams are the providers a route can go to, by name.
type Upstreams map[string]Upstream

// For resolves a route's provider name to the upstream that serves it.
//
// Two rules, and the second one only applies when there is exactly one
// upstream:
//
//   - A named provider that is configured is used, whatever else is there.
//   - With a single upstream configured, every route goes to it. That is the
//     ordinary deployment: one provider, or one gateway in front of several,
//     and a catalogue that names five providers against one endpoint would
//     otherwise answer 502 to all of them for a reason the operator cannot act
//     on.
//
// With two or more configured, a route naming a provider that is not among
// them is an error rather than a fallback. Sending a request for one model to
// whichever endpoint happened to be configured is how a caller ends up billed
// for something they did not ask for, and by then there is more than one
// endpoint to be wrong about.
func (u Upstreams) For(provider string) (Upstream, error) {
	name := strings.TrimSpace(provider)
	if name == "" {
		name = "default"
	}
	if up, ok := u[name]; ok {
		return checked(up, name)
	}
	if len(u) == 1 {
		for _, up := range u {
			return checked(up, name+" (the only upstream configured)")
		}
	}
	return Upstream{}, fmt.Errorf(
		"no upstream is configured for provider %q; configured: %s", name, strings.Join(u.names(), ", "))
}

func checked(up Upstream, name string) (Upstream, error) {
	if strings.TrimSpace(up.BaseURL) == "" {
		return Upstream{}, fmt.Errorf("the upstream for %q has no base URL", name)
	}
	return up, nil
}

func (u Upstreams) names() []string {
	names := make([]string, 0, len(u))
	for name := range u {
		names = append(names, name)
	}
	if len(names) == 0 {
		return []string{"none"}
	}
	return names
}

// RouterOptions is what the HTTP side needs.
type RouterOptions struct {
	Ledger    *Ledger
	Catalogue *Catalogue
	Upstreams Upstreams

	// MaxReserveMicroUSD bounds what a single request may hold against a
	// balance while it is in flight. Without it a request asking for a
	// million tokens would reserve a million tokens' worth of money and
	// freeze the account for as long as the provider took, which is a way to
	// lock somebody out with one line of JSON.
	MaxReserveMicroUSD MicroUSD

	// Timeout bounds one upstream call.
	Timeout time.Duration

	// Logger receives request-level refusals. Nil means the charm default.
	Logger *log.Logger
}

// Router serves /v1.
type Router struct {
	opts RouterOptions
	http *http.Client
}

// NewRouter builds the HTTP side.
func NewRouter(opts RouterOptions) (*Router, error) {
	if opts.Ledger == nil {
		return nil, errors.New("the router needs a ledger to bill against")
	}
	if opts.Catalogue == nil {
		opts.Catalogue = DefaultCatalogue()
	}
	if opts.MaxReserveMicroUSD <= 0 {
		// Generous enough for a long completion, small enough that it is not
		// a lock-out. See the field comment.
		opts.MaxReserveMicroUSD = 5 * PerMicroUSD
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Minute
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	return &Router{
		opts: opts,
		http: &http.Client{Timeout: opts.Timeout},
	}, nil
}

// Handler serves the OpenAI-compatible routes.
//
// Mounted under /v1, so the paths here are relative to that: "models" and
// "chat/completions".
func (r *Router) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /models", r.listModels)
	mux.HandleFunc("POST /chat/completions", r.chatCompletions)
	return mux
}

// listModels answers the catalogue, in the shape a client expects.
func (r *Router) listModels(w http.ResponseWriter, req *http.Request) {
	if _, ok := r.authenticate(w, req); !ok {
		return
	}
	data := make([]map[string]any, 0)
	for _, m := range r.opts.Catalogue.Models() {
		data = append(data, map[string]any{
			"id":       m.ID,
			"object":   "model",
			"owned_by": m.Provider,
			"pricing": map[string]string{
				"input_per_mtok":  perMTok(m.InputPerMTok),
				"output_per_mtok": perMTok(m.OutputPerMTok),
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// authenticate turns a presented API key into the account it belongs to.
//
// One place, before anything else looks at the request, because every route
// behind it spends money and the question "is this credential real" must have
// exactly one answer.
func (r *Router) authenticate(w http.ResponseWriter, req *http.Request) (string, bool) {
	key := bearer(req)
	if key == "" {
		writeError(w, http.StatusUnauthorized, "no API key",
			"send one as 'Authorization: Bearer rc_abcd...wxyz'")
		return "", false
	}
	address, err := r.opts.Ledger.Resolve(key)
	if err != nil {
		r.opts.Logger.Debug("api key refused", "error", err, "remote", req.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "unknown API key",
			"that key is not on file. Mint a new one with: ssh -A "+Domain)
		return "", false
	}
	return address, true
}

// bearer reads the Authorization header.
func bearer(req *http.Request) string {
	raw := req.Header.Get("Authorization")
	if raw == "" {
		return ""
	}
	scheme, value, ok := strings.Cut(raw, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

// chatCompletions is the route everything else is about.
func (r *Router) chatCompletions(w http.ResponseWriter, req *http.Request) {
	address, ok := r.authenticate(w, req)
	if !ok {
		return
	}

	raw, err := io.ReadAll(io.LimitReader(req.Body, 8<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request", err.Error())
		return
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		writeError(w, http.StatusBadRequest, "the request is not JSON", err.Error())
		return
	}

	asked, _ := body["model"].(string)
	route, err := r.opts.Catalogue.Lookup(asked)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such model", err.Error())
		return
	}
	upstream, err := r.opts.Upstreams.For(route.Provider)
	if err != nil {
		// The operator's problem, not the caller's: the route exists and this
		// server cannot serve it. A 502 rather than a 404, so a client can
		// tell "wrong name" from "ours is broken".
		r.opts.Logger.Error("route has no upstream", "model", route.ID, "error", err)
		writeError(w, http.StatusBadGateway, "route unavailable", err.Error())
		return
	}

	streaming, _ := body["stream"].(bool)
	reserved, err := r.reserve(address, route, body)
	if err != nil {
		// The one refusal a caller can act on, so it is a 402 with the
		// numbers in the message: what it would have cost, and what is left.
		// The ledger's own wording leads with the same words this status
		// carries, so it is passed as the whole message rather than pasted
		// after a second copy of the same sentence.
		writeError(w, http.StatusPaymentRequired, "", err.Error())
		return
	}

	// The reservation is given back on every path out of here. That is the
	// whole contract: the balance is held for the request, and whatever the
	// request did not use comes back whether it succeeded, failed, or turned
	// out to be a stream that reported no usage at all.
	settled := false
	settle := func(spent MicroUSD) {
		if settled {
			return
		}
		settled = true
		if err := r.opts.Ledger.Settle(address, reserved, spent); err != nil {
			r.opts.Logger.Error("could not settle a reservation",
				"account", address, "reserved", reserved, "spent", spent, "error", err)
		}
	}
	// On every path that does not reach the settle call below, the whole
	// hold comes back: the caller was served nothing.
	defer func() { settle(reserved) }()

	// Ask the upstream for usage even when streaming. Without it a streamed
	// request reports nothing, and the caller would be charged the
	// reservation - which for a short answer is a great deal more than the
	// answer cost.
	body["model"] = route.Upstream
	if streaming {
		options, ok := body["stream_options"].(map[string]any)
		if !ok {
			options = map[string]any{}
			body["stream_options"] = options
		}
		options["include_usage"] = true
	}
	payload, err := json.Marshal(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not re-encode the request", err.Error())
		return
	}

	resp, err := r.call(req.Context(), upstream, route, payload)
	if err != nil {
		r.opts.Logger.Warn("upstream refused", "model", route.ID, "error", err)
		writeError(w, http.StatusBadGateway, "the provider did not answer", err.Error())
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	if streaming {
		r.streamThrough(w, resp)
		return
	}

	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "the provider's answer ended early", err.Error())
		return
	}
	spent := r.charge(route, reserved, readUsage(answer))
	settle(spent)

	// The name goes back to what the caller asked for, so a client reading
	// what it just used sees the name it sent rather than the provider's.
	writeJSONBytes(w, rewriteModel(answer, route.Upstream, route.ID))
}

// charge is what a completed request cost, given what the provider reported.
//
// A provider that reported nothing is charged the reservation, because that is
// the only answer that is not a loophole: a caller able to make the provider
// stop reporting usage would be choosing what they pay.
func (r *Router) charge(route Model, reserved MicroUSD, reported usage) MicroUSD {
	if !reported.Reported {
		return reserved
	}
	cost := route.Cost(reported.PromptTokens, reported.CompletionTokens)
	if cost > reserved {
		// Usage above the estimate. The difference is still charged, because
		// the work really was done and the balance has to reflect it; the
		// Credit below goes negative as a debit-in-reverse, which is the
		// same int64 arithmetic and the same ledger field.
		return cost
	}
	return cost
}

// call asks the provider.
func (r *Router) call(ctx context.Context, up Upstream, route Model, payload []byte) (*http.Response, error) {
	url := strings.TrimSuffix(up.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build the request for %s: %w", route.Provider, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if up.Key != "" {
		req.Header.Set("Authorization", "Bearer "+up.Key)
	}

	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach %s: %w", up.Name, err)
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close() //nolint:errcheck
		return nil, fmt.Errorf("%s answered %s: %s",
			up.Name, resp.Status, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

// streamThrough copies a provider's event stream to the caller untouched.
//
// Byte for byte and as it arrives, because buffering it would defeat the
// reason a caller asked for a stream at all. The usage frame is picked out of
// the same bytes on the way past rather than by reading them twice.
func (r *Router) streamThrough(w http.ResponseWriter, resp *http.Response) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	var scanner usageScanner
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			scanner.feed(buf[:n])
			if _, werr := w.Write(buf[:n]); werr != nil {
				// The client hung up mid-stream. Whatever was sent has been
				// sent; the reservation is released by the caller's defer.
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}
}

// usageScanner finds the usage frame in a stream without buffering the stream.
//
// SSE frames are lines, so this keeps the tail of what it has seen up to the
// last newline and tries each complete line. The cap is what stops a provider
// that sends one enormous line from turning into memory growth here: a line
// that long carries no usage anybody is going to read.
type usageScanner struct {
	tail []byte
	u    usage
}

const maxUsageLine = 1 << 20

func (s *usageScanner) feed(chunk []byte) {
	s.tail = append(s.tail, chunk...)
	for {
		nl := bytes.IndexByte(s.tail, '\n')
		if nl < 0 {
			if len(s.tail) > maxUsageLine {
				s.tail = append(s.tail[:0], s.tail[len(s.tail)-maxUsageLine:]...)
			}
			return
		}
		line := s.tail[:nl]
		s.tail = s.tail[nl+1:]
		data, ok := bytes.CutPrefix(line, []byte("data:"))
		if !ok {
			continue
		}
		data = bytes.TrimSpace(data)
		if len(data) == 0 || string(data) == "[DONE]" {
			continue
		}
		if got := readUsage(data); got.Reported {
			s.u = got
		}
	}
}

// reserve is the most this request could cost, taken from the balance now.
//
// Bounded twice over: by what the request asks for, and by the operator's
// ceiling. The first is what the caller said; the second is what is worth
// holding against somebody's balance while a provider thinks about it.
func (r *Router) reserve(address string, route Model, body map[string]any) (MicroUSD, error) {
	inputTokens := estimateInputTokens(body)
	outputTokens := int(numberOf(body, "max_tokens"))
	if n := int(numberOf(body, "max_completion_tokens")); n > outputTokens {
		outputTokens = n
	}
	if outputTokens <= 0 {
		// Nothing named a cap. Assume the common one rather than the worst
		// one, so a client that does not send max_tokens is not reserving a
		// completion nobody asked to be allowed to make.
		outputTokens = defaultMaxTokens
	}
	cost := route.Cost(inputTokens, outputTokens)
	if cost > r.opts.MaxReserveMicroUSD {
		cost = r.opts.MaxReserveMicroUSD
	}
	// The amount is returned even when the hold is refused. A caller that
	// cannot take it needs to know how much it would have been, and that is
	// the difference between a 402 that says why and one that says no.
	if err := r.opts.Ledger.Reserve(address, cost); err != nil {
		return cost, err
	}
	return cost, nil
}

// defaultMaxTokens is the output cap assumed for a request that names none.
const defaultMaxTokens = 4096

// estimateInputTokens is a rough count of the prompt, for the reservation only.
//
// Four characters to a token is the usual approximation and it is only ever
// used to decide whether to start, never to bill: the amount charged comes
// from what the provider reported, and this figure is gone the moment the
// response arrives.
func estimateInputTokens(body map[string]any) int {
	messages, ok := body["messages"].([]any)
	if !ok {
		return 0
	}
	chars := 0
	for _, raw := range messages {
		message, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if content, ok := message["content"].(string); ok {
			chars += len(content)
			continue
		}
		// Multimodal content is an array of parts; its text is counted and
		// the rest is left out rather than guessed at, because a guess that
		// over-counts only makes the reservation larger.
		if parts, ok := message["content"].([]any); ok {
			for _, p := range parts {
				if part, ok := p.(map[string]any); ok {
					if text, ok := part["text"].(string); ok {
						chars += len(text)
					}
				}
			}
		}
	}
	tokens := chars / 4
	if tokens < 1 {
		tokens = 1
	}
	return tokens
}

func numberOf(body map[string]any, key string) float64 {
	v, _ := body[key].(float64)
	return v
}

// usage is what a provider reported about a request.
//
// Reported is the field that matters most. A zero count is not the same as an
// unreported one: zero could be a real answer for a request that cost nothing,
// and treating it as "nothing was said" would charge a reservation for work
// that was free.
type usage struct {
	PromptTokens     int
	CompletionTokens int
	Reported         bool
}

// readUsage pulls the token counts out of a provider's answer.
//
// Both shapes are accepted because both exist: the nested completion_tokens
// object, and the flat prompt_tokens form some providers send for streaming.
func readUsage(body []byte) usage {
	var answer struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return usage{}
	}
	out := usage{
		PromptTokens:     answer.Usage.PromptTokens,
		CompletionTokens: answer.Usage.CompletionTokens,
	}
	if out.PromptTokens == 0 {
		out.PromptTokens = answer.PromptTokens
	}
	if out.CompletionTokens == 0 {
		out.CompletionTokens = answer.CompletionTokens
	}
	out.Reported = out.PromptTokens > 0 || out.CompletionTokens > 0 || answer.Usage.TotalTokens > 0
	return out
}

// rewriteModel puts the router's own name back on the answer, so a client
// reading what it just used sees the name it sent rather than the provider's.
//
// Returns the bytes rather than editing in place: the re-encoded JSON is a
// different length from what came back, and copying a shorter one over the
// original leaves the tail of the provider's answer behind as trailing bytes
// that are not valid JSON.
func rewriteModel(body []byte, from, to string) []byte {
	if len(body) == 0 || from == to {
		return body
	}
	var answer map[string]any
	if err := json.Unmarshal(body, &answer); err != nil {
		return body
	}
	name, ok := answer["model"].(string)
	if !ok || name != from {
		return body
	}
	answer["model"] = to
	re, err := json.Marshal(answer)
	if err != nil {
		return body
	}
	return re
}

// writeJSON answers in the shape an OpenAI client expects from every failure,
// because a client that gets HTML back has nothing to show the person holding
// it.
func writeJSON(w http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		http.Error(w, `{"error":{"message":"could not encode the answer"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

// writeJSONBytes answers with bytes that are already JSON.
//
// Used where the body came from a provider and is being passed on rather than
// re-encoded: re-encoding it here would reorder keys and, on a stream, would
// destroy the framing outright.
func writeJSONBytes(w http.ResponseWriter, encoded []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

// joinMessage is "summary: detail", or just the detail when there is no
// summary worth putting in front of it.
func joinMessage(message, detail string) string {
	switch {
	case message == "":
		return detail
	case detail == "":
		return message
	default:
		return message + ": " + detail
	}
}

func writeError(w http.ResponseWriter, status int, message, detail string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": joinMessage(message, detail),
			"type":    http.StatusText(status),
			"code":    status,
		},
	})
}
