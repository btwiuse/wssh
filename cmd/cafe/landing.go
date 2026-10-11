package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"charm.land/log/v2"
	"github.com/btwiuse/wssh/cafe"
)

// The landing page.
//
// It is also the pitch deck, which is the reason it exists as a page rather
// than a README: the product is a terminal, and a terminal you cannot see is
// a hard thing to be sold. So the page shows one: a terminal window with the
// session UI drawn in it, running the same words the real one prints, with
// nothing fetched to make it work.
//
// The embedded directory covers the whole page rather than a list of files, so
// the same mistake wssh has about a missing wasm is available here too: the
// build succeeds and the page is blank. LandingMissing is the check.
//
//go:embed all:static
var landing embed.FS

// LandingMissing reports whether the landing page failed to embed.
//
// A go:embed of a directory that does not exist is a compile error, so this is
// really about the page being there but empty, which is what a stale checkout
// or a bad copy produces.
func LandingMissing() bool {
	info, err := fs.Stat(landing, "static/index.html")
	return err != nil || info.Size() == 0
}

// landingHandler serves the page at the root and nowhere else.
//
// The "/only is deliberate: this is a product's front door, not a file server,
// and a path that does not exist should say so rather than serving the same
// marketing to every URL a crawler invents.
func landingHandler(opts *serveOptions) http.Handler {
	page, err := fs.ReadFile(landing, "static/index.html")
	if err != nil {
		log.Warn("the landing page is not embedded; serving a placeholder", "error", err)
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "RouterCafe is running, but its landing page is missing from this build.", http.StatusInternalServerError)
		})
	}

	var treasury string
	if err := cafe.ValidateAddress(opts.Treasury.Address); err == nil {
		treasury = opts.Treasury.Address
	}
	body := string(page)
	body = strings.ReplaceAll(body, "__ROUTERCAFE_TREASURY__", escapeHTML(treasury))
	body = strings.ReplaceAll(body, "__ROUTERCAFE_SOL_PRICE__",
		escapeHTML(strconv.FormatFloat(solPriceFlag, 'f', -1, 64)))
	body = strings.ReplaceAll(body, "__ROUTERCAFE_UPSTREAM__", escapeHTML(upstreamName(opts.Upstream)))

	templated := []byte(body)
	files := http.FileServer(http.FS(subStatic(landing)))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Anything that is not the page itself is a 404 rather than the
		// marketing again: this host serves the API, the terminal and this
		// one document, and pretending otherwise only makes a typo look
		// like a working link.
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			if strings.HasPrefix(r.URL.Path, "/index.html/") {
				http.NotFound(w, r)
				return
			}
			files.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Not cached. The page carries the treasury and the price, and a
		// cached one would show a deposit address an operator has moved
		// money off.
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(templated)
	})
}

func subStatic(f fs.FS) fs.FS {
	sub, err := fs.Sub(f, "static")
	if err != nil {
		// Unreachable: the embed directive above guarantees the directory.
		panic(err)
	}
	return sub
}

// escapeHTML is what stops a configured address from being able to close a tag
// and put its own markup on the page. It is not paranoid: the treasury address
// comes from an operator's command line, and this is the one place a value
// reaches HTML without going through a template engine that would escape it.
func escapeHTML(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func upstreamName(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if i := strings.Index(trimmed, "://"); i >= 0 {
		trimmed = trimmed[i+3:]
	}
	// The trailing slash is dropped too: what belongs on a page is the host a
	// reader would recognise, not the exact string a config file holds.
	return strings.TrimSuffix(trimmed, "/")
}
