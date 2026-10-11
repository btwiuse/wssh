package main

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/routercafe/routercafe/webui"
)

// The browser terminal, mounted under /app.
//
// It is the same front end wssh serves at its root, from the same embedded
// files, reached by the same session endpoint. Everything it has always had is
// here: imported keys, a connected wallet, the approval prompt that shows a
// transaction as YAML before a person signs it, agent forwarding, and the
// one-shot command field.
//
// It reaches the same sessions ssh(1) does, so what a person gets is the same
// program whichever way they arrived. That is deliberate. Serving a shell
// behind this path and a UI behind the ssh one would mean the browser was the
// way in, and the whole design here is that there is no way in.
func appHandler(assets fs.FS, opts *serveOptions) http.Handler {
	// RouterCafe's own mark rather than wssh's. The page is wssh's, but the
	// tab it opens in belongs to the product somebody reached router.cafe
	// for, and a green shell prompt is not that.
	terminal := webui.Handler(assets, opts.SessionPath, FaviconURL)
	prefix := strings.TrimSuffix(opts.AppPath, "/")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /app without the trailing slash would resolve every relative asset
		// against the root rather than against /app/, so the page would load
		// and then fail to find app.js. A redirect rather than a rewrite,
		// because a rewrite would make /app and /app/ two URLs for one page.
		if r.URL.Path == prefix {
			http.Redirect(w, r, prefix+"/", http.StatusMovedPermanently)
			return
		}
		http.StripPrefix(prefix, terminal).ServeHTTP(w, r)
	})
}
