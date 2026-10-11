// Package webui serves the browser terminal: the xterm + React page, the
// worker that hosts the Go/WASM SSH client, and the wallet side of a Solana
// signing request.
//
// It is a package rather than a directory under cmd/wssh because two binaries
// embed it. go:embed can only see files inside the package's own directory, so
// a second binary wanting the same front end has to import the one that owns
// it rather than reach across for a copy. wssh serves it at /, and RouterCafe
// serves it at /app/ behind its own landing page; the files are the same and
// stay the same.
//
// The wasm binary itself is not committed: it is a build artefact of
// client/build.sh, and this package's go:generate directive runs that. A build
// made before it exists still compiles, because the embed covers a directory
// rather than a list of files, so MissingWasm is the only place the mistake is
// still visible before someone opens a terminal and watches the worker die on
// a 404.
package webui

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"charm.land/log/v2"
)

//go:generate bash ../client/build.sh
//go:embed all:static
var embedded embed.FS

// SessionPathPlaceholder is replaced in index.html with the configured session
// endpoint. The page resolves it against its own URL, so one build works on
// localhost, behind a relay, or on a domain with nothing reconfigured.
const SessionPathPlaceholder = "__WSSH_SESSION_PATH__"

// Assets returns the embedded front end, stripped of the directory holding it
// so it can be mounted at a path root.
func Assets() fs.FS {
	assets, err := fs.Sub(embedded, "static")
	if err != nil {
		// Unreachable: the embed directive above guarantees the directory.
		panic(err)
	}
	return assets
}

// MissingWasm reports whether the browser client is absent from the embedded
// assets. The embed succeeds either way, so this is the only place the mistake
// is still visible before someone opens a terminal.
func MissingWasm(assets fs.FS) bool {
	_, err := fs.Stat(assets, "ssh.wasm")
	return err != nil
}

// Handler serves the front end, telling the page where its session endpoint is.
//
// The page resolves that relative to wherever it was loaded from rather than
// being handed an absolute address, so the same build is correct on localhost,
// behind a relay, or on a domain.
func Handler(assets fs.FS, sessionPath string) http.Handler {
	if assets == nil {
		// A nil file system is a programming mistake, and taking the process
		// down with it would be the worst possible way to report one: this
		// server also holds live sessions. Saying so on the page is enough.
		log.Error("the browser front end was asked for with no assets")
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "This build has no browser front end in it.", http.StatusInternalServerError)
		})
	}
	files := http.FileServer(http.FS(assets))
	if sessionPath == "" {
		sessionPath = "/ws"
	}
	page, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		log.Debug("could not read index.html to template it", "error", err)
		return noCache(files)
	}
	templated := strings.ReplaceAll(string(page), SessionPathPlaceholder, sessionPath)

	return noCache(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the page itself is templated. Every other file is served as it
		// is, so a stale copy of app.js cannot survive a rebuild by being
		// rewritten here.
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			files.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, templated)
	}))
}

// noCache keeps the browser from holding on to a stale wasm binary after a
// rebuild, which otherwise shows up as a baffling version mismatch.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
