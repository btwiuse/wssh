package webui_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/btwiuse/wssh/webui"
)

// Two binaries serve these files: wssh at its root, RouterCafe under /app.
// The second one is the reason this is a package rather than a directory under
// cmd/wssh, so the tests here are about the shared behaviour both rely on.

func TestAssetsAreThereAndIncludeTheWasm(t *testing.T) {
	assets := webui.Assets()
	for _, want := range []string{"index.html", "app.js", "worker.js", "ssh.wasm", "wasm_exec.js"} {
		if _, err := fs.Stat(assets, want); err != nil {
			t.Errorf("%s is not in the embedded assets: %v", want, err)
		}
	}
	if webui.MissingWasm(assets) {
		t.Error("MissingWasm says the wasm is absent from a built tree")
	}
}

// The page is told where its sessions are, and the placeholder is replaced
// rather than served. A page that reaches the server for the placeholder
// string connects to nothing and says nothing about why.
func TestHandlerTemplatesTheSessionPath(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	webui.Handler(webui.Assets(), "/sessions", "").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, webui.SessionPathPlaceholder) {
		t.Error("the page was served with the placeholder still in it")
	}
	if !strings.Contains(body, `"/sessions"`) {
		t.Errorf("the page does not carry the session path: %q", firstLines(body, 20))
	}
}

// Every other file is served as it is. Templating them too would rewrite a
// cached app.js on every rebuild and produce a version mismatch that looks
// like a bug somewhere else.
func TestOtherFilesAreServedUntouched(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	webui.Handler(webui.Assets(), "/sessions", "").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), webui.SessionPathPlaceholder) {
		t.Error("app.js was templated")
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "javascript") {
		t.Errorf("app.js has content type %q", got)
	}
}

// The wasm is a build artefact and changes on every rebuild; a cached one is
// a runtime ABI mismatch that surfaces as an unexplained web error.
func TestHandlerDoesNotCache(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	webui.Handler(webui.Assets(), "/ws", "").ServeHTTP(rec, req)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control is %q, want no-store", got)
	}
}

// An empty path still has to become something: the page resolves this
// relative to its own URL, and a bare "" resolves to the page itself.
func TestHandlerDefaultsTheSessionPath(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	webui.Handler(webui.Assets(), "", "").ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), webui.SessionPathPlaceholder) {
		t.Error("an empty session path left the placeholder in the page")
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " | ")
}

// A binary serving this front end can put its own mark on the tab. Without
// that, every product built on these files wears wssh's prompt, which is
// wrong for anything that is not wssh.
func TestHandlerTakesAFavicon(t *testing.T) {
	rec := httptest.NewRecorder()
	webui.Handler(webui.Assets(), "/ws", "/favicon.ico").ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	if strings.Contains(body, webui.FaviconPlaceholder) {
		t.Error("the favicon placeholder reached the page")
	}
	if !strings.Contains(body, `href="/favicon.ico"`) {
		t.Errorf("the page does not carry the icon it was given: %q", firstLines(body, 20))
	}

	// And wssh's own still comes out when nothing is given, so the default
	// lives in one place rather than in the page.
	rec = httptest.NewRecorder()
	webui.Handler(webui.Assets(), "/ws", "").ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rec.Body.String(), "image/svg+xml") {
		t.Error("an empty favicon did not fall back to wssh's own")
	}
}

var _ http.Handler = webui.Handler(nil, "", "")
