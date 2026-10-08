package wssh

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"charm.land/wish/v2"
	"github.com/btwiuse/wssh/shell"
)

// newTestServer builds a server with a throwaway host key.
func newTestServer(t *testing.T, path string) *Server {
	t.Helper()
	server, err := NewServer(Options{
		HostKeyPath: filepath.Join(t.TempDir(), "host_ed25519"),
		Path:        path,
		Middleware:  []wish.Middleware{shell.Middleware()},
		Pty:         true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

// upgradeReq is shaped like a WebSocket upgrade so it gets past any path check
// and as far as the handshake itself.
func upgradeReq(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	return req
}

// A bare SSH server has nothing else on the port, so sessions belong on every
// path rather than one conventional one: a client may as well dial the host
// alone, the way `websocat -b wss://host` does.
func TestAnyPathOpensSessionByDefault(t *testing.T) {
	server := newTestServer(t, "")

	for _, path := range []string{"/", "/ws", "/anything", "/deep/nested/path"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, upgradeReq(path))

			// The handshake then fails with 501, because a recorder is not
			// a real connection and cannot be hijacked. That is the signal:
			// a path check answers 404 and never reaches the handshake at all.
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("path %q: got %d, want the handler to be reached", path, rec.Code)
			}
		})
	}
}

func TestConfiguredPathIsExclusive(t *testing.T) {
	server := newTestServer(t, "/ws")

	for _, path := range []string{"/", "/elsewhere", "/ws/nested"} {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, upgradeReq(path))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("path %q: got %d, want 404", path, rec.Code)
		}
	}
}

// The front end serves static files from the same port, so sessions need a
// path of their own. This is the arrangement the web subcommand relies on.
func TestWebLayoutKeepsSessionsOffTheAssets(t *testing.T) {
	server := newTestServer(t, "/ws")
	mux := http.NewServeMux()
	mux.Handle("/ws", server)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("page"))
	}))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/index.html", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("asset request: got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "page") {
		t.Fatalf("asset request reached the wrong handler: %q", rec.Body.String())
	}
}
