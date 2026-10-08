// Command webssh serves a browser front end and the WebSocket endpoint that
// front end connects to.
//
// Both halves live in one process on one port:
//
//	/     the terminal UI (xterm.js driving a Go/WebAssembly SSH client)
//	/ws   the SSH sessions themselves, via wssh.Server
//
// The browser never speaks SSH. It loads a Go binary compiled to
// WebAssembly, which dials /ws and runs a real SSH client inside the page. The
// server is unchanged from wsshd: the WebSocket is just a byte pipe, and the
// SSH protocol is spoken on either side of it.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"charm.land/log/v2"
	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/shell"
)

//go:embed all:static
var static embed.FS

const shutdownTimeout = 30 * time.Second

func main() {
	addr := flag.String("addr", defaultAddr(), "address to listen on")
	hostKey := flag.String("hostkey", defaultHostKey(), "path to the ed25519 host key")
	forward := flag.Bool("allow-tcp-forwarding", false, "allow ssh -L/-D port forwarding (open proxy unless restricted)")
	debug := flag.Bool("debug", false, "log session-level detail")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	// A browser always sends an Origin header; ssh(1) and websocat never do.
	// This narrows who can reach the page from a browser at all. During
	// development the session is still unauthenticated, so it is a filter,
	// not access control.
	var originPatterns []string
	if origins := os.Getenv("ALLOWED_ORIGINS"); origins != "" {
		originPatterns = strings.Split(origins, ",")
		log.Info("restricting origins", "patterns", originPatterns)
	}

	server, err := wssh.NewServer(wssh.Options{
		HostKeyPath:        *hostKey,
		Middleware:         []wish.Middleware{shell.Middleware()},
		Pty:                true,
		AllowTcpForwarding: *forward,
		OriginPatterns:     originPatterns,
	})
	if err != nil {
		log.Fatal("could not create server", "error", err)
	}
	if *forward {
		log.Warn("TCP forwarding enabled: clients can relay to any host this server can reach")
	}

	mux := http.NewServeMux()
	mux.Handle("/ws", server)
	mux.Handle("/", staticHandler())

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal("could not listen", "address", *addr, "error", err)
	}

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: an SSH session is a long-lived stream and any
		// write deadline would sever an idle-but-open shell.
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "address", listener.Addr().String())
		serveErr <- httpServer.Serve(listener)
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signals:
		log.Info("shutting down", "signal", sig.String())
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server stopped", "error", err)
		}
	}

	if err := httpServer.Close(); err != nil {
		log.Debug("could not close listener", "error", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Error("could not stop server", "error", err)
	}
}

// staticHandler serves the embedded front end.
func staticHandler() http.Handler {
	assets, err := fs.Sub(static, "static")
	if err != nil {
		log.Fatal("could not open embedded assets", "error", err)
	}
	files := http.FileServer(http.FS(assets))
	return noCache(files)
}

// noCache keeps the browser from holding on to a stale wasm binary after a
// rebuild, which otherwise shows up as a confusing version mismatch.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func defaultAddr() string {
	port := os.Getenv("PORT")
	if port == "" {
		return ":8080"
	}
	if strings.HasPrefix(port, ":") {
		return port
	}
	return ":" + port
}

func defaultHostKey() string {
	if path := os.Getenv("HOST_KEY"); path != "" {
		return path
	}
	return "host_ed25519"
}
