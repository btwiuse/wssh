// Command wsshd serves an SSH session over a WebSocket.
//
// The port lives here and nowhere else: wssh.Server is an http.Handler, and
// this command is the thin piece that binds a socket to it and shuts it down
// again on a signal.
//
//	ssh -o 'ProxyCommand=websocat -b wss://host:port' user@host
package main

import (
	"context"
	"errors"
	"flag"
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

// shutdownTimeout bounds how long live sessions get to finish.
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

	server, err := wssh.NewServer(wssh.Options{
		HostKeyPath:        *hostKey,
		Middleware:         []wish.Middleware{shell.Middleware()},
		Pty:                true,
		AllowTcpForwarding: *forward,
	})
	if err != nil {
		log.Fatal("could not create server", "error", err)
	}
	if *forward {
		log.Warn("TCP forwarding enabled: clients can relay to any host this server can reach")
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal("could not listen", "address", *addr, "error", err)
	}

	// http.Serve runs the HTTP/1.1 upgrade exchange on our listener. There is
	// no http.Server value holding configuration or lifecycle state: closing
	// the listener is what stops the server.
	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "address", listener.Addr().String(), "scheme", "websocket")
		serveErr <- http.Serve(listener, server)
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signals:
		log.Info("shutting down", "signal", sig.String())
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listener stopped", "error", err)
		}
	}

	// Stop accepting before draining, so no session starts while we shut down.
	if err := listener.Close(); err != nil {
		log.Debug("could not close listener", "error", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Error("could not stop server", "error", err)
	}
}

// defaultAddr is the listen address when -addr is not given.
//
// Hosted platforms inject the port to bind through the PORT environment
// variable (Railway, Heroku and friends all do this), and a hardcoded port
// would just fail to bind behind their router.
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

// defaultHostKey is where the server's ed25519 host key lives.
//
// The key is generated on first run and must stay stable. On a platform with
// an ephemeral filesystem, point HOST_KEY at a mounted volume.
func defaultHostKey() string {
	if path := os.Getenv("HOST_KEY"); path != "" {
		return path
	}
	return "host_ed25519"
}
