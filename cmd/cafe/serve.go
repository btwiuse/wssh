package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"charm.land/log/v2"
	"charm.land/wish/v2"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth"
	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
	"github.com/btwiuse/wssh/cafe"
	"github.com/btwiuse/wssh/webui"
	"github.com/spf13/cobra"
)

// The default prices.
//
// Authentication is off in wssh and on here, both of them "*", and that is not
// a contradiction: a session is a program that shows a balance, so accepting
// every key costs nothing and refusing every key would make the product
// unusable. What "*" means here is "anyone may hold an account", which is the
// dapp model - see auth.AnyKey and siws.AnyAddress, which say the same thing
// about themselves.
//
// The blast radius of that is zero only because of the things this command
// does not install. There is no shell middleware, no direct-tcpip handler and
// no subsystem handler, so a connection that got in has nothing to run.
const (
	// defaultSolPriceMicroUSD is what one SOL buys, in micro-USD. A starting
	// point for an operator to replace, not a quote: every deposit records
	// the rate it was credited at, so changing this never rewrites history.
	defaultSolPriceMicroUSD cafe.MicroUSD = 200 * cafe.PerMicroUSD

	// defaultSessionPath is where the browser terminal keeps its sessions. It
	// is not "/", because the landing page is there.
	defaultSessionPath = "/ws"

	// defaultAppPath is where the browser terminal is mounted.
	defaultAppPath = "/app"

	// anyOrigin is --origins '*'. The page is served by this same process and
	// the sessions are on this same process, so there is nothing to restrict
	// against; and an empty list would reject every browser while still
	// letting ssh(1) through, which is the one setting where the two differ.
	anyOrigin = "*"
)

type serveOptions struct {
	// Addr is the HTTP/WebSocket address. Empty means $PORT, then :8080.
	Addr string

	// TCPAddr, when set, is an extra plain-TCP SSH listener, so `ssh -p PORT
	// host` reaches the same sessions a WebSocket client would.
	TCPAddr string

	// HostKeyPath is the ed25519 host key, generated on first use. It has to
	// stay stable across restarts or every client reports a mismatch.
	HostKeyPath string

	// SessionPath is the WebSocket session endpoint.
	SessionPath string

	// AppPath is where the browser terminal is mounted.
	AppPath string

	// Origins restricts which browser origins may open a session.
	Origins []string

	// Auth decides which SSH keys may connect. Defaults to "*".
	Auth auth.Config

	// AuthorizedAddresses are Solana accounts allowed to sign in over the
	// browser's wallet sign-in. Defaults to "*".
	AuthorizedAddresses []string

	// WalletStatement is the one line a wallet shows above a sign-in.
	WalletStatement string

	// ForwardAgent is whether sessions may ask the connecting client to
	// sign. On by default: it is how a deposit is signed at all.
	ForwardAgent bool

	// Treasury is where deposits go.
	Treasury cafe.Treasury

	// SolPriceMicroUSD is what one SOL buys, in micro-USD.
	SolPriceMicroUSD cafe.MicroUSD

	// LedgerPath is the file the accounts live in.
	LedgerPath string

	// Upstream is the provider's API root.
	Upstream string

	// UpstreamKey is the provider's credential.
	UpstreamKey string

	// MaxReserveMicroUSD bounds what one request may hold against a balance.
	MaxReserveMicroUSD cafe.MicroUSD

	// DryRunDeposits takes deposits without moving money: the amount is
	// priced and shown and nothing is signed or broadcast. For a public
	// instance that is obviously not the setting; it is here so the whole
	// flow can be walked through against a devnet, or with no RPC at all,
	// before a treasury address exists.
	DryRunDeposits bool

	// ShutdownTimeout is how long live sessions get after an interrupt.
	ShutdownTimeout time.Duration

	// OpenBrowser points the user's browser at the landing page.
	OpenBrowser bool
}

func addServeFlags(cmd *cobra.Command, opts *serveOptions) {
	cmd.PersistentFlags().BoolVar(debug, "verbose", false, "log session-level detail")

	cmd.Flags().StringVar(&opts.Addr, "addr", "", "address to listen on (default $PORT or :8080)")
	cmd.Flags().StringVar(&opts.TCPAddr, "tcp-addr", "",
		"also listen on this address for plain TCP/SSH, so `ssh -p PORT host` reaches the same sessions")
	cmd.Flags().StringVar(&opts.HostKeyPath, "hostkey", defaultHostKey(), "path to the ed25519 host key")
	cmd.Flags().StringVar(&opts.SessionPath, "path", defaultSessionPath, "URL path sessions are served on")
	cmd.Flags().StringVar(&opts.AppPath, "app-path", defaultAppPath, "path the browser terminal is mounted at")
	cmd.Flags().StringSliceVar(&opts.Origins, "origins", []string{anyOrigin},
		"browser origins allowed to open a session; '$ALLOWED_ORIGINS' sets this too")
	cmd.Flags().BoolVar(&opts.OpenBrowser, "open", false, "open the landing page once it is up")
	cmd.Flags().DurationVar(&opts.ShutdownTimeout, "shutdown-timeout", 5*time.Second,
		"how long live sessions get to finish after an interrupt; 0 waits forever")

	cmd.Flags().StringVar(&opts.Treasury.Address, "treasury", "",
		"the Solana account deposits are sent to; required, or $ROUTERCAFE_TREASURY")
	cmd.Flags().StringVar(&opts.Treasury.RPC, "rpc", cafe.DefaultRPC,
		"JSON-RPC endpoint for deposits: blockhash, broadcast and confirmation")
	cmd.Flags().Float64Var(&solPriceFlag, "sol-price", 200,
		"what one SOL buys in US dollars; recorded per deposit, so changing it never rewrites history")

	cmd.Flags().StringVar(&opts.LedgerPath, "ledger", defaultLedgerPath(),
		"file the accounts and balances live in; $ROUTERCAFE_LEDGER sets this")
	cmd.Flags().StringVar(&opts.Upstream, "upstream", "",
		"the provider's API root, e.g. https://api.openai.com/v1; without it no route can be served")
	cmd.Flags().StringVar(&opts.UpstreamKey, "upstream-key", "",
		"the provider's credential; this is what callers spend their balance on, never their own key")
	cmd.Flags().Int64Var(&maxReserveFlag, "max-reserve-usd", 5,
		"the most one request may hold against a balance while it is in flight")
	cmd.Flags().BoolVar(&opts.DryRunDeposits, "dry-run-deposits", false,
		"price and show deposits without signing or broadcasting anything")

	cmd.Flags().StringSliceVar(&opts.Auth.Keys, "authorized-key", []string{auth.AnyKey},
		`authorized_keys entries to accept; "*" (the default) accepts any key at all`)
	cmd.Flags().StringSliceVar(&opts.Auth.KeyFiles, "authorized-keys", nil,
		`authorized_keys files to accept; "*" accepts any key, "system" means the usual locations`)
	cmd.Flags().StringSliceVar(&opts.AuthorizedAddresses, "authorized-addresses", []string{siws.AnyAddress},
		"Solana accounts allowed to sign in from a browser wallet; '*' (the default) accepts any")
	cmd.Flags().StringVar(&opts.WalletStatement, "wallet-statement", "",
		"one line of text a wallet shows above the sign-in request")

	cmd.Flags().BoolVar(&opts.ForwardAgent, "forward-agent", true,
		"let sessions ask the connecting client to sign; this is how a deposit is signed, "+
			"and turning it off leaves the deposit screen with nothing to ask")
}

// The two flags that are not a simple string or bool get a variable to bind
// to, because pflag will not write into a field of a struct it cannot name.
// solPriceFlag is in dollars and opts.SolPriceMicroUSD is in micro-USD, which
// is why the conversion happens once, in serve, rather than at every use.
var (
	solPriceFlag   float64
	maxReserveFlag int64
)

func serve(opts *serveOptions) error {
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	opts.SolPriceMicroUSD = cafe.MicroUSD(solPriceFlag * float64(cafe.PerMicroUSD))
	opts.MaxReserveMicroUSD = cafe.MicroUSD(maxReserveFlag * cafe.PerMicroUSD)
	opts.Treasury.SolPriceUSD = opts.SolPriceMicroUSD

	if opts.Treasury.Address == "" {
		opts.Treasury.Address = os.Getenv("ROUTERCAFE_TREASURY")
	}
	if opts.Treasury.Address == "" {
		return errors.New("--treasury is required: there is nowhere to send deposits without it, " +
			"or set $ROUTERCAFE_TREASURY")
	}
	if opts.DryRunDeposits {
		// The address still has to parse, because the point of a dry run is
		// to walk the flow that a real one takes; a treasury that is not an
		// address would fail later at the last step instead.
		if err := cafe.ValidateAddress(opts.Treasury.Address); err != nil {
			return fmt.Errorf("the treasury address: %w", err)
		}
	}
	if raw := os.Getenv("ALLOWED_ORIGINS"); raw != "" && len(opts.Origins) == 1 && opts.Origins[0] == anyOrigin {
		opts.Origins = strings.Split(raw, ",")
	}

	ledger, err := cafe.OpenLedger(opts.LedgerPath)
	if err != nil {
		return err //nolint:wrapcheck
	}

	sessions, err := cafe.New(cafe.Options{
		Ledger:    ledger,
		Treasury:  opts.Treasury,
		Catalogue: cafe.DefaultCatalogue(),
	})
	if err != nil {
		return err //nolint:wrapcheck
	}
	router, err := cafe.NewRouter(cafe.RouterOptions{
		Ledger:             ledger,
		Catalogue:          sessions.Catalogue(),
		Upstreams:          upstreamsFrom(opts),
		MaxReserveMicroUSD: opts.MaxReserveMicroUSD,
		Logger:             log.Default(),
	})
	if err != nil {
		return err //nolint:wrapcheck
	}

	walletAuth, err := buildWalletAuth(opts)
	if err != nil {
		return err
	}
	authOpts, err := opts.Auth.Options()
	if err != nil {
		return err //nolint:wrapcheck
	}

	// Forward appended, not prepended: wish composes middleware from first to
	// last with the last one outermost, so putting it here is what makes it
	// run before the session UI. It has to: the UI asks that socket for a
	// signature the moment somebody presses enter on the deposit screen.
	//
	// There is no shell middleware in this list and there is not going to be
	// one. See package cafe.
	middleware := []wish.Middleware{sessions.Middleware()}
	if opts.ForwardAgent {
		middleware = append(middleware, agentkey.Forward())
	}

	sshServer, err := wssh.NewServer(wssh.Options{
		HostKeyPath:    opts.HostKeyPath,
		Middleware:     middleware,
		ForwardAgent:   opts.ForwardAgent,
		Pty:            true,
		Path:           opts.SessionPath,
		OriginPatterns: opts.Origins,
		WalletAuth:     walletAuth,
		SSHOptions:     authOpts,
		// AllowTcpForwarding is deliberately absent and is not a flag:
		// direct-tcpip lets a client name any destination and this server
		// dials it, which on a public host is an open proxy into whatever
		// the host can reach. There is no configuration in which this
		// server wants that.
	})
	if err != nil {
		return err //nolint:wrapcheck
	}

	mux := http.NewServeMux()

	// The landing page first, at the root, and only the root. Everything
	// else falls through to the paths below.
	mux.Handle("/", landingHandler(opts))

	// The router: what the API keys are for.
	mux.Handle("/v1/", http.StripPrefix("/v1", router.Handler()))

	// The browser terminal, under /app, with every feature it has always
	// had: imported keys, a connected wallet, the approval prompt, agent
	// forwarding, a one-shot command field. It reaches the same sessions as
	// ssh(1) does, so it shows the same program - which is the point of
	// keeping it.
	assets := webui.Assets()
	if webui.MissingWasm(assets) {
		log.Warn("no ssh.wasm in the browser terminal: /app will load but cannot connect. " +
			"Build it with 'go generate ./...' or 'make'")
	}
	mux.Handle(opts.AppPath+"/", appHandler(assets, opts))

	// Sessions. WebSocket first, then the optional plain-TCP listener.
	mux.Handle(opts.SessionPath, sshServer)

	var tcpListener net.Listener
	if opts.TCPAddr != "" {
		// Returned as it is: net.Listen already says which address and why,
		// and wrapping it again prints the same sentence twice.
		ln, err := net.Listen("tcp", opts.TCPAddr)
		if err != nil {
			return err //nolint:wrapcheck
		}
		tcpListener = ln
	}

	listener, err := net.Listen("tcp", listenAddr(opts.Addr))
	if err != nil {
		return err //nolint:wrapcheck
	}

	server := &http.Server{
		Handler: mux,
		// A header timeout, and no write timeout: a session is a long-lived
		// stream and any write deadline would cut an idle but open terminal.
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("serving",
			"address", listener.Addr().String(),
			"landing", "http://"+browserHost(listener.Addr())+"/",
			"terminal", "http://"+browserHost(listener.Addr())+opts.AppPath+"/",
			"sessions", opts.SessionPath,
			"treasury", opts.Treasury.Address,
			"solPrice", cafe.FormatUSD(opts.SolPriceMicroUSD))
		serveErr <- server.Serve(listener)
	}()

	if tcpListener != nil {
		log.Info("listening", "address", tcpListener.Addr().String(), "scheme", "tcp/ssh")
		go func() {
			if err := sshServer.ServeTCP(tcpListener); err != nil {
				log.Warn("tcp listener stopped", "error", err)
			}
		}()
	}

	// Worth saying out loud: the documented way in is `ssh -A router.cafe`,
	// which is plain SSH on port 22 and is not what the HTTP listener answers.
	// Without this line an operator starts the server, reads the landing page,
	// runs the command the page tells them to, and gets an HTTP 400 from a
	// port that looks like it should be SSH.
	if tcpListener == nil {
		log.Info("plain SSH is not listening: `ssh -A router.cafe` needs --tcp-addr :22, " +
			"or a WebSocket proxy in front of /ws")
	}

	if opts.OpenBrowser {
		// The listener is bound, so the browser queues in the backlog rather
		// than arriving before Serve.
		openBrowser("http://" + browserHost(listener.Addr()) + "/")
	}

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	var runErr error
	select {
	case sig := <-signals:
		log.Info("shutting down", "signal", sig.String(), "grace", opts.ShutdownTimeout)
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err //nolint:wrapcheck
		}
	}

	// Stop accepting from both before draining, so no session starts while we
	// are shutting down.
	if err := listener.Close(); err != nil {
		log.Debug("could not close the listener", "error", err)
	}
	if tcpListener != nil {
		_ = tcpListener.Close() //nolint:errcheck
	}
	if runErr != nil {
		return runErr
	}
	return drain(sshServer, signals, opts.ShutdownTimeout)
}

// drain waits for live sessions to finish, but not indefinitely.
//
// A session is a program waiting for a keypress, so it never ends by itself;
// without a bound every interrupt would look like a hang. A second signal
// abandons the rest.
func drain(sessions *wssh.Server, signals <-chan os.Signal, grace time.Duration) error {
	done := make(chan error, 1)
	go func() {
		if grace <= 0 {
			done <- sessions.Shutdown(context.Background())
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		done <- sessions.Shutdown(ctx)
	}()

	select {
	case err := <-done:
		return err //nolint:wrapcheck
	case sig := <-signals:
		log.Warn("second signal, dropping live sessions", "signal", sig.String())
		return nil
	}
}

// upstreamsFrom builds the routing table's provider map.
//
// One entry, called "default", whatever provider it turns out to be: a
// catalogue route names a provider, and every route in the default catalogue
// resolves to this one. An operator running several providers sets the
// provider's own name here and points the routes at it.
func upstreamsFrom(opts *serveOptions) cafe.Upstreams {
	if strings.TrimSpace(opts.Upstream) == "" {
		return cafe.Upstreams{}
	}
	return cafe.Upstreams{"default": cafe.Upstream{
		Name:    "default",
		BaseURL: opts.Upstream,
		Key:     opts.UpstreamKey,
	}}
}

// buildWalletAuth turns the flags into the verifier, or nil when nothing is
// configured.
func buildWalletAuth(opts *serveOptions) (*siws.SIWSAuth, error) {
	if len(opts.AuthorizedAddresses) == 0 {
		return nil, nil
	}
	addresses, open, err := siws.ParseAuthorizedAddresses(opts.AuthorizedAddresses)
	if err != nil {
		return nil, err
	}
	if !open && len(addresses) == 0 {
		return nil, nil
	}
	statement := opts.WalletStatement
	if statement == "" {
		statement = "Sign in to RouterCafe"
	}
	return &siws.SIWSAuth{Addresses: addresses, Open: open, Statement: statement}, nil
}

func listenAddr(addr string) string {
	if addr != "" {
		return addr
	}
	port := os.Getenv("PORT")
	if port == "" {
		return ":8080"
	}
	if strings.HasPrefix(port, ":") {
		return port
	}
	return ":" + port
}

// browserHost turns a listen address into something worth pasting into a bar.
// A wildcard bind has no host to show, so localhost stands in for it.
func browserHost(addr net.Addr) string {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

// defaultLedgerPath is where the accounts live.
//
// $ROUTERCAFE_LEDGER first, because an ephemeral filesystem is the normal
// deployment and a ledger that is rebuilt empty on every deploy is every
// balance back to zero.
func defaultLedgerPath() string {
	if path := os.Getenv("ROUTERCAFE_LEDGER"); path != "" {
		return path
	}
	return "routercafe.json"
}

// defaultHostKey is the server's ed25519 host key. Generated on first run and
// then never changed, because changing it makes every client report a mismatch.
func defaultHostKey() string {
	if path := os.Getenv("HOST_KEY"); path != "" {
		return path
	}
	return "host_ed25519"
}

// openBrowser opens a URL in the user's default browser. Not being able to is
// not a reason to take the server down, so failures are only logged.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Debug("could not open a browser", "error", err, "url", url)
		return
	}
	go func() { _ = cmd.Wait() }()
}
