// Package cafe is RouterCafe: an OpenRouter-shaped API, paid for in SOL, and
// reached by connecting to a terminal rather than by opening a page.
//
// The one thing this package exists to guarantee is that a session is a
// program and not a command line. `ssh -A router.cafe` opens a full-screen UI
// showing a balance, an API key, and a way to deposit; nothing typed at it is
// ever run. That is a design constraint rather than a missing feature, so it is
// worth being concrete about how it is enforced, because "we did not write a
// shell handler" is not on its own a guarantee:
//
//   - Nothing in this package starts a process. No exec.Command, no
//     os.StartProcess, no $SHELL, anywhere in cafe/ - and
//     TestThePackageCannotStartAProcess reads this package's own source and
//     fails if one appears. os/exec does reach the binary, pulled in
//     transitively by bubbletea and lipgloss, but nothing here calls it: the
//     one exec in the whole binary is `openBrowser` in cmd/cafe, which runs
//     at startup against an operator's own --open flag and is not reachable
//     from a connection.
//   - s.RawCommand is never read for anything but this sentence. A client that
//     sends `ssh router.cafe uptime` gets that uptime printed back at it as a
//     refusal and a non-zero exit status. It does not get the program it asked
//     for, and it does not get the UI either, because a caller running a
//     command deserves an answer rather than a screenful it has to recognise
//     as a refusal.
//   - Subsystem requests - sftp, scp, anything under a subsystem name - are
//     refused outright. There are no files here to transfer.
//   - The direct-tcpip channel is never installed, so `ssh -L` and `ssh -D` have
//     nothing to open, and cmd/cafe does not offer the flag that would.
//
// What a session *can* do is draw a UI, read and write the ledger, and ask the
// agent it was handed for a signature on a transaction it then checks.
package cafe

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/log/v2"
	"charm.land/ssh"
	"charm.land/wish/v2"
	wishtea "charm.land/wish/v2/bubbletea"
	"github.com/btwiuse/wssh"
	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/solana"
	gossh "golang.org/x/crypto/ssh"
)

// Options is what a RouterCafe server is made of. Configured by the caller and
// handed to one constructor, the same shape as every other Options in this
// repository.
type Options struct {
	// Ledger holds the accounts. Required.
	Ledger *Ledger

	// Treasury is where deposits go and what they are worth. Required:
	// without an address there is nowhere to send the money.
	Treasury Treasury

	// Catalogue is the routing table. Nil means DefaultCatalogue.
	Catalogue *Catalogue

	// Logger receives session-level detail. Nil means the charm default.
	Logger *log.Logger
}

// Server is the session side of RouterCafe: the middleware that turns a
// connection into a UI rather than into a shell.
type Server struct {
	opts Options
}

// New builds the session server.
func New(opts Options) (*Server, error) {
	if opts.Ledger == nil {
		return nil, fmt.Errorf("a router needs a ledger to keep balances in")
	}
	if strings.TrimSpace(opts.Treasury.Address) == "" {
		return nil, fmt.Errorf("a router needs a treasury address to take deposits into")
	}
	if err := ValidateAddress(opts.Treasury.Address); err != nil {
		return nil, fmt.Errorf("the treasury address: %w", err)
	}
	if opts.Catalogue == nil {
		opts.Catalogue = DefaultCatalogue()
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	return &Server{opts: opts}, nil
}

// Catalogue is the routing table, for the caller that also serves /v1.
func (s *Server) Catalogue() *Catalogue { return s.opts.Catalogue }

// Ledger is the accounts, for the caller that also serves /v1.
func (s *Server) Ledger() *Ledger { return s.opts.Ledger }

// Middleware is what wish calls middleware: the handler every session gets.
//
// The order note matters here as much as it does anywhere else. Whatever is
// appended after this in the middleware slice runs first, and agentkey.Forward
// has to: it publishes SSH_AUTH_SOCK on the connection, and the deposit screen
// is useless without it. cmd/cafe wires it as []Middleware{cafe, Forward}.
func (s *Server) Middleware() wish.Middleware {
	ui := wishtea.Middleware(s.handler())
	return func(next ssh.Handler) ssh.Handler {
		inner := ui(next)
		return func(sess ssh.Session) {
			// A subsystem is not a terminal: sftp, scp, anything under a
			// subsystem name. Refused rather than passed on, because nothing
			// behind this would want one either, and a session that silently
			// did nothing looks like a failure somewhere else.
			if name := sess.Subsystem(); name != "" {
				s.opts.Logger.Debug("subsystem refused", "subsystem", name, "remote", remoteOf(sess))
				wish.Fatalln(sess, "RouterCafe has no subsystems: it has no files to transfer. "+
					"Run 'ssh -A "+Domain+"' for the session UI.")
				return
			}

			// A command is not run. Not quoted into a shell, not looked up on
			// a PATH, not handed anywhere. Saying so and exiting non-zero is
			// the honest answer: a caller that wanted a command is told there
			// are none, in the same breath, rather than being handed a
			// screenful of UI it has to recognise as a refusal.
			if cmd := strings.TrimSpace(sess.RawCommand()); cmd != "" {
				s.opts.Logger.Info("command refused", "command", cmd, "remote", remoteOf(sess))
				fmt.Fprintf(sess.Stderr(),
					"RouterCafe does not run commands. %q was not executed.\n"+
						"Open the session UI with: ssh -A %s\n", cmd, Domain)
				_ = sess.Exit(1)
				return
			}

			inner(sess)
		}
	}
}

func remoteOf(sess ssh.Session) string {
	if addr := sess.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return "unknown"
}

// handler builds the Bubble Tea handler.
//
// Split out from Middleware so the UI can be driven in a test with a session
// that is not a session at all.
func (s *Server) handler() wishtea.Handler {
	return func(sess ssh.Session) (tea.Model, []tea.ProgramOption) {
		return s.newModel(sess), wishtea.MakeOptions(sess)
	}
}

// newModel works out which account this session is and builds its UI.
func (s *Server) newModel(sess ssh.Session) tea.Model {
	address, refusal := SessionAccount(sess)
	if refusal != "" {
		// No account, no session. Not a degraded mode to paper over with a
		// placeholder: an account is what a deposit credits and what a
		// balance belongs to, and a session with neither must not be handed a
		// UI showing zeros it might act on.
		return refuseModel{refusal}
	}

	sockPath, _ := sess.Context().Value(agentkey.SSHAuthSockKey).(string)

	return model{
		deps: deps{
			Address:   address,
			SockPath:  sockPath,
			Ctx:       sess.Context(),
			Ledger:    s.opts.Ledger,
			Treasury:  s.opts.Treasury,
			Catalogue: s.opts.Catalogue,
			Host:      Domain,
		},
		st:      newStyles(),
		view:    screenHome,
		account: s.opts.Ledger.Account(address),
		width:   80,
		height:  24,
	}
}

// SessionAccount is the Solana account a session belongs to.
//
// Two ways in, and the choice between them is not a preference:
//
//   - the key that authenticated the session, read through solana.AddressFor.
//     An ed25519 SSH key is already a Solana account, so this is a rename
//     rather than a lookup, and it is the right answer for a session that came
//     in through ssh -A.
//   - the account a wallet proved over the WebSocket sign-in, for a browser
//     that owns no SSH key. See wssh.WalletAddress.
//
// The SSH username is never consulted. It is chosen by the client, so every
// account would be the same account.
//
// A key that is not ed25519 names no account, and that is said out loud rather
// than left blank: it is the difference between "use an ed25519 key" and
// something that looks like a bug.
func SessionAccount(sess ssh.Session) (string, string) {
	return AccountFor(sess.PublicKey(), wssh.WalletAddress(sess.Context()))
}

// AccountFor is the naming rule on its own, without a session.
//
// Split out so it can be exercised directly: whether a given key names an
// account is the question, and answering it needs a session only as a way of
// holding two values.
func AccountFor(pub gossh.PublicKey, walletAddress string) (string, string) {
	if wallet := strings.TrimSpace(walletAddress); wallet != "" {
		return wallet, ""
	}
	if pub == nil {
		// No key and no wallet: the connection got through unauthenticated.
		// That cannot happen while a key handler is installed, so it is said
		// as what it is rather than assumed to be a key that is not there.
		return "", "this connection did not authenticate with a key, so it names no account"
	}
	address, err := solana.AddressFor(pub)
	if err != nil {
		return "", "this session has no account: " + err.Error() +
			"\n\nRouterCafe accounts are Solana accounts, and an account address is an " +
			"ed25519 public key. Make one with 'ssh-keygen -t ed25519' and connect with it."
	}
	return address, ""
}

// refuseModel is what a session with no account gets: one screen, one key, and
// an exit.
//
// A plain program rather than a TUI, because there is nothing to browse and a
// full-screen UI for an error is a worse way to be told something than a line
// of text.
type refuseModel struct{ reason string }

func (r refuseModel) Init() tea.Cmd { return nil }

func (r refuseModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "q", "ctrl+c", "esc", "enter":
			return r, tea.Quit
		}
	}
	return r, nil
}

func (r refuseModel) View() tea.View {
	st := newStyles()
	return tea.NewView("\n  " + st.brand.Render("RouterCafe") + "\n\n  " +
		st.errText.Render(r.reason) + "\n\n  " + st.dim.Render("press q to disconnect") + "\n")
}

// DepositContext is the context a session's deposits run under.
//
// The session's own context rather than a background one, so a client hanging
// up cancels a signature it is no longer there to approve. That is the whole
// reason it is threaded through rather than defaulting: a deposit waiting on a
// wallet prompt that nobody will ever answer should stop when the session ends,
// not hold a goroutine and a connection until the five-minute bound.
func DepositContext(sess ssh.Session) context.Context { return sess.Context() }
