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
	"charm.land/lipgloss/v2"
	"charm.land/log/v2"
	"charm.land/ssh"
	"charm.land/wish/v2"
	wishtea "charm.land/wish/v2/bubbletea"
	"github.com/routercafe/routercafe"
	"github.com/routercafe/routercafe/auth/agentkey"
	"github.com/routercafe/routercafe/solana"
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

	// AllowAnonymous lets a session in that proved nothing.
	//
	// Only safe together with the forwarded agent, and the two go together:
	// admitting a connection that carries no key means admitting every
	// connection that way, so identity has to come from the agent signing.
	// A session with an agent adopts a key out of it; a session without one
	// is told how to get that and given nothing else. See anonymous.go.
	AllowAnonymous bool

	// Version is what the help screen says this server is. Empty means the
	// server was built without one and the line is left off, rather than
	// printing the word the ldflags would have replaced.
	Version string

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

// who is the identity a session arrived with, taken apart so the UI can be
// built without one.
//
// A local run has no SSH handshake and therefore no authenticated key, no
// username and no wallet - which is exactly the shape of a connection that
// proved nothing. Pulling these apart is what lets one constructor serve both
// rather than there being a second copy of the rules that decides which
// account somebody is looking at.
type who struct {
	pub    gossh.PublicKey
	wallet string
	user   string

	// sock is the agent this session may ask to sign, and empty means it has
	// none. Over SSH it is the socket the client forwarded; locally it is the
	// agent already running on the machine.
	sock string

	// local says there is no other end: this program was started on the
	// terminal it is drawing on, rather than arriving over a connection. It
	// changes wording, not behaviour - the rules about proof are the same
	// either way, and making them different would be the one place where
	// running locally could be more permissive than running for real.
	local bool

	ctx context.Context
}

// newModel works out which account this session is and builds its UI.
func (s *Server) newModel(sess ssh.Session) tea.Model {
	sockPath, _ := sess.Context().Value(agentkey.SSHAuthSockKey).(string)
	return s.modelFor(who{
		pub:    sess.PublicKey(),
		wallet: wssh.WalletAddress(sess.Context()),
		user:   sess.User(),
		sock:   sockPath,
		ctx:    sess.Context(),
	})
}

// modelFor builds the UI for an identity, with no session involved.
func (s *Server) modelFor(w who) tea.Model {
	sockPath := w.sock

	// A connection that arrived with no key at all, checked first because
	// it is the one case where there is nothing to refuse: there was no
	// credential to turn away. It gets the screen that adopts a key out of a
	// forwarded agent, or says how to get one.
	//
	// A connection that brought a key of the wrong type is not in this
	// branch. It has proved it holds something, and telling that person to go
	// and make a different key is the answer; anonymous access is for people
	// who arrived with nothing, not with the wrong thing.
	if s.opts.AllowAnonymous && w.pub == nil &&
		w.wallet == "" && !namesAnAccount(w.user) {
		return anonymousModel{
			deps: deps{
				SockPath:  sockPath,
				Local:     w.local,
				Ctx:       w.ctx,
				Ledger:    s.opts.Ledger,
				Treasury:  s.opts.Treasury,
				Catalogue: s.opts.Catalogue,
				Host:      Domain,
				Version:   s.opts.Version,
			},
			st:     newStyles(),
			width:  80,
			height: 24,
		}
	}

	address, refusal, proven := AccountFor(w.pub, w.wallet, w.user)
	if refusal != "" {
		// No account, no session. Not a degraded mode to paper over with a
		// placeholder: an account is what a deposit credits and what a
		// balance belongs to, and a session with neither must not be handed a
		// UI showing zeros it might act on.
		return refuseModel{reason: refusal, width: 80, height: 24}
	}

	m := model{
		deps: deps{
			Address:   address,
			Proven:    proven,
			SockPath:  sockPath,
			Local:     w.local,
			Ctx:       w.ctx,
			Ledger:    s.opts.Ledger,
			Treasury:  s.opts.Treasury,
			Catalogue: s.opts.Catalogue,
			Host:      Domain,
			Version:   s.opts.Version,
		},
		st:      newStyles(),
		view:    screenHome,
		account: s.opts.Ledger.Account(address),
		width:   80,
		height:  24,
	}
	// The two lists are built here rather than lazily on first visit, so that
	// arriving at one is not the thing that discovers there is no catalogue.
	m.syncLists()
	return m
}

// namesAnAccount reports whether a username is written as an account address,
// which is the one thing the client chooses that can mean something here.
func namesAnAccount(user string) bool {
	return strings.TrimSpace(user) != "" && ValidateAddress(strings.TrimSpace(user)) == nil
}

// SessionAccount is the account a session names, and whether it proved it.
//
// Three ways in, and the difference between them is the whole of what a
// session may do:
//
//   - a wallet that signed in over the WebSocket. Proved.
//   - the key that authenticated the session, read through solana.AddressFor.
//     An ed25519 SSH key is already a Solana account, so this is a rename
//     rather than a lookup. Proved, because holding the key is the proof.
//   - the username, when it is written as a Solana address. Named, not proved:
//     the client chose it, so it can only ever mean "show me this account".
//
// That last one exists because admitting a connection with no key admits every
// connection that way, and a service that turns those away is a service that
// refuses to answer the question. Addressing an account the way git addresses a
// repository costs nothing and gets somebody with no key to the screen they
// wanted. It buys exactly one thing: a view.
//
// So "proved" is not decoration. Anything that changes an account - spending
// its balance, minting a key against it - requires it, or `ssh
// <someone-else's-address>@host` would hand that person a key to spend with.
// AccountFor is the naming rule on its own, without a session.
//
// Split out so it can be exercised directly: whether a given connection names
// an account is the question, and answering it needs a session only as a way
// of holding three values.
//
// The order below is the order of how much the client proved, not of how much
// was asked for. The username is read before the key because a connection
// almost always carries one now - refusing "none" is what lets the server see
// a key at all - and if the key won, `ssh <someone-else>@host` would silently
// open the account of whoever happened to be holding the connection instead of
// the one that was asked for. A name in the username is the client asking for
// a view, and it gets one.
func AccountFor(pub gossh.PublicKey, walletAddress, user string) (string, string, bool) {
	if wallet := strings.TrimSpace(walletAddress); wallet != "" {
		// A wallet proved itself by signing something a person read.
		return wallet, "", true
	}

	// Chosen by the client, so it names an account to look at and nothing else.
	if named := strings.TrimSpace(user); named != "" {
		if err := ValidateAddress(named); err == nil {
			return named, "", false
		}
	}

	if pub != nil {
		address, err := solana.AddressFor(pub)
		if err != nil {
			return "", "not an ed25519 key: " + reasonText(err.Error()), false
		}
		return address, "", true
	}

	return "", reasonText("no key on this connection"), false
}

// refuseModel is what a session with no account gets: what went wrong, the
// command that fixes it, and a key that leaves.
//
// A plain program rather than the full-screen one, because there is nothing to
// browse and a whole terminal UI for an error is a worse way to be told
// something than a few lines of text.
//
// The wording is broken into short lines on purpose. A single long sentence
// handed to a narrow terminal is hard-wrapped by the terminal itself, with no
// indent and in the middle of words, which is indistinguishable from the UI
// having crashed - which is the impression this screen most needs not to give.
type refuseModel struct {
	reason string
	width  int
	height int
}

func (r refuseModel) Init() tea.Cmd { return nil }

func (r refuseModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.width, r.height = msg.Width, msg.Height
		return r, nil
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc", "enter":
			return r, tea.Quit
		}
	}
	return r, nil
}

func (r refuseModel) View() tea.View {
	st := newStyles()
	width := r.width
	if width <= 0 {
		// A session that never reported a size: the common default rather
		// than a guess, and wide enough that nothing is cut.
		width = 80
	}
	var b strings.Builder
	b.WriteString("  " + wrapText(r.reason, bodyWidth(width), st.errText))
	b.WriteString("\n")
	b.WriteString(wrapText("make a key, then connect with it:", bodyWidth(width), st.title))
	b.WriteString("\n\n")
	b.WriteString(wrapText(KeyCommand, bodyWidth(width), st.accent))
	b.WriteString("\n\n")
	b.WriteString(wrapText("then:", bodyWidth(width), st.title))
	b.WriteString("\n\n")
	b.WriteString(wrapText("ssh -A -i ~/.ssh/routercafe "+Domain, bodyWidth(width), st.accent))
	b.WriteString("\n\n")
	// Same chrome as every other screen, so a refusal reads as this program
	// refusing rather than as a different program that happens to share a name.
	//
	// The height falls back to a default because a refusal is the answer to a
	// handshake and there is no reason for a size to have arrived by the time
	// it is drawn.
	height := r.height
	if height <= 0 {
		height = refusalHeight
	}
	return ownedView(frame(st, width, height, "",
		strings.TrimRight(b.String(), "\n"),
		"  "+st.dim.Render("q to disconnect")))
}

// refusalHeight is the height a refusal is drawn at when no size has arrived.
const refusalHeight = 24

// KeyCommand is the line that fixes it, and the line after it that uses it.
//
// Shown whenever a session names no account, because a person who just typed
// ssh and got this screen wants to know what to type next rather than a
// paragraph about why ed25519 and Solana are the same thing. Wrapped to the
// terminal like everything else here, so a narrow window cuts nothing: a
// half-printed command is the one thing this screen must never show.
const KeyCommand = "ssh-keygen -t ed25519 -f ~/.ssh/routercafe -N ''"

// reasonText turns a refusal into the sentence the person reads.
//
// Both cases are written out rather than derived, because each half of it is
// advice and the advice differs: no key at all is a missing step, while a key
// of the wrong type is a step that has to be redone differently. Both end on
// the same two commands.
func reasonText(reason string) string {
	switch {
	case strings.HasPrefix(reason, "no key on this connection"):
		return "This connection carried no key.\n\n" +
			"An account here is an ed25519 public key, so the key you connect\n" +
			"with is the account your balance belongs to. Nothing here can\n" +
			"guess which one you meant."
	case strings.HasPrefix(reason, "not an ed25519 key:"):
		return "This key does not name an account.\n\n" +
			"An account is exactly an ed25519 public key. An RSA or ECDSA\n" +
			"key is not one and cannot be turned into one, so this session\n" +
			"has nothing to show you and nothing to charge."
	default:
		return reason
	}
}

// wrapText breaks styled text into lines that fit width, indented to match the
// rest of the interface, and re-styled line by line.
//
// Broken on a space where there is one and on a character where there is not,
// so an address or a command survives being narrow even though a sentence
// does not have to. The main screen wraps the same way for the same reason.
func wrapText(s string, width int, style lipgloss.Style) string {
	// The two-space indent is a luxury, and it is the first thing to go: on a
	// narrow terminal it costs a path two columns it may well need. Inside the
	// box the width is already the inside, so giving the indent back is what
	// lets an eighteen-character key path still fit on a twenty-column screen.
	indent := 2
	if width < 24 {
		indent = 0
	}
	avail := width - indent
	if avail < 12 {
		avail = 12
	}
	var out strings.Builder
	for _, paragraph := range strings.Split(s, "\n") {
		lines := wrapWords(paragraph, avail)
		if len(lines) == 0 {
			out.WriteString("\n")
			continue
		}
		for _, line := range lines {
			out.WriteString(strings.Repeat(" ", indent) + style.Render(line) + "\n")
		}
	}
	return strings.TrimRight(out.String(), "\n")
}

// wrapWords is a plain-text wrapper: greedy, and never losing a word.
func wrapWords(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var out []string
	line := ""
	for _, word := range words {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			out = append(out, line)
			line = word
		}
		// A single word longer than the line is cut rather than dropped, so
		// a very narrow terminal shows a mangled path instead of none.
		for len(line) > width {
			out = append(out, line[:width])
			line = line[width:]
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

// DepositContext is the context a session's deposits run under.
//
// The session's own context rather than a background one, so a client hanging
// up cancels a signature it is no longer there to approve. That is the whole
// reason it is threaded through rather than defaulting: a deposit waiting on a
// wallet prompt that nobody will ever answer should stop when the session ends,
// not hold a goroutine and a connection until the five-minute bound.
func DepositContext(sess ssh.Session) context.Context { return sess.Context() }
