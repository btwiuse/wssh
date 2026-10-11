package cafe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// The session UI.
//
// This is the whole of what `ssh -A router.cafe` gives you: a balance, an API
// key, a way to put money in, and the price list. It is a Bubble Tea program
// rather than a shell, and that is the load-bearing decision of the whole
// server - see session.go, which is what decides that no session can run a
// command. Nothing in this file starts a process, reads a file, or opens a
// socket other than the agent it was handed.
//
// The layout is the terminal.shop shape: full screen, a few single-letter
// views, and the current numbers always on screen. A person who has never seen
// it should be able to press "?" and know what every key does.

// Domain is where this thing lives. It appears in the header and in the copy
// a key is meant to be pasted into, so it is one constant rather than a string
// repeated in five views.
const Domain = "router.cafe"

type screen int

const (
	screenHome screen = iota
	screenDeposit
	screenKeys
	screenModels
	screenHelp
)

type styles struct {
	brand    lipgloss.Style
	brandDim lipgloss.Style
	label    lipgloss.Style
	value    lipgloss.Style
	money    lipgloss.Style
	dim      lipgloss.Style
	accent   lipgloss.Style
	warn     lipgloss.Style
	key      lipgloss.Style
	box      lipgloss.Style
	title    lipgloss.Style
	errText  lipgloss.Style
	okText   lipgloss.Style
}

func newStyles() styles {
	return styles{
		brand:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#34d399")),
		brandDim: lipgloss.NewStyle().Foreground(lipgloss.Color("#334155")),
		label:    lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b")),
		value:    lipgloss.NewStyle().Foreground(lipgloss.Color("#e2e8f0")),
		money:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f8fafc")),
		dim:      lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b")),
		accent:   lipgloss.NewStyle().Foreground(lipgloss.Color("#38bdf8")),
		warn:     lipgloss.NewStyle().Foreground(lipgloss.Color("#fbbf24")),
		key:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#34d399")),
		title:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#e2e8f0")),
		errText:  lipgloss.NewStyle().Foreground(lipgloss.Color("#f87171")),
		okText:   lipgloss.NewStyle().Foreground(lipgloss.Color("#34d399")),
		box:      lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#1e293b")).Padding(0, 1),
	}
}

// deps is everything the model needs from the server, handed over rather than
// reached for, so the whole thing is constructible in a test with four fields
// and no server at all.
type deps struct {
	// Address is the account this session is looking at.
	Address string

	// Proven is whether this session owns it, as against having merely named
	// it. A key that authenticated the session, or a wallet that signed in,
	// owns it; a username written as an address only names it.
	//
	// Everything read-only works either way. Everything that changes the
	// account - spending its balance, minting a key against it - is refused
	// without it, because otherwise `ssh <address>@host` hands that address's
	// owner to whoever typed it.
	Proven bool

	// SockPath is the agent this session was given. Empty means the client
	// did not forward one, which is a thing to say out loud rather than to
	// discover when a deposit refuses.
	SockPath string

	Ledger    *Ledger
	Treasury  Treasury
	Catalogue *Catalogue

	// Host is the name the session reached us at, used in the copy a key is
	// pasted into.
	Host string

	// Ctx is the session's context, so a deposit stops when the client hangs
	// up rather than holding a goroutine until its own deadline.
	Ctx context.Context
}

// ctx returns the context a deposit runs under, falling back to the background
// context only for a model built without a session - which is a test.
func (d deps) ctx() context.Context {
	if d.Ctx != nil {
		return d.Ctx
	}
	return context.Background()
}

// model is the Bubble Tea model for one session.
//
// A value type, as Bubble Tea wants: Update returns a new one and the old one
// is discarded, so there is nothing to keep in step by hand and nothing another
// goroutine can be mutating underneath.
type model struct {
	deps deps
	st   styles

	view    screen
	account Account
	width   int
	height  int

	// amount is the text being typed on the deposit screen. A plain string
	// rather than a bubbles textinput: it is one field with three keys
	// against it, and a whole input widget for that is more dependency than
	// the job needs.
	amount string

	// busy and notice are the two states a long operation passes through.
	// busy is a sentence saying what is being waited on, because a deposit
	// asks the client's own agent and a wallet prompt can take a person a
	// while, and a frozen screen during that reads as a hang.
	busy   string
	notice notice

	// fresh is the key this session just minted, held only for as long as the
	// notice displaying it is on screen.
	//
	// The ledger keeps a SHA-256 of every key and never the key itself, so
	// this is the only copy that will ever exist: `y` can copy it, and once
	// the notice is gone there is nothing left to copy. That is the whole
	// reason copying is a keystroke on this screen rather than a column in
	// the keys list - and also why forgetting to copy is cheap: mint another.
	fresh string
}

// to leaves the current screen, taking the notice with it.
//
// fresh goes at the same time as the notice that displays it, deliberately,
// so that "y copies it" and "you can see it" can never disagree.
func (m *model) to(view screen) {
	m.view, m.notice, m.fresh = view, notice{}, ""
}

type noticeKind int

const (
	noticeNone noticeKind = iota
	noticeGood
	noticeBad
)

type notice struct {
	kind noticeKind
	text string
}

func (m model) Init() tea.Cmd {
	// An account named by username is a view. When an agent was forwarded as
	// well, ask it whether it holds that address's key: if it does, and it
	// signs for it, this session owns the account and may change it.
	if !m.deps.Proven && m.deps.SockPath != "" && m.deps.Address != "" {
		return proveCmd(m.deps.SockPath, m.deps.Address)
	}
	return nil
}

func (m model) View() tea.View {
	var v tea.View
	v.AltScreen = true
	v.WindowTitle = "RouterCafe"
	v.SetContent(m.render())
	return v
}

// refreshCmd reloads the account from the ledger.
//
// Every view reads the account rather than keeping a copy, and every mutation
// is followed by one of these. A balance that is stale is worse than one that
// is briefly wrong while it reloads, because the person looking at it has no
// way to tell.
func refreshCmd(d deps) tea.Cmd {
	return func() tea.Msg {
		return refreshedMsg{account: d.Ledger.Account(d.Address)}
	}
}

type refreshedMsg struct{ account Account }

// depositFinishedMsg carries the outcome of a deposit back to the model.
//
// The deposit runs on its own goroutine because it waits on a client that may
// be a person answering a wallet prompt, and blocking Update would freeze the
// screen for exactly as long as that takes.
type depositFinishedMsg struct {
	receipt DepositReceipt
	err     error
}

type keyMintedMsg struct {
	key string
	err error
}

type keyRevokedMsg struct {
	label string
	ok    bool
	err   error
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case provenMsg:
		// Silent either way. An agent that does not hold the key is the
		// ordinary case for somebody looking at someone else's balance, and
		// saying so on a screen they are only reading would be noise.
		if msg.proven {
			m.deps.Proven = true
		}
		return m, nil

	case refreshedMsg:
		m.account = msg.account
		return m, nil

	case depositFinishedMsg:
		m.busy = ""
		if msg.err != nil {
			m.notice = notice{noticeBad, msg.err.Error()}
		} else if msg.receipt.Pending {
			m.notice = notice{noticeGood, fmt.Sprintf(
				"dry run: %s would have bought %s of credit. Nothing was signed, sent, or charged",
				solText(msg.receipt.Lamports), FormatUSD(msg.receipt.Credits))}
		} else {
			m.notice = notice{noticeGood, fmt.Sprintf(
				"%s arrived and bought %s of credit. Signature %s",
				solText(msg.receipt.Lamports), FormatUSD(msg.receipt.Credits),
				shortSig(msg.receipt.Signature))}
			m.view = screenHome
			m.amount = ""
		}
		return m, refreshCmd(m.deps)

	case keyMintedMsg:
		m.busy = ""
		if msg.err != nil {
			m.notice = notice{noticeBad, msg.err.Error()}
			return m, nil
		}
		m.fresh = msg.key
		m.notice = notice{noticeGood, "new key: " + msg.key +
			"  — this is the only time it is shown; press y to copy it, or put it somewhere safe"}
		return m, refreshCmd(m.deps)

	case keyRevokedMsg:
		m.busy = ""
		switch {
		case msg.err != nil:
			m.notice = notice{noticeBad, msg.err.Error()}
		case !msg.ok:
			m.notice = notice{noticeBad, "that key was not on file"}
		default:
			m.notice = notice{noticeGood, "revoked " + msg.label}
		}
		return m, refreshCmd(m.deps)

	case tea.KeyPressMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m model) onKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// ^C always quits, whatever is on screen: a person holding a wallet
	// prompt needs a way out that does not depend on which view they
	// wandered into.
	if msg.String() == "ctrl+c" {
		return m, tea.Quit
	}

	if m.view == screenDeposit {
		return m.onDepositKey(msg)
	}

	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "y":
		return m.copyFreshKey()
	case "b", "home":
		m.to(screenHome)
	case "d":
		m.to(screenDeposit)
	case "k":
		if !m.deps.Proven {
			m.notice = notice{noticeBad, notOwned}
			return m, nil
		}
		m.to(screenKeys)
	case "m", "p":
		m.to(screenModels)
	case "?", "h":
		m.to(screenHelp)
	case "r":
		// A reload is a key because the balance is somebody's money and
		// they should be able to make it re-read without reconnecting.
		return m, refreshCmd(m.deps)
	case "esc":
		m.to(screenHome)
	}

	// Keys are numbered so that revoking one is a keystroke and not a
	// sub-menu: the screen shows which number is which, and there is no
	// second place for the mapping to live.
	if m.view == screenKeys {
		if msg.String() == "n" {
			return m.mintKey()
		}
		if i, err := strconv.Atoi(msg.String()); err == nil {
			return m.revokeKey(i)
		}
	}
	return m, nil
}

// copyFreshKey puts the key this session just minted on the clipboard.
//
// OSC 52, which is what tea.SetClipboard emits and the only mechanism a
// terminal offers for this: there is no way for a program running over SSH to
// reach the machine's clipboard by any other route. Not every terminal honours
// it, and a few ask permission first, so the message says what was asked for
// rather than claiming the clipboard now holds it - the program genuinely
// cannot tell.
//
// A key that was minted earlier is not copyable, because the ledger kept a
// digest and threw the key away. That is said plainly rather than left to look
// like a broken keystroke.
func (m model) copyFreshKey() (tea.Model, tea.Cmd) {
	if m.fresh == "" {
		m.notice = notice{noticeBad, noKeyToCopy}
		return m, nil
	}
	m.notice = notice{noticeGood, "sent to the clipboard as OSC 52: " + m.fresh +
		"  — if it did not paste, this terminal does not honour OSC 52"}
	return m, tea.SetClipboard(m.fresh)
}

const noKeyToCopy = "no key on screen to copy. One is shown once, when it is " +
	"minted: press n on the api keys screen and press y straight away."

func (m model) mintKey() (tea.Model, tea.Cmd) {
	if !m.deps.Proven {
		return m.refuse(notOwned)
	}
	d := m.deps
	m.busy = "minting an API key"
	// The previous key's one chance to be copied is over: minting another
	// replaces it on screen, and the ledger never kept it either way.
	m.notice, m.fresh = notice{}, ""
	return m, func() tea.Msg {
		key, err := d.Ledger.MintKey(d.Address, "")
		return keyMintedMsg{key: key, err: err}
	}
}

func (m model) revokeKey(oneBased int) (tea.Model, tea.Cmd) {
	idx := oneBased - 1
	if idx < 0 || idx >= len(m.account.Keys) {
		m.notice = notice{noticeBad, fmt.Sprintf("there is no key %d; the list above is numbered", oneBased)}
		return m, nil
	}
	d := m.deps
	key := m.account.Keys[idx]
	m.busy = "revoking " + key.Label
	m.notice = notice{}
	return m, func() tea.Msg {
		ok, err := d.Ledger.RevokeKey(d.Address, key.Digest)
		return keyRevokedMsg{label: key.Label, ok: ok, err: err}
	}
}

func (m model) onDepositKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.view, m.amount, m.notice = screenHome, "", notice{}
		return m, nil
	case "enter":
		return m.startDeposit()
	case "backspace":
		if len(m.amount) > 0 {
			r := []rune(m.amount)
			m.amount = string(r[:len(r)-1])
		}
		return m, nil
	}

	// Anything printable goes into the amount. Filtered to characters that can
	// be part of a number rather than accepted and rejected later, so there is
	// no state in which the field holds something that cannot be parsed.
	if len(msg.Text) == 1 {
		if c := msg.Text[0]; (c >= '0' && c <= '9') || c == '.' {
			m.amount += string(c)
		}
	}
	return m, nil
}

func (m model) startDeposit() (tea.Model, tea.Cmd) {
	if !m.deps.Proven {
		return m.refuse(notOwned)
	}
	lamports, err := parseSOL(m.amount)
	if err != nil {
		m.notice = notice{noticeBad, err.Error()}
		return m, nil
	}
	d := m.deps
	m.busy = "waiting for a signature from your agent — approve it where it asks you to"
	m.notice = notice{}
	return m, func() tea.Msg {
		receipt, err := Deposit(d.ctx(), d.Ledger, d.Treasury, d.Address, d.SockPath, lamports)
		return depositFinishedMsg{receipt: receipt, err: err}
	}
}

// parseSOL reads what somebody typed as an amount of SOL.
//
// Parsed as a string and scaled by hand rather than through ParseFloat,
// because the result has to be a whole number of lamports that rounds towards
// zero: a float would let 0.1 + 0.2 style drift reach a transaction, and this
// is an amount of money.
func parseSOL(text string) (uint64, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, fmt.Errorf("type an amount of SOL first, or press esc to go back")
	}
	whole, frac, hasFrac := strings.Cut(trimmed, ".")
	if whole == "" {
		whole = "0"
	}
	if hasFrac && (frac == "" || strings.Contains(frac, ".")) {
		return 0, fmt.Errorf("that is not an amount: %q", text)
	}
	for _, part := range []string{whole, frac} {
		for _, c := range part {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("that is not an amount: %q", text)
			}
		}
	}
	// Nine digits is a whole SOL; anything longer is a number of lamports
	// somebody typed by mistake, and truncating it silently would deposit a
	// different amount than the one on screen.
	if len(frac) > 9 {
		return 0, fmt.Errorf("SOL has nine decimal places; %q has more", text)
	}
	w, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("that amount is too large to send: %w", err)
	}
	padded := frac + strings.Repeat("0", 9-len(frac))
	f, err := strconv.ParseUint(padded, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("that amount is too large to send: %w", err)
	}
	if w > (1<<64-1-f)/1_000_000_000 {
		return 0, fmt.Errorf("that amount is larger than can be sent in one transaction")
	}
	return w*1_000_000_000 + f, nil
}

func (m model) render() string {
	var b strings.Builder
	b.WriteString(m.header())
	if !m.deps.Proven && m.deps.Address != "" {
		b.WriteString("\n  " + m.st.warn.Render("read-only: this address was named, not proved") + "\n")
	}
	b.WriteString("\n\n")

	switch m.view {
	case screenDeposit:
		b.WriteString(m.renderDeposit())
	case screenKeys:
		b.WriteString(m.renderKeys())
	case screenModels:
		b.WriteString(m.renderModels())
	case screenHelp:
		b.WriteString(m.renderHelp())
	default:
		b.WriteString(m.renderHome())
	}

	if m.busy != "" {
		b.WriteString("\n\n  " + m.st.warn.Render(m.busy) + "\n")
	}
	if m.notice.kind != noticeNone {
		b.WriteString("\n")
		switch m.notice.kind {
		case noticeGood:
			b.WriteString(m.wrap(m.st.okText.Render(m.notice.text), m.st.okText))
		default:
			b.WriteString(m.wrap(m.st.errText.Render(m.notice.text), m.st.errText))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n" + m.footer())
	return b.String()
}

func (m model) header() string {
	left := m.st.brand.Render("RouterCafe")
	right := m.st.dim.Render(Domain)
	gap := m.contentWidth() - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return "  " + left + strings.Repeat(" ", gap) + right
}

func (m model) footer() string {
	binding := m.st.key.Render("b") + m.st.dim.Render(" balance  ") +
		m.st.key.Render("d") + m.st.dim.Render(" deposit  ") +
		m.st.key.Render("k") + m.st.dim.Render(" api key  ") +
		m.st.key.Render("m") + m.st.dim.Render(" models  ") +
		m.st.key.Render("r") + m.st.dim.Render(" refresh  ")
	// Only while there is something to copy. A y that is always offered and
	// usually refused is a keystroke people learn to ignore.
	if m.fresh != "" {
		binding += m.st.key.Render("y") + m.st.dim.Render(" copy key  ")
	}
	binding += m.st.key.Render("?") + m.st.dim.Render(" help  ") +
		m.st.key.Render("q") + m.st.dim.Render(" quit")
	return "  " + binding
}

func (m model) renderHome() string {
	var b strings.Builder
	acct := m.account
	b.WriteString(m.field("account", m.shortAddress(acct.Address)))
	b.WriteString(m.field("balance", m.st.money.Render(FormatUSD(acct.Balance))))
	b.WriteString(m.field("paid in", FormatUSD(acct.Deposits)))
	b.WriteString(m.field("spent", FormatUSD(acct.Spent)))

	if !m.deps.Proven {
		b.WriteString("\n\n  " + m.st.dim.Render("keys are only shown to whoever holds the account's key") + "\n")
	} else if len(acct.Keys) == 0 {
		b.WriteString("\n\n  " + m.st.warn.Render("no API key yet") + "\n")
		b.WriteString("  " + m.st.dim.Render("press k to mint one, then point any OpenAI client at https://"+m.endpointHost()) + "\n")
	} else {
		b.WriteString("\n\n  " + m.st.title.Render("api keys") + "\n")
		for _, k := range acct.Keys {
			b.WriteString("  " + m.st.accent.Render("rc_live_"+k.Label) +
				m.st.dim.Render("   last used "+ago(k.Touched)) + "\n")
		}
	}

	b.WriteString("\n  " + m.st.title.Render("use it") + "\n")
	b.WriteString("  " + m.st.dim.Render("export OPENAI_BASE_URL=https://"+m.endpointHost()+"/v1") + "\n")
	b.WriteString("  " + m.st.dim.Render("export OPENAI_API_KEY=rc_live_…") + "\n")

	b.WriteString("\n  " + m.st.title.Render("cheapest routes") + "\n")
	models := m.deps.Catalogue.Models()
	for i, route := range models {
		if i >= 3 {
			break
		}
		b.WriteString("  " + pad(m.st.value.Render(route.ID), 24) +
			pad(m.st.dim.Render(route.Provider), 12) +
			m.st.dim.Render(perMTok(route.InputPerMTok)+" in, "+perMTok(route.OutputPerMTok)+" out") + "\n")
	}
	if len(models) > 3 {
		b.WriteString("  " + m.st.dim.Render("press m for all "+strconv.Itoa(len(models))) + "\n")
	}
	return b.String()
}

func (m model) renderDeposit() string {
	var b strings.Builder
	b.WriteString("  " + m.st.title.Render("deposit") + "\n\n")
	b.WriteString("  " + m.st.label.Render("sending to") + "  " + m.st.value.Render(m.deps.Treasury.Address) + "\n")
	b.WriteString("  " + m.st.label.Render("rate") + "        " + m.st.value.Render(
		FormatUSD(m.deps.Treasury.SolPriceUSD)+" of credit per SOL") + "\n\n")
	b.WriteString("  " + m.st.label.Render("amount") + "      " + m.st.money.Render(m.amount+" SOL") + "\n\n")

	if !m.deps.Proven {
		b.WriteString("  " + m.st.warn.Render("This address was named, not proved, so a deposit cannot be signed.") + "\n")
		b.WriteString("  " + m.st.dim.Render("Forward an agent holding this address's key and reconnect with") + "\n")
		b.WriteString("  " + m.st.dim.Render("the -A:") + "\n")
		b.WriteString("  " + m.st.accent.Render("ssh-add ~/.ssh/id_ed25519 && ssh -A -i ~/.ssh/id_ed25519 "+m.endpointHost()) + "\n")
	} else if m.deps.SockPath == "" {
		b.WriteString("  " + m.st.errText.Render("this session has no forwarded agent, so there is nothing here that can sign.") + "\n")
		b.WriteString("  " + m.st.dim.Render("reconnect with:  ssh -A "+Domain) + "\n")
	} else {
		b.WriteString("  " + m.st.dim.Render("Your key stays on your machine. This server asks your agent to sign and") + "\n")
		b.WriteString("  " + m.st.dim.Render("never sees it. The transfer is checked against what was asked for") + "\n")
		b.WriteString("  " + m.st.dim.Render("before anything is broadcast.") + "\n")
		b.WriteString("\n  " + m.st.key.Render("enter") + m.st.dim.Render(" to send    ") +
			m.st.key.Render("esc") + m.st.dim.Render(" to go back"))
	}
	return b.String()
}

func (m model) renderKeys() string {
	var b strings.Builder
	b.WriteString("  " + m.st.title.Render("api keys") + "\n\n")
	if len(m.account.Keys) == 0 {
		b.WriteString("  " + m.st.dim.Render("none yet.") + "\n")
	}
	for i, k := range m.account.Keys {
		b.WriteString("  " + m.st.key.Render(strconv.Itoa(i+1)) + "  " +
			m.st.value.Render("rc_live_"+k.Label) + "\n")
		b.WriteString("     " + m.st.dim.Render("made "+ago(k.Created)+", last used "+ago(k.Touched)) + "\n")
	}
	b.WriteString("\n  " + m.st.key.Render("n") + m.st.dim.Render(" mint a new key    ") +
		m.st.key.Render("1") + m.st.dim.Render("…") + m.st.key.Render("9") + m.st.dim.Render(" revoke one") + "\n")
	b.WriteString("\n  " + m.st.dim.Render("A key is shown once, when it is minted; only its fingerprint is kept.") + "\n")
	b.WriteString("  " + m.st.dim.Render("Losing one is not a problem: mint another.") + "\n")
	if m.fresh != "" {
		b.WriteString("\n  " + m.st.key.Render("y") + m.st.dim.Render(" copy the key above") + "\n")
	}
	return b.String()
}

func (m model) renderModels() string {
	var b strings.Builder
	b.WriteString("  " + m.st.title.Render("routes") + "\n\n")
	models := m.deps.Catalogue.Models()
	for _, route := range models {
		b.WriteString("  " + pad(m.st.value.Render(route.ID), 22) +
			pad(m.st.dim.Render(route.Provider), 11) +
			pad(m.st.dim.Render(perMTok(route.InputPerMTok)), 20) +
			m.st.dim.Render(perMTok(route.OutputPerMTok)+" out") + "\n")
	}
	b.WriteString("\n  " + m.st.dim.Render("ask for one by putting its name in \"model\". Prices are per million tokens,") + "\n")
	b.WriteString("  " + m.st.dim.Render("and what they are is the rate your balance is actually billed at.") + "\n")
	return b.String()
}

func (m model) renderHelp() string {
	var b strings.Builder
	b.WriteString("  " + m.st.title.Render("RouterCafe") + "\n\n")
	b.WriteString("  " + m.st.value.Render("An OpenRouter you reach with ssh, paid for in SOL.") + "\n\n")
	b.WriteString("  " + m.st.label.Render("b") + m.st.dim.Render("  balance, keys and the short version of what a key buys") + "\n")
	b.WriteString("  " + m.st.label.Render("d") + m.st.dim.Render("  deposit SOL, signed by the agent you forwarded") + "\n")
	b.WriteString("  " + m.st.label.Render("k") + m.st.dim.Render("  API keys: mint a new one, revoke an old one") + "\n")
	b.WriteString("  " + m.st.label.Render("m") + m.st.dim.Render("  every route and what it costs") + "\n")
	b.WriteString("  " + m.st.label.Render("r") + m.st.dim.Render("  re-read the balance") + "\n")
	b.WriteString("  " + m.st.label.Render("y") + m.st.dim.Render("  copy a key just minted, using OSC 52") + "\n")
	b.WriteString("  " + m.st.label.Render("q") + m.st.dim.Render("  disconnect") + "\n\n")

	b.WriteString("  " + m.st.title.Render("what this is not") + "\n\n")
	b.WriteString("  " + m.st.dim.Render("There is no shell here. Nothing you type is run on this machine,") + "\n")
	b.WriteString("  " + m.st.dim.Render("because there is no way to ask it to: the session is a program,") + "\n")
	b.WriteString("  " + m.st.dim.Render("not a command line, and a command sent instead of a shell is ignored.") + "\n\n")
	b.WriteString("  " + m.st.dim.Render("Your private key never leaves your machine. This server asks the agent") + "\n")
	b.WriteString("  " + m.st.dim.Render("you forwarded with ssh -A, and checks the transaction it gets back.") + "\n")
	b.WriteString("  " + m.st.dim.Render("The same, more carefully, is at "+Domain+".") + "\n")
	return b.String()
}

// notOwned is what every action that changes an account says without one.
const notOwned = "this address was named, not proved. Forward an agent holding " +
	"its key and reconnect with -A to change anything here."

// refuse is what an action that needs proof answers with: the model carries
// the reason straight away, rather than a command that delivers it on the next
// tick. One keystroke should not have a delay between the key and the word no.
func (m model) refuse(reason string) (tea.Model, tea.Cmd) {
	m.notice = notice{noticeBad, reason}
	return m, nil
}

func (m model) field(label, value string) string {
	return "  " + pad(m.st.label.Render(label), 11) + value + "\n"
}

func (m model) endpointHost() string {
	if m.deps.Host != "" {
		return m.deps.Host
	}
	return Domain
}

// contentWidth is how wide the middle column is allowed to be.
//
// Floored at a width a phone can render, because a narrow terminal would
// otherwise get a negative gap and the header would tear the pane in half.
func (m model) contentWidth() int {
	w := m.width - 4
	if w < 40 {
		w = 40
	}
	return w
}

// wrap puts a long sentence into lines this terminal can show.
//
// Not lipgloss's Wrap: that breaks on words and will not break a URL or an
// address, and both of those are things a session needs to read in full.
func (m model) wrap(s string, style lipgloss.Style) string {
	width := m.contentWidth()
	if width < 20 {
		width = 20
	}
	runes := []rune(stripANSI(s))
	if len(runes) <= width {
		return "  " + s
	}
	// Broken on a space where there is one, at a character where there is not.
	// A hard cut alone would split "somewhere" into "some" and "where", which
	// is the one thing a wrapped sentence should never do; and an address or a
	// URL has no spaces at all, so the hard cut still has to be there.
	var out strings.Builder
	for len(runes) > width {
		cut := width
		if space := lastSpaceBefore(runes, width); space > width/3 {
			cut = space
		}
		out.WriteString("  " + style.Render(strings.TrimRight(string(runes[:cut]), " ")) + "\n")
		runes = runes[cut:]
		runes = []rune(strings.TrimLeft(string(runes), " "))
	}
	if len(runes) > 0 {
		out.WriteString("  " + style.Render(string(runes)))
	}
	return out.String()
}

// lastSpaceBefore is the index of the last space at or before limit, or -1.
func lastSpaceBefore(runes []rune, limit int) int {
	for i := limit - 1; i > 0; i-- {
		if runes[i] == ' ' {
			return i
		}
	}
	return -1
}

func (m model) shortAddress(addr string) string {
	if len(addr) <= 16 {
		return addr
	}
	return addr[:6] + "…" + addr[len(addr)-6:]
}

func shortSig(sig string) string {
	if len(sig) <= 16 {
		return sig
	}
	return sig[:8] + "…" + sig[len(sig)-8:]
}

func pad(s string, n int) string {
	w := lipgloss.Width(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// stripANSI removes escape sequences so a width can be measured on the text
// rather than on the styling. lipgloss.Width already does this for the styled
// string, but the wrap loop is slicing runes itself and needs the plain ones.
func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}
