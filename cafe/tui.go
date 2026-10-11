package cafe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/crypto/ssh/agent"
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

// screens is every place a session can be, in the order tab walks them.
//
// The order is the whole of the navigation: there are no page shortcuts, so
// this slice is what "next" means. Help is last because arriving somewhere
// and finding out how to get somewhere else should not be the default next
// thing you do.
//
// The first tab is the name, drawn as plain text rather than in a box, and it
// opens home: the wordmark, the numbers, the keys, the exports and the price
// list. It was briefly a splash screen of its own - the name and the balance
// at a glance - with the numbers on the tab beside it, and there was no reason
// for it to be anything but the same page twice.
var screens = []tab{
	{screenHome, "RouterCafe"},
	{screenDeposit, "deposit"},
	{screenKeys, "api keys"},
	{screenModels, "routes"},
	{screenHelp, "help"},
}

// widget is whether the current page has something on it that takes the
// keyboard once focused. A list always does and arrives focused; a text field
// does and arrives not, because a field that eats keystrokes the moment you
// look at it is the trap the focus was added to remove.
func (v screen) widget() bool {
	return v == screenDeposit || v == screenKeys || v == screenModels
}

// tab is one entry on the bar: a page, and what it is called there.
type tab struct {
	view screen
	name string
}

// tabs is the bar, and the ring, for this session.
//
// A session that has proved nothing has one of them. There is exactly one
// thing it can do - say which account it is - and offering it four pages it
// cannot use is a bar that lies about where you can go. It grows to all five
// the moment an account is named, which is the whole of what "proving" means
// here.
func (m model) tabs() []tab {
	if m.picking() {
		return screens[:1]
	}
	return screens
}

// picking is whether this session has an account at all, which is what the
// first tab is for. Read from the address rather than from the candidate list,
// because the address is what everything that changes an account reads and the
// two disagreeing is a session that thinks it owns something it does not.
func (m model) picking() bool { return strings.TrimSpace(m.deps.Address) == "" }

// current is the account this session is looking at, or nil when it has none.
//
// Falls back to the address on its own for a model built without a candidate
// list - which is every session that arrived with a key and an agent that
// answered with nothing new, and every model a test builds by hand.
func (m model) current() *candidate {
	if m.picking() {
		return nil
	}
	if len(m.candidates) == 0 {
		return &candidate{address: m.deps.Address, proven: m.deps.Proven}
	}
	return &m.candidates[m.at]
}

// cycle moves n accounts along the list and makes that one the session's.
//
// Which is the whole of what the picker used to be for, done with two keys
// instead of a screen: arriving somewhere and finding the balance you
// recognise *is* choosing it, and a question asked before anything is shown
// is a question answered before there is anything to answer it with.
//
// Proving follows the selection rather than preceding it. A candidate that
// came out of the agent is proved by asking the agent to sign, which happens
// as soon as it is the one on screen; one that was merely named on the
// command line is a view, and stays one.
func (m model) cycle(n int) (model, tea.Cmd) {
	if m.picking() || len(m.candidates) < 2 {
		return m, nil
	}
	next := (m.at + n) % len(m.candidates)
	if next < 0 {
		next += len(m.candidates)
	}
	m.at = next
	c := m.current()
	m.deps.Address, m.deps.Proven = c.address, c.proven
	m.view, m.notice, m.fresh, m.focus, m.amount = screenHome, notice{}, "", false, ""
	m.account = m.deps.Ledger.Account(c.address)
	m.paintFocus()
	m.syncLists()
	if c.key != nil && !c.proven {
		return m, proveCmd(m.deps.SockPath, c.address)
	}
	return m, nil
}

// addCandidates folds the agent's keys into the list of accounts this session
// may look at, without disturbing where it is or which one it is looking at.
func (m *model) addCandidates(keys []*agent.Key) {
	for _, k := range keys {
		_, sshPub, ok := pubkeyOf(k)
		if !ok {
			continue
		}
		address, err := AddressOf(sshPub)
		if err != nil || address == "" {
			continue
		}
		if m.has(address) {
			continue
		}
		m.candidates = append(m.candidates, candidate{
			address: address, comment: labelForKey(k), key: k,
		})
	}
}

// has is whether this session is already looking at, or could look at, an
// address. The one it arrived with is in the list before the agent's, so this
// is what keeps `ssh <address>@host` and `ssh -A host` from offering the same
// account twice.
func (m model) has(address string) bool {
	for _, c := range m.candidates {
		if c.address == address {
			return true
		}
	}
	return false
}

// proveCurrent asks the agent to sign for the account on screen, which is what
// turns a view into something that can be changed. Asked whenever the account
// on screen came out of the agent and has not been proved yet - including when
// it was just arrived at by cycling.
func (m model) proveCurrent() tea.Cmd {
	c := m.current()
	if c == nil || c.key == nil || c.proven || m.deps.SockPath == "" {
		return nil
	}
	return proveCmd(m.deps.SockPath, c.address)
}

// adopt puts the session on an account that is not in its list yet, which is
// the shape `ssh <address>@host` arrives in: named, not proved.
func (m model) adopt(address string) (model, tea.Cmd) {
	if !m.has(address) {
		m.candidates = append([]candidate{{address: address}}, m.candidates...)
	}
	m.deps.Address, m.deps.Proven = address, false
	m.at = 0
	for i, c := range m.candidates {
		if c.address == address {
			m.at = i
			break
		}
	}
	m.view, m.notice, m.fresh, m.focus, m.amount = screenHome, notice{}, "", false, ""
	m.account = m.deps.Ledger.Account(address)
	m.paintFocus()
	m.syncLists()
	return m, m.proveCurrent()
}

// candidate is one account this session could be looking at.
type candidate struct {
	address string

	// comment is the agent's own label for the key, which is ssh-add's
	// "user@host" for a key it loaded from a file. Shown beside the address,
	// because an address is a string of base58 and a comment is a name somebody
	// chose, and the name is what makes a list of them readable.
	comment string

	// key is the agent key this account came from, and nil for one that was
	// named on the command line. It is what tells "prove this" from "this is a
	// view of it".
	key *agent.Key

	// proven is whether an agent has been asked and answered. Not a guess: a
	// session that assumed it owned every account it could name would hand the
	// balance of somebody else's to anybody who typed the address.
	proven bool
}

// screenList is the ring in the order the bar shows it, for turning a column
// into a page.
func (m model) screenList() []screen {
	out := make([]screen, 0, len(m.tabs()))
	for _, t := range m.tabs() {
		out = append(out, t.view)
	}
	return out
}

// step moves n places through the ring of screens, wrapping at both ends.
//
// Wrapping rather than stopping is deliberate: tab is a cycle here, and a
// cycle that stalls at the last page makes the end of it feel like a dead end
// rather than the place you came round to.
func (m model) step(from screen, n int) screen {
	ring := m.tabs()
	i := 0
	for j, t := range ring {
		if t.view == from {
			i = j
			break
		}
	}
	i = (i + n) % len(ring)
	if i < 0 {
		i += len(ring)
	}
	return ring[i].view
}

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

	// caret is the reverse-video style a focused element wears, and idle is
	// the same element with the focus gone. Two styles rather than one toggled
	// on and off, because an unfocused field has to stay readable rather than
	// just stop being highlighted - it is still showing an amount somebody
	// typed, and dimming it into the background would look like a bug.
	caret lipgloss.Style
	idle  lipgloss.Style

	// homeIdle and homeActive are the first tab, which is the only one drawn
	// without a border. They are the same two colours as the tabs either side
	// of them, so the name reads as one of them rather than as a heading.
	homeIdle   lipgloss.Style
	homeActive lipgloss.Style

	// tabIdle and tabActive are the two states of the bar at the top of every
	// screen. They carry a bottom edge of their own rather than closing, so
	// the current page looks joined to the content under it instead of boxed
	// off from it.
	tabIdle   lipgloss.Style
	tabActive lipgloss.Style

	// window is the page sitting in the box the bar opens into: bordered on
	// three sides, deliberately not on the top, which is the tab's job.
	window lipgloss.Style

	// dark is which background these were picked against, so a frame drawn
	// from them can use the same colour for the edges it draws itself.
	dark bool
}

// newStyles builds the palette, for a terminal whose background is known.
//
// Two sets, and it has to be two: a near-white number on a near-white terminal
// is not a number. Every colour below is picked against one background or the
// other, and a palette that only reads on one of them is half a palette - and
// the half that vanishes is always the numbers, which are the last thing this
// program should lose.
//
// Dark is the default because a program that has not been told has to be
// readable and most terminals are dark; Bubble Tea sends
// tea.BackgroundColorMsg within the first few frames and the palette is rebuilt
// then. Per model, not per process: two sessions on two terminals with opposite
// backgrounds are two sessions with opposite palettes.
func newStyles(dark bool) styles {
	if !dark {
		return lightStyles()
	}
	return styles{
		brand:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#34d399")),
		brandDim:   lipgloss.NewStyle().Foreground(lipgloss.Color("#94a3b8")),
		label:      lipgloss.NewStyle().Foreground(lipgloss.Color("#94a3b8")),
		value:      lipgloss.NewStyle().Foreground(lipgloss.Color("#e2e8f0")),
		money:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f8fafc")),
		dim:        lipgloss.NewStyle().Foreground(lipgloss.Color("#94a3b8")),
		accent:     lipgloss.NewStyle().Foreground(lipgloss.Color("#38bdf8")),
		warn:       lipgloss.NewStyle().Foreground(lipgloss.Color("#fbbf24")),
		key:        lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#34d399")),
		title:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#e2e8f0")),
		errText:    lipgloss.NewStyle().Foreground(lipgloss.Color("#f87171")),
		okText:     lipgloss.NewStyle().Foreground(lipgloss.Color("#34d399")),
		box:        lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#1e293b")).Padding(0, 1),
		homeIdle:   lipgloss.NewStyle().Foreground(lipgloss.Color("#94a3b8")),
		homeActive: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#34d399")),
		tabIdle:    lipgloss.NewStyle().Padding(0, 1).Foreground(lipgloss.Color("#94a3b8")).Border(tabBorderWithBottom("\u2534", "\u2500", "\u2534"), true),
		tabActive:  lipgloss.NewStyle().Padding(0, 1).Bold(true).Foreground(lipgloss.Color("#34d399")).Border(tabBorderWithBottom("\u2518", " ", "\u2514"), true),
		window:     lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true).UnsetBorderTop().BorderForeground(lipgloss.Color("#475569")),
		idle:       lipgloss.NewStyle().Foreground(lipgloss.Color("#cbd5e1")),
		// The caret is reversed video on both backgrounds rather than a colour
		// of its own: a block of inverted cells reads the same either way, and
		// a caret that vanishes on one of them is not a caret.
		caret: lipgloss.NewStyle().Bold(true).Reverse(true).Foreground(lipgloss.Color("#0f172a")).Background(lipgloss.Color("#38bdf8")),
		dark:  dark,
	}
}

// lightStyles is the same palette against a light terminal. Darker and less
// saturated than the dark set for the same reason: on white, a colour that
// reads as "dim" against black reads as "invisible".
func lightStyles() styles {
	return styles{
		brand:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#047857")),
		brandDim:   lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b")),
		label:      lipgloss.NewStyle().Foreground(lipgloss.Color("#475569")),
		value:      lipgloss.NewStyle().Foreground(lipgloss.Color("#0f172a")),
		money:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0f172a")),
		dim:        lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b")),
		accent:     lipgloss.NewStyle().Foreground(lipgloss.Color("#0369a1")),
		warn:       lipgloss.NewStyle().Foreground(lipgloss.Color("#a16207")),
		key:        lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#047857")),
		title:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0f172a")),
		errText:    lipgloss.NewStyle().Foreground(lipgloss.Color("#b91c1c")),
		okText:     lipgloss.NewStyle().Foreground(lipgloss.Color("#047857")),
		box:        lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#cbd5e1")).Padding(0, 1),
		homeIdle:   lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b")),
		homeActive: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#047857")),
		tabIdle:    lipgloss.NewStyle().Padding(0, 1).Foreground(lipgloss.Color("#64748b")).Border(tabBorderWithBottom("\u2534", "\u2500", "\u2534"), true),
		tabActive:  lipgloss.NewStyle().Padding(0, 1).Bold(true).Foreground(lipgloss.Color("#047857")).Border(tabBorderWithBottom("\u2518", " ", "\u2514"), true),
		window:     lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true).UnsetBorderTop().BorderForeground(lipgloss.Color("#94a3b8")),
		idle:       lipgloss.NewStyle().Foreground(lipgloss.Color("#475569")),
		caret:      lipgloss.NewStyle().Bold(true).Reverse(true).Foreground(lipgloss.Color("#0f172a")).Background(lipgloss.Color("#38bdf8")),
		dark:       false,
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

	// Local says this program is running on the terminal it was started from
	// rather than arriving over a connection. Wording only.
	Local bool

	// Version is what the help screen says this server is. Empty means the
	// line is left off rather than printed blank: a binary built without the
	// version ldflags has no version, and an empty one looks like something
	// failed to load.
	Version string

	// Ctx is the session's context, so a deposit stops when the client hangs
	// up rather than holding a goroutine until its own deadline.
	Ctx context.Context
}

// catalogue is the routing table, falling back to the default when there is
// none.
//
// deps is built by hand in tests and by intoAccount on the path a session
// that proved nothing arrives by, so "no catalogue" has to mean something
// rather than being a nil pointer in the middle of a render.
func (d deps) catalogue() *Catalogue {
	if d.Catalogue == nil {
		return DefaultCatalogue()
	}
	return d.Catalogue
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

	// routes and apiKeys are the two screens that are a list rather than a
	// page. Held here rather than built per render because the cursor, the
	// page and the scroll offset all live in them and rebuilding on every
	// frame would reset all three.
	routes  list.Model
	apiKeys list.Model

	// candidates and at are the accounts this session may be looking at and
	// which one it is. Empty candidates is the whole of what "picking" means -
	// there is nothing to show anybody - so picking() counts them rather than
	// keeping a flag beside them that could disagree with the address.
	candidates []candidate
	at         int

	// rows is where the current page's list put its rows on screen, as the
	// delegate drew them. Set by every frame, because a row's place on the
	// screen is a fact about this frame: the same row sits somewhere else
	// once a notice wraps, and a click read against the wrong frame revokes
	// the wrong key.
	rows []drawnRow

	// mark is where the wordmark on the balance screen landed, so a click on
	// it navigates rather than doing nothing. A link like any other, and the
	// same code path as the bar: a logo takes you home.
	mark box

	// help is the pager on the one page with more on it than a window shows.
	// Held for the same reason as the lists: where in the help somebody is
	// reading is theirs, not something to be reset every frame.
	help viewport.Model

	// focus is whether a text field is taking keystrokes. Off by default,
	// and that is the whole point: a field that swallows every key while it
	// is on screen takes the page shortcuts with it, so b, k and m stop
	// working and the only way out of the screen becomes esc. Tab puts the
	// caret in the field and takes it back out, and only a focused field
	// consumes a printable key.
	focus bool

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
	m.view, m.notice, m.fresh, m.focus = view, notice{}, "", false
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
	// What a forwarded agent holds, asked for whatever this session arrived
	// with. A session that named an account needs to know whether it owns it,
	// and either way the other keys in that agent are accounts it could be
	// looking at instead - which is what `<` and `>` move between.
	if m.deps.SockPath == "" {
		return nil
	}
	return listKeysCmd(m.deps.SockPath)
}

func (m model) View() tea.View {
	// A pointer, because drawing is what sizes the list on the page and what
	// records where its rows landed, and both have to survive to reach the
	// click handling below.
	p := &m
	content, where := p.frame()
	v := ownedView(content)
	// Cell motion rather than all-motion: clicks and drags, not every mouse
	// movement reported. Over ssh this is the difference between a program
	// that responds and one that floods the connection, and it still costs
	// the terminal its own text selection, which is why it is on rather than
	// on by default.
	v.MouseMode = tea.MouseModeCellMotion
	v.OnMouse = clickTo(where)
	return v
}

// clickTo turns a click into an intent, given what the last frame drew.
//
// It is a closure over the frame's own layout rather than a fixed map,
// because the bar changes width with the names in it and the list changes
// height with how many rows are on the page. The only thing that can place a
// click correctly is the thing that drew the thing being clicked.
func clickTo(where clicks) func(tea.MouseMsg) tea.Cmd {
	return func(msg tea.MouseMsg) tea.Cmd {
		m := msg.Mouse()
		if m.Button != tea.MouseLeft {
			return nil
		}
		if view, ok := where.link(m.X, m.Y); ok {
			return func() tea.Msg { return gotoScreenMsg{view} }
		}
		if row, ok := where.rowAt(m.X, m.Y); ok {
			return func() tea.Msg { return selectRowMsg{row} }
		}
		return nil
	}
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
		// The lists are not resized here. They are sized by the page that
		// draws them, every frame, because what they are sized to is the room
		// between a title and the prose under it rather than the window; and
		// because a list that has not been built yet is a zero value, which
		// the component panics on.
		m.sizeHelp()
		return m, nil

	case tea.BackgroundColorMsg:
		// The terminal says what it is once, early. Every colour in this
		// program is picked against one background or the other, and a number
		// drawn in near-white on a near-white terminal is not a number.
		if dark := msg.IsDark(); dark != m.st.dark {
			m.st = newStyles(dark)
			m.paintFocus()
		}
		return m, nil

	case keysListedMsg:
		// The agent's keys join the accounts this session may look at. The one
		// it came in with stays first, so cycling forward from where you
		// started is the road to the others and cycling back is the way home.
		m.addCandidates(orderableKeys(msg.keys))

		// A session that named nothing at all lands on the first of them. Not
		// because somebody chose it - there was nobody to choose - but because
		// showing the first one and letting `<` and `>` move off it is the same
		// as choosing it, and asking first was the thing this replaced.
		if m.picking() {
			if len(m.candidates) == 0 {
				return m, nil
			}
			next, cmd := m.adopt(m.candidates[0].address)
			return next, cmd
		}
		// An account that was named rather than proved is proved now, if this
		// agent turns out to hold it: that is the upgrade
		// `ssh <address>@host` has always got, and it is silent when the agent
		// does not, because somebody reading somebody else's balance is the
		// ordinary case rather than an error.
		if len(m.candidates) > 0 {
			m.candidates[m.at].proven = m.deps.Proven
		}
		return m, m.proveCurrent()

	case nonceSignedMsg:
		m.busy = ""
		if msg.err != nil {
			m.notice = notice{noticeBad, msg.err.Error()}
			return m, nil
		}
		return m.adopt(msg.address)

	case pickKeyMsg:
		if m.view != screenHome || msg.row < 0 || msg.row >= len(m.candidates) {
			return m, nil
		}
		m.at = msg.row
		next, cmd := m.cycle(0)
		return next, cmd

	case provenMsg:
		// Silent either way. An agent that does not hold the key is the
		// ordinary case for somebody looking at someone else's balance, and
		// saying so on a screen they are only reading would be noise.
		// Silent either way. An agent that does not hold the key is the
		// ordinary case for somebody looking at someone else's balance, and
		// saying so on a screen they are only reading would be noise.
		if msg.proven && !m.picking() {
			m.candidates[m.at].proven = true
			m.deps.Proven = true
		}
		return m, nil

	case refreshedMsg:
		m.account = msg.account
		m.syncLists()
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
		defer m.syncLists()
		switch {
		case msg.err != nil:
			m.notice = notice{noticeBad, msg.err.Error()}
		case !msg.ok:
			m.notice = notice{noticeBad, "that key was not on file"}
		default:
			m.notice = notice{noticeGood, "revoked " + msg.label}
		}
		return m, refreshCmd(m.deps)

	case gotoScreenMsg:
		return m.show(msg.view), nil

	case selectRowMsg:
		// A click on a row is a click on a list, so it also focuses one: a
		// cursor that moved but did not light up leaves it impossible to tell
		// whether anything will answer to the next keystroke.
		if l := m.nav(); l != nil && msg.row < len(l.Items()) {
			m.focus = true
			l.Select(msg.row)
			m.paintFocus()
		}
		return m, nil

	case tea.KeyPressMsg:
		return m.onKey(msg)
	}
	return m, nil
}

// gotoScreenMsg is a click on the bar asking for a page.
type gotoScreenMsg struct{ view screen }

// selectRowMsg is a click in a list asking for the row it landed on.
type selectRowMsg struct{ row int }

func (m model) onKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// ^C always quits, whatever is on screen: a person holding a wallet
	// prompt needs a way out that does not depend on which view they
	// wandered into.
	if msg.String() == "ctrl+c" {
		return m, tea.Quit
	}

	// The deposit amount only takes keys while it is focused. Unfocused, this
	// screen is an ordinary page and b, k, m and d all work, which is what
	// makes esc a convenience here rather than the only exit it used to be.
	// The three screens with something to type into or move through take the
	// keyboard only once they have been focused. Unfocused, each of them is
	// an ordinary page and the footer at the bottom keeps telling the truth,
	// which is the whole reason a list here does not answer to k, d or b at
	// any focus level.
	// Tab and shift+tab are the navigation, and the bar at the top says where
	// they go. Tab takes the widget first where there is one, so arriving on
	// the deposit screen and pressing tab once puts the caret in the amount
	// rather than skipping past it.
	switch msg.String() {
	case "tab":
		if m.focus {
			return m.advance(), nil
		}
		if m.view.widget() {
			m.focus = true
			m.paintFocus()
			return m, nil
		}
		return m.advance(), nil
	case "shift+tab":
		return m.retreat(), nil
	}

	// The widget on screen gets the keyboard first - and a text field gets all
	// of it, because a field that lets a letter through to the program is a
	// field that disconnects the session because somebody typed q into an
	// amount. A list gets only what it claims; see listClaims for what that
	// is and why.
	if m.focus && m.view == screenDeposit {
		return m.onDepositKey(msg)
	}
	if l := m.nav(); m.focus && l != nil {
		// Esc and enter are not the list's to answer for: esc puts the
		// cursor down without leaving the page, and enter acts on where the
		// cursor is, which is this program's idea of what a selection is for.
		switch msg.String() {
		case "esc":
			m.focus = false
			m.paintFocus()
			return m, nil
		case "enter":
			return m.onListEnter()
		}
		if listClaims(l.KeyMap, msg.String()) {
			return m.onListKey(msg)
		}
	}
	if m.view == screenHelp && helpKeys[msg.String()] {
		return m.scrollHelp(msg), nil
	}
	return m.onProgramKey(msg)
}

// onProgramKey is leaving, copying a key that is on screen, minting another,
// reading the help, and re-reading a balance.
//
// It comes after the widget on screen rather than before it, and that ordering
// is the whole of the focus rule. A text field is holding the keyboard, so it
// keeps these: a field that quits the session because somebody typed a letter
// into an amount is the trap the focus exists to avoid. A list is different -
// it answers only to hjkl and the paging keys and swallows everything else -
// and a list arrives focused, because that is what makes hjkl work without a
// keystroke. So the keys that were left to a list were keys nobody pressed:
// on the api keys screen, which is the page whose whole job is minting a key,
// `n` went into the list and did nothing.
func (m model) onProgramKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "<", "shift+,":
		return m.cycle(-1)
	case ">", "shift+.":
		return m.cycle(1)
	case "q":
		return m, tea.Quit
	case "y":
		return m.copyFreshKey()
	case "?":
		return m.show(screenHelp), nil
	case "r":
		// A reload is a key because the balance is somebody's money and they
		// should be able to make it re-read without reconnecting.
		return m, refreshCmd(m.deps)
	case "n":
		// Minting is a keystroke rather than a sub-menu. Revoking is not, and
		// used to be a number typed beside the key: there is a cursor now, and
		// a number next to a thing that moves is a number that means one
		// thing on screen and another after a keypress. Enter acts on where
		// the cursor is.
		if m.view == screenKeys {
			return m.mintKey()
		}
	}
	return m, nil
}

// advance walks the focus ring forwards, which is the only navigation there
// is.
//
// The ring is: this page's widget, then the next page. A page with no widget
// is simply passed through, so tab from the balance screen lands on the
// deposit screen rather than on nothing.
func (m model) advance() model {
	return m.show(m.step(m.view, 1))
}

// retreat is advance, the other way round.
func (m model) retreat() model {
	return m.show(m.step(m.view, -1))
}

// show moves to a page, putting it into the state a freshly arrived session
// should be in.
//
// Lists arrive focused: hjkl is only ever wanted by something already looking
// at a list, and arriving live saves a keystroke on the common path. The
// amount field arrives cold, which is the whole reason it was given focus in
// the first place.
func (m model) show(view screen) model {
	m.view = view
	m.focus = view.widget() && view != screenDeposit
	m.notice = notice{}
	m.amount = ""
	m.busy = ""
	m.fresh = ""
	m.paintFocus()
	return m
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

// onListKey is a focused list and a key it has a binding for, so the whole of
// what happens next is the component's business.
//
// It is handed the key rather than asked about it, which is why the caller
// checks listClaims first: a component that is given a key it has no binding
// for swallows it, and a swallowed key is a key nobody presses.
func (m model) onListKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if l := m.nav(); l != nil {
		// Update returns the moved list rather than mutating in place, and a
		// discarded copy is a cursor that never goes anywhere.
		var cmd tea.Cmd
		*l, cmd = l.Update(msg)
		return m, cmd
	}
	return m, nil
}

// onListEnter is what enter means on each list.
//
// Only the keys list has anything to enter: a route is chosen by naming it in
// the request rather than by standing on it here, and pretending otherwise
// would be a button that does nothing.
func (m model) onListEnter() (tea.Model, tea.Cmd) {
	if m.view != screenKeys {
		m.notice = notice{noticeBad, "a route is chosen by naming it in the request, not from here"}
		return m, nil
	}
	i := m.apiKeys.Index()
	if i < 0 || i >= len(m.account.Keys) {
		return m, nil
	}
	return m.revokeKey(i + 1)
}

func (m model) onDepositKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// Reached only while the field is focused. Tab and esc both put it down
	// rather than touching the amount, so putting the caret away and leaving
	// the screen are two different presses with two different meanings - which
	// they could not be when this handler caught every key on the page.
	switch msg.String() {
	case "esc":
		m.focus = false
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
	// Focus goes with the field. Leaving the caret in a field the session is
	// now waiting on a signature for would let the next keystroke change an
	// amount that is already committed to.
	m.amount, m.focus = "", false
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

// renderPage is the page content and everything that hangs off it, with no
// frame around it: the box is applied by render so that its width and the
// bar's width are decided in the same place.
//
// The two lists are sized here rather than when the window changed, because
// the room a list gets is what is left of the box after the lines the page
// prints around it - and those change under it. A notice wraps to a second
// line when a key is minted, and a page with a fresh key on it has two more
// lines under the list than one without. Sized once, at the window resize, a
// list is right until the first time somebody does something, and then it is
// either scrolling off the bottom of the box or leaving a hole under it - and
// both of those look like the frame is broken rather than like a list is the
// wrong size.
func (m *model) renderPage() (string, int) {
	var b strings.Builder
	b.WriteString(m.banner())

	// listTop is the line the page's list starts on, relative to the top of
	// the page, and -1 for a page with no list. Absolute lines are worked out
	// by frame, which is what knows where the page itself starts.
	listTop := -1
	switch m.view {
	case screenHome:
		b.WriteString(m.renderHome())
	case screenDeposit:
		b.WriteString(m.renderDeposit())
	case screenKeys:
		head, tail := m.keysPage()
		l, view, rows := m.fitted(m.apiKeys, 2, head, tail)
		m.apiKeys, m.rows = l, rows
		listTop = countLines(b.String() + head)
		b.WriteString(head + view + "\n" + tail)
	case screenModels:
		head, tail := m.routesPage()
		l, view, rows := m.fitted(m.routes, 1, head, tail)
		m.routes, m.rows = l, rows
		listTop = countLines(b.String() + head)
		b.WriteString(head + view + "\n" + tail)
	default:
		b.WriteString(m.renderHelp())
	}
	if m.busy != "" {
		b.WriteString("\n\n  " + m.st.warn.Render(m.busy) + "\n")
	}
	b.WriteString(m.note())
	return b.String(), listTop
}

// banner is the line a page carries above it when the session is only looking
// at somebody else's account.
func (m model) banner() string {
	if m.deps.Proven || m.deps.Address == "" {
		return ""
	}
	return "  " + m.st.warn.Render("read-only: this address was named, not proved") + "\n\n"
}

// note is what the page has to say about the last thing that happened to it.
//
// Counted by the list sizing as well as drawn by the page, for the reason
// above: a notice that wraps to two lines is two lines out of the room the
// list had.
func (m model) note() string {
	var b strings.Builder
	if m.busy != "" {
		b.WriteString("\n\n  " + m.st.warn.Render(m.busy) + "\n")
	}
	if m.notice.kind == noticeNone {
		return b.String()
	}
	b.WriteString("\n")
	switch m.notice.kind {
	case noticeGood:
		b.WriteString(m.wrap(m.st.okText.Render(m.notice.text), m.st.okText))
	default:
		b.WriteString(m.wrap(m.st.errText.Render(m.notice.text), m.st.errText))
	}
	b.WriteString("\n")
	return b.String()
}

// pageRoom is how many terminal lines the page inside the box has to fill:
// the window, less the bar, the footer, and the box's own bottom edge. There
// is no brand line to take off, because the bar carries the name. One fewer than the box because the box's height counts its
// border, and the page does not have one along the bottom of its own.
//
// Floored, because a model built by hand in a test has no window and a
// negative height is a component that draws nothing rather than a small one
// that draws something.
func (m model) pageRoom() int {
	return max(1, m.height-footerLines-barLines-1)
}

// fitted gives a list the room left on the page and returns it with what it
// made, and where each row landed.
//
// Asked and checked rather than worked out, because the component's own
// arithmetic is not something to reproduce here: it lays its rows out around
// a status bar, a blank line under it, a blank between rows and a margin
// above the page dots, and it grows past the height it was given rather than
// cutting itself at it. A height derived from an assumed formula is a list
// that is one row out, and the check below is two lines long and cannot be.
//
// The rows come back from the delegate, which is the only thing in the program
// that sees each row as it is drawn. Asking the component where it put them
// afterwards is not an option and counting the blanks between them is the
// guess this function exists to avoid.
func (m *model) fitted(l list.Model, perRow int, head, tail string) (list.Model, string, []drawnRow) {
	room := m.roomFor(head, tail, countLines(m.note()))
	// The delegate starts as if it had already written the lines the
	// component puts above the first row, so what it records is a line on the
	// screen rather than a line inside the component.
	d := &rowDelegate{focused: m.focus, written: listLead}
	l.SetDelegate(d)
	l.SetWidth(m.listWidth())
	floor := m.listFloor(perRow)
	l.SetHeight(max(floor, room))
	for range 4 {
		// Both cleared each time round: the delegate records every row the
		// list draws and how many lines it has written, and four passes at
		// the same list would otherwise answer with four copies of every row
		// at four different heights.
		d.drawn, d.written = nil, listLead
		view := l.View()
		if countLines(view) <= room || l.Height() <= floor {
			return l, view, d.drawn
		}
		l.SetHeight(max(floor, l.Height()+room-countLines(view)))
	}
	d.drawn, d.written = nil, listLead
	return l, l.View(), d.drawn
}

// listFloor is the smallest a list on this page is allowed to be: three rows,
// because below that there is no room to move the cursor and say so.
//
// A terminal too short for it still gets it - the list is the page, and a
// list sized to nothing is not a tight list, it is a broken one. What a page
// does about being too short is drop the prose under the list, which is what
// keysPage asks about this before it keeps it.
func (m model) listFloor(perRow int) int { return perRow * 3 }

// roomFor is how many lines are left on the page for a list once the two
// halves of the page around it and the notice under it are counted.
//
// Pages ask this before deciding what to leave off, so a page can drop the
// line that matters least rather than having the frame cut off the line that
// matters most - see keysPage.
func (m model) roomFor(head, tail string, noticeLines int) int {
	return m.pageRoom() - countLines(m.banner()) - countLines(head) - countLines(tail) - noticeLines
}

// countLines is how many lines a string adds to what is already written, which
// is what every layout decision in this file is made in and what lipgloss
// measures things in too.
//
// The trailing newline is the whole of the subtlety. Every chunk of a page in
// this program ends with one, because they are concatenated, and a string
// that ends with a newline has closed its last line rather than started
// another: counting it as one more line puts every measurement of a page one
// line out, which is a list drawn a line lower than the frame thinks it is
// and a click one row out.
func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

// frame is the brand line, the bar, and the page in the box underneath them.
//
// The box has no top edge and the current tab has a blank one, which is the
// whole of what makes the two look joined rather than stacked: a bar floating
// above a wall of text reads as chrome, and a bar whose current tab opens into
// the page reads as navigation.
//
// A pointer receiver, unlike everything else that draws, because drawing the
// page is what sizes the list on it and what records where its rows landed.
// Both are per-frame facts that the click handling has to agree with, and a
// copy of the model would have thrown them away.
func (m *model) frame() (string, clicks) {
	m.rows, m.mark = nil, box{}
	bar, tabs := m.tabBar()
	page, listAt := m.renderPage()

	// The bar is three lines - the top of the box, the labels, the bottom edge
	// - and a click on any of them is a click on the tab under it.
	where := clicks{inside: span{x0: 1, x1: m.width - 1}}
	views := m.screenList()
	for i, tab := range tabs {
		where.tabs = append(where.tabs, barTab{
			box{x0: tab.x0, x0y: barTop, x1: tab.x1, y1: barTop + barLines - 1},
			views[i],
		})
	}
	// The page starts on the line after the bar's underline, and the box has no
	// top edge of its own, so a line on the page is a line on the terminal from
	// there on. The rows come back from the delegate that drew them, offset by
	// the lines the component puts above them, so a click lands on the row
	// under it rather than on a row counted by a formula that a later release
	// of the component would move.
	if listAt >= 0 {
		where.listTop = barLines + listAt
		where.rows = m.rows
	}
	// The wordmark on the balance screen is a link to the balance screen, in
	// the same way the name on the bar is. It is read after the page is drawn
	// because where it landed is a fact about what was drawn.
	where.mark = m.mark
	return frame(m.st, m.width, m.height, bar, page, m.footer()), where
}

// clicks is what the last frame put on screen and where, so that a mouse
// event carrying coordinates can be turned into an intent.
//
// Rebuilt on every frame, because the thing it describes - which tab is
// current, which row the cursor is on - differs on every frame, and a click
// against yesterday's layout is worse than no click at all.
type clicks struct {
	tabs    []barTab
	tabLine int

	// listTop is the line the current page's first list row is on and rows are
	// where the rest of them fell, as the delegate drew them. Only the rows on
	// this page are in it: clicking a row that is on another page of the list
	// is a click on nothing.
	listTop int
	rows    []drawnRow

	// inside is the horizontal extent of the box, so a click on its border is
	// not a click on the row behind the border.
	inside span

	// mark is the wordmark on the balance screen, where it actually landed.
	// It is a second kind of link rather than one of the tabs because it is
	// only ever on one screen and only when there is room for it - but it is
	// the same act, so link() answers for both.
	mark box
}

// barTop is where the bar starts counting from. It is line 0: the name and the
// address are on the bar's own line, so there is nothing above it.
const barTop = 0

// listLead is how many lines the list component puts above its first row: the
// status bar that says how many keys there are, and the blank line under it.
//
// Measured, not assumed: a frame whose rows are one line out is a frame whose
// clicks revoke the wrong key.
const listLead = 2

// link returns the page a click on line y column x navigates to, from the bar
// or from the wordmark. Both are the same act and both go through here.
func (c clicks) link(x, y int) (screen, bool) {
	for _, tab := range c.tabs {
		if tab.area.contains(x, y) {
			return tab.view, true
		}
	}
	if c.mark.contains(x, y) {
		return screenHome, true
	}
	return 0, false
}

// rowAt returns the item a click landed on within the list, if any.
func (c clicks) rowAt(x, y int) (int, bool) {
	if len(c.rows) == 0 || !c.inside.contains(x) {
		return 0, false
	}
	off := y - c.listTop
	if off < 0 {
		return 0, false
	}
	for _, r := range c.rows {
		if off >= r.start && off < r.start+r.lines {
			return r.item, true
		}
	}
	return 0, false
}

func (m model) header() string {
	left := m.st.brand.Render("RouterCafe")
	right := m.st.dim.Render(Domain)
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

// tabBar is where every page is, all at once.
//
// It replaces the footer that used to list what each letter did. That footer
// had to be right on every screen or it was a lie, which is why a list
// component that wanted b, d, f and u was a problem rather than a detail: the
// screen could not show the same letters as shortcuts and mean them. A bar
// shows where you are and where you can go, and cannot go stale the way a
// legend does.
// tabBar is where every page is, all at once, with the name of this thing at
// the left of it and where it is served from at the right.
//
// It replaces the footer that used to list what each letter did. That footer
// had to be right on every screen or it was a lie, which is why a list
// component that wanted b, d, f and u was a problem rather than a detail: the
// screen could not show the same letters as shortcuts and mean them. A bar
// shows where you are and where you can go, and cannot go stale the way a
// legend does.
//
// The brand and the address sit on the bar's own line rather than on one above
// it, for the same reason the bar exists: a line of chrome that changes nothing
// is a line somebody has to look past. Which also means the name is where a
// logo goes, and it is clickable - a logo takes you home everywhere it is.
//
// Returns the bar and the columns that can be clicked. The name is the first
// of them, and a click on it goes through exactly the same handling as a click
// on any other: going home is what the first tab does.
func (m model) tabBar() (string, []span) {
	// The first tab is the name, and it is the only one drawn without a
	// border: plain text on the bar's own line, set in from the
	// edge, coloured the way a tab is coloured and behaving exactly like one -
	// it lights up when its page is the one on screen, and a click on it opens
	// that page. A box drawn round it would be the only tab not shaped like a
	// tab, which is the whole of what having it in the bar is there to stop.
	ring := m.tabs()
	style := m.st.homeIdle
	if m.view == ring[0].view {
		style = m.st.homeActive
	}
	name := "  " + style.Render(ring[0].name) + "  "
	left := lipgloss.Width(name)

	cells := make([]string, 0, len(ring))
	for _, page := range ring[1:] {
		s := m.st.tabIdle
		if page.view == m.view {
			s = m.st.tabActive
		}
		// The last tab keeps the corner its style gives it, which the tabs
		// example overrides because there the page is exactly as wide as the
		// bar and the run of edge stops where the last tab stops. Here the edge
		// carries on past it.
		cells = append(cells, s.Border(s.GetBorder()).Render(page.name))
	}

	// Whole tabs are dropped from the end rather than the run being cut: a tab
	// with half of its label missing is not a tab, and the frame's top edge
	// needs somewhere to go after the last one. The ring does not care - tab
	// and shift+tab still walk all of them.
	//
	// The run is rebuilt each time rather than measured by adding the cells
	// up: each cell is three lines tall, and a width measured across the wrong
	// axis is a bar dropped one tab too eagerly or not eagerly enough.
	run := func() []string {
		return strings.Split(lipgloss.JoinHorizontal(lipgloss.Top, cells...), "\n")
	}
	rows := run()
	tabs := lipgloss.Width(rows[0])
	for len(cells) > 1 && left+tabs+barEdgeGap > m.width {
		cells = cells[:len(cells)-1]
		rows, tabs = run(), lipgloss.Width(run()[0])
	}
	// A session that has named no account has one tab and no bordered cells at
	// all, and an empty join is one line rather than three. Padded so the bar is
	// always the height the frame is expecting.
	for len(rows) < barLines {
		rows = append(rows, "")
	}

	// Shedding, widest first: the address with the version, the address alone,
	// then nothing. The name is never one of them - it is the way back.
	var address string
	for _, candidate := range []string{m.address(), m.st.dim.Render(Domain), ""} {
		if left+tabs+lipgloss.Width(candidate) <= m.width-barMargin {
			address = candidate
			break
		}
	}

	tail := max(0, m.width-left-tabs-1)
	lines := []string{
		strings.Repeat(" ", left) + rows[0] + strings.Repeat(" ", tail+1),
		name + rows[1] + strings.Repeat(" ", max(0, m.width-barMargin-left-tabs-lipgloss.Width(address))) +
			address + strings.Repeat(" ", barMargin),
		// The top edge of the box, all the way across: a corner at the left
		// where it turns down into the box's own wall, the tabs' own bottom
		// edge through the middle, and the corner at the right. Not a rule laid
		// over a box - it is the box's edge, and a gap in it is a hole with
		// the page showing through.
		"\u250c" + strings.Repeat("\u2500", left-1) + rows[barLines-1] +
			strings.Repeat("\u2500", tail) + "\u2510",
	}
	// Cut to the window on the way out. Six tabs are wider than a narrow
	// terminal, and a bar that runs past the right edge drags the frame out
	// with it - the one thing the frame's own MaxWidth was there to stop.
	for i, line := range lines {
		lines[i] = ansi.Truncate(line, m.width, "")
	}

	clickable := make([]span, 0, len(cells)+1)
	clickable = append(clickable, span{0, left})
	x := left
	for _, cell := range cells {
		w := lipgloss.Width(cell)
		clickable = append(clickable, span{x, x + w})
		x += w
	}
	return strings.Join(lines, "\n"), clickable
}

const (
	// barEdgeGap is the columns kept clear between the right of the tabs and
	// the address. Without it the last tab and the address are the same object
	// with no gap in it, which reads as one run of text.
	barEdgeGap = 2

	// barMargin is how far in from the right edge the address sits. Flush
	// against the edge is one way to be tidy, and the wrong one here: the name
	// is set in two columns from the left, so the address set in two from the
	// right is what makes the two ends of the line look like they were placed
	// rather than one of them measured.
	barMargin = 2
)

// address is the domain, and the version of the server beside it.
//
// On the bar rather than at the bottom of the help screen, which is where it
// used to be: there it was on one screen of five and cut off on the terminals
// with least room, and here it is where somebody looks when they want to know
// what they are talking to. A build with no version ldflags says nothing at
// all - a bare "dev", or a blank, reads as a bug rather than as an
// unversioned build.
func (m model) address() string {
	v := strings.TrimSpace(m.deps.Version)
	if v == "" || v == "dev" {
		return m.st.dim.Render(Domain)
	}
	return m.st.dim.Render(Domain + " " + v)
}

// carryBarEdge runs the bar's bottom edge on to the right-hand corner of the
// box.
//
// The bar is as wide as the names in it and the box is as wide as the window,
// so without this the top of the frame simply stops a third of the way across
// the terminal: a box with a lid on the left two thirds of it and open sky
// over the rest, which reads as the bar being drawn over something rather
// than as a page with a bar on it. The run is the box's own border colour, so
// it is the edge continuing rather than more bar.
func (m model) carryBarEdge(bar string, barWidth int) string {
	lines := strings.Split(bar, "\n")
	if len(lines) < barLines || m.width <= barWidth {
		return bar
	}
	// One column short of the window: the last is the box's corner.
	run := m.width - barWidth - 1
	if run < 1 {
		return bar
	}
	lines[barLines-1] += edge(m.st).Render(strings.Repeat("\u2500", run)) + edge(m.st).Render("\u2510")
	return strings.Join(lines, "\n")
}

// barTab is one thing on the bar you can click and where it goes.
//
// The destination is carried with the area rather than worked out from the
// order, because the name at the left of the bar goes somewhere as well and
// is not one of the pages in the ring - a bar whose clicks are indexed against
// a list it no longer lines up with is a bar that navigates to the wrong page
// the moment anything is added to either side of it.
type barTab struct {
	area box
	view screen
}

// span is a run of terminal columns something clickable occupies.
type span struct{ x0, x1 int }

// contains reports whether a column falls inside, half-open: the right edge is
// the first column of whatever comes next.
func (s span) contains(x int) bool { return x >= s.x0 && x < s.x1 }

// box is a rectangle on the screen: columns from x0 up to x1, lines from y0
// down to y1. Columns are half-open for the reason spans are - two things
// sharing a column is a click that lands on whichever was asked about last -
// and lines are inclusive, because a rectangle is a rectangle.
type box struct{ x0, x0y, x1, y1 int }

// contains reports whether a cell is inside. An empty box contains nothing,
// which is what lets a page that drew no wordmark leave the rectangle zero and
// have every click on it fall through.
func (b box) contains(x, y int) bool {
	return x >= b.x0 && x < b.x1 && y >= b.x0y && y <= b.y1
}

// tabBorderWithBottom is a rounded border with its bottom edge replaced, which
// is what makes an active tab look joined to the page under it instead of
// closed off from it.
func tabBorderWithBottom(left, middle, right string) lipgloss.Border {
	border := lipgloss.RoundedBorder()
	border.BottomLeft = left
	border.Bottom = middle
	border.BottomRight = right
	return border
}

func (m model) footer() string {
	pairs := [][2]string{
		{"tab", "next page"},
		{"shift+tab", "previous"},
		{"r", "refresh"},
	}
	// Only while there is something to copy. A y that is always offered and
	// usually refused is a keystroke people learn to ignore.
	if m.fresh != "" {
		pairs = append(pairs, [2]string{"y", "copy key"})
	}
	// Only when there is more than one account to be between: one candidate is
	// not a list, and offering a switch across a single entry is a hint for a
	// control that does nothing.
	if len(m.candidates) > 1 {
		pairs = append(pairs, [2]string{"< >", "switch account"})
	}
	// The help screen scrolls when it has more on it than fits, and only then:
	// a hint that claims a page scrolls on a terminal where it does not is
	// worse than no hint, because the person presses j and then wonders why
	// nothing happened.
	if m.view == screenHelp && m.helpOverflows() {
		pairs = append(pairs, [2]string{"hjkl", "scroll"})
	}
	pairs = append(pairs, [2]string{"?", "help"}, [2]string{"q", "quit"})

	// Built by dropping what does not fit rather than by wrapping, because the
	// frame is a fixed height and a footer that grew to two lines would push it
	// past the bottom of the terminal. The help screen has the whole list, so
	// what is lost here is discoverable rather than gone.
	var b strings.Builder
	b.WriteString("  ")
	used := 2
	for i, pair := range pairs {
		piece := m.st.key.Render(pair[0]) + m.st.dim.Render(" "+pair[1]+"    ")
		w := lipgloss.Width(piece)
		if used+w > m.width && i < len(pairs)-1 {
			continue
		}
		if used+w > m.width && i > 0 {
			// The last one always goes in, even if it has to be the only thing
			// on the line: a footer that cannot say how to leave is worse than
			// one that overflows by a column.
			break
		}
		b.WriteString(piece)
		used += w
	}
	return strings.TrimRight(b.String(), " ")
}

// renderEmpty is the first tab for a session with nothing to look at: no
// account named and no agent holding one.
//
// It is a page rather than a screen of its own, and that is the whole point: a
// connection that proved nothing used to be handed a different program, which
// then handed this one over the moment it worked out who it was. One window,
// with the question on its first page and the answer where it was waiting.
//
// There is no address field here, and there used to be. Naming an account is
// something a person does on the command line, where writing it says out loud
// that they are naming rather than proving: `ssh <address>@router.cafe`. The
// only thing a session in this state can do that nothing else can is look at
// an account its agent holds, and that is not something typing does.
func (m model) renderEmpty() string {
	st := m.st
	var b strings.Builder
	if m.busy != "" {
		return m.wrap(st.warn.Render(m.busy), st.warn) + "\n"
	}
	if m.deps.Local {
		b.WriteString("  " + st.title.Render("No ssh-agent, so nothing here can sign.") + "\n")
		b.WriteString(m.wrap(st.dim.Render("An account is an ed25519 public key. Start an agent, add a key, and come back:"), st.dim) + "\n")
		b.WriteString("  " + st.accent.Render("eval $(ssh-agent -s) && ssh-add ~/.ssh/id_ed25519") + "\n")
		return b.String()
	}
	b.WriteString("  " + st.title.Render("This connection proved nothing, so nothing here can sign.") + "\n")
	b.WriteString(m.wrap(st.dim.Render("To look at an account instead of proving one, name it on the command line - which says out loud that it is named rather than proved:"), st.dim) + "\n")
	b.WriteString("  " + st.accent.Render("ssh "+m.deps.host()+" <address>") + "\n")
	b.WriteString(m.wrap(st.dim.Render("To prove one instead, reconnect with an agent holding it:"), st.dim) + "\n")
	b.WriteString("  " + st.accent.Render("ssh -A "+m.deps.host()) + "\n")
	return b.String()
}

// renderAccount is which account this session is looking at, in full, with the
// agent's own name for the key beside it when there is one.
//
// In full, not shortened: an address is the thing a person pastes into
// `ssh-keygen` and into `sol-keys`, and a page that will not print all of it
// is a page that makes them go and look it up somewhere else. It is also the
// one thing on this screen that tells two candidates apart - two 44-character
// strings that share a prefix are the same account, and two that share
// nothing are two accounts, which is the whole of what choosing is.
//
// The comment is the agent's label for the key, which is ssh-add's "user@host"
// for one it loaded from a file. A name somebody chose next to a string nobody
// can read is what makes a list of candidates pickable.
func (m model) renderAccount() string {
	c := m.current()
	if c == nil {
		return ""
	}
	// The label is padded to the same column every other field uses, so the
	// address below it lines up with the numbers underneath it however long it
	// is.
	lead := "  " + m.st.label.Render(pad("account", 11))
	whole := c.address
	if lipgloss.Width(lead)+len(whole) > bodyWidth(m.width) {
		whole = m.shortAddress(whole)
	}
	out := lead + m.st.value.Render(whole)

	// Proven or not is said here rather than as a banner on every page of the
	// session: it is the difference between a balance you may spend and one you
	// may only read, and it belongs next to the number.
	detail := strings.TrimSpace(c.comment)
	if c.proven {
		if detail == "" {
			detail = "proven"
		} else {
			detail += "  proven"
		}
	}
	if detail == "" {
		return out + "\n"
	}
	// Beside the address where it fits, under it where it does not - a comment
	// that pushed the address off the edge would be worse than a second line.
	if lipgloss.Width(out)+2+lipgloss.Width(detail) <= bodyWidth(m.width) {
		return out + "  " + m.st.dim.Render(detail) + "\n"
	}
	return out + "\n" + "  " + pad("", 11) + m.st.dim.Render(detail) + "\n"
}

// switchHint is what `<` and `>` do, offered only when there is more than one
// account to switch between. One candidate is not a list.
func (m model) switchHint() string {
	if len(m.candidates) < 2 {
		return ""
	}
	return "  " + m.st.key.Render("<") + m.st.dim.Render(" ") + m.st.key.Render(">") +
		m.st.dim.Render(" to switch between the "+strconv.Itoa(len(m.candidates))+
			" accounts your agent holds") + "\n"
}

// renderHome is the page the name at the left of the bar opens: the wordmark,
// the numbers, and everything that belongs with them.
//
// The wordmark is on it rather than on a splash page of its own because there
// is nothing a splash page could have said that this does not also say - the
// name, the balance, and what to do next were already all here.
func (m *model) renderHome() string {
	if m.picking() {
		return m.renderEmpty()
	}
	var b strings.Builder
	acct := m.account
	b.WriteString(m.wordmark())
	b.WriteString(m.renderAccount())
	b.WriteString(m.field("balance", m.st.money.Render(FormatUSD(acct.Balance))))
	b.WriteString(m.field("paid in", FormatUSD(acct.Deposits)))
	b.WriteString(m.field("spent", FormatUSD(acct.Spent)))

	if !m.deps.Proven {
		b.WriteString("\n\n  " + m.st.dim.Render("keys are only shown to whoever holds the account's key") + "\n")
	} else if len(acct.Keys) == 0 {
		b.WriteString("\n\n  " + m.st.warn.Render("no API key yet") + "\n")
		b.WriteString("  " + m.st.dim.Render("tab to the api keys to mint one, then point any OpenAI client at https://"+m.endpointHost()) + "\n")
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
	models := m.deps.catalogue().Models()
	for i, route := range models {
		if i >= 3 {
			break
		}
		b.WriteString("  " + pad(m.st.value.Render(route.ID), 24) +
			pad(m.st.dim.Render(route.Provider), 12) +
			m.st.dim.Render(perMTok(route.InputPerMTok)+" in, "+perMTok(route.OutputPerMTok)+" out") + "\n")
	}
	if len(models) > 3 {
		b.WriteString("  " + m.st.dim.Render("tab for all "+strconv.Itoa(len(models))+" of them") + "\n")
	}
	return b.String()
}

func (m model) renderDeposit() string {
	var b strings.Builder
	b.WriteString("  " + m.st.title.Render("deposit") + "\n\n")
	b.WriteString("  " + m.st.label.Render("sending to") + "  " + m.st.value.Render(m.deps.Treasury.Address) + "\n")
	b.WriteString("  " + m.st.label.Render("rate") + "        " + m.st.value.Render(
		FormatUSD(m.deps.Treasury.SolPriceUSD)+" of credit per SOL") + "\n\n")
	b.WriteString("  " + m.st.label.Render("amount") + "      " + m.amountField() + "\n\n")

	if !m.deps.Proven {
		b.WriteString("  " + m.st.warn.Render("This address was named, not proved, so a deposit cannot be signed.") + "\n")
		if m.deps.Local {
			b.WriteString("  " + m.st.dim.Render("Add the key for it to your ssh-agent and pick it from the list:") + "\n")
			b.WriteString("  " + m.st.accent.Render("ssh-add ~/.ssh/id_ed25519") + "\n")
		} else {
			b.WriteString("  " + m.st.dim.Render("Forward an agent holding this address's key and reconnect with") + "\n")
			b.WriteString("  " + m.st.dim.Render("the -A:") + "\n")
			b.WriteString("  " + m.st.accent.Render("ssh-add ~/.ssh/id_ed25519 && ssh -A -i ~/.ssh/id_ed25519 "+m.endpointHost()) + "\n")
		}
	} else if m.deps.SockPath == "" {
		if m.deps.Local {
			b.WriteString("  " + m.st.errText.Render("there is no ssh-agent here, so there is nothing that can sign.") + "\n")
			b.WriteString("  " + m.st.dim.Render("set one up and add the key:") + "\n")
			b.WriteString("  " + m.st.accent.Render("eval $(ssh-agent -s) && ssh-add ~/.ssh/id_ed25519") + "\n")
		} else {
			b.WriteString("  " + m.st.errText.Render("this session has no forwarded agent, so there is nothing here that can sign.") + "\n")
			b.WriteString("  " + m.st.dim.Render("reconnect with:  ssh -A "+Domain) + "\n")
		}
	} else {
		b.WriteString("  " + m.st.dim.Render("Your key stays on your machine. This server asks your agent to sign and") + "\n")
		b.WriteString("  " + m.st.dim.Render("never sees it. The transfer is checked against what was asked for") + "\n")
		b.WriteString("  " + m.st.dim.Render("before anything is broadcast.") + "\n")
	}
	b.WriteString("\n  " + m.focusHint() + "\n")
	return b.String()
}

// amountField is the amount as it appears on the deposit screen, highlighted
// while it is taking keystrokes and quiet while it is not.
//
// The two states differ in more than colour: the focused one carries a block
// cursor and a trailing space to sit in, so a field with a number in it and a
// field with nothing in it are visibly the same width of thing rather than
// appearing and disappearing.
func (m model) amountField() string {
	text := m.amount + " SOL"
	if !m.focus {
		return m.st.idle.Render(text)
	}
	return m.st.caret.Render(text + " \u2588")
}

// focusHint is the line under the deposit screen that says what the next
// keystroke will do, which on a screen with an optional field is not a fixed
// footer.
func (m model) focusHint() string {
	if m.focus {
		return m.st.key.Render("enter") + m.st.dim.Render(" to send    ") +
			m.st.key.Render("tab") + m.st.dim.Render(" to the next page    ") +
			m.st.key.Render("esc") + m.st.dim.Render(" to stop typing")
	}
	return m.st.key.Render("tab") + m.st.dim.Render(" to type an amount")
}

// keysPage is the api keys screen without the list in it: the title above and
// everything under. Returned as two halves so the list can be sized to what
// is left between them, which is the only way to be sure the hint underneath
// is still on the screen afterwards.
func (m model) keysPage() (head, tail string) {
	var h, t strings.Builder
	h.WriteString("  " + m.st.title.Render("api keys") + "\n\n")

	t.WriteString("  " + m.st.key.Render("n") + m.st.dim.Render(" mint a new key    ") +
		m.st.key.Render("enter") + m.st.dim.Render(" revoke the selected one") + "\n")
	t.WriteString("\n  " + m.listHint("to revoke it") + "\n")
	if m.fresh != "" {
		t.WriteString("\n  " + m.st.key.Render("y") + m.st.dim.Render(" copy the key above") + "\n")
	}
	head, tail = h.String(), t.String()

	// The reassurance underneath it - that a key is printed once and that
	// losing one costs nothing - is the first thing on this page to be left
	// off when the terminal is short, and it is asked for rather than
	// discovered: everything below it in the frame is a notice, and on this
	// page a notice can be the only copy of a key that will never be printed
	// again. A frame that cuts the reassurance to reach the key is the right
	// trade; one that cuts the key to reach the reassurance is how somebody
	// loses a key they had just made.
	//
	// Asked with the prose already counted and with the list still to have a
	// floor, because a page that fits while the list is left with nothing is
	// a page that does not fit.
	prose := "\n  " + m.st.dim.Render("A key is shown once, when it is minted; only its fingerprint is kept.") +
		"\n  " + m.st.dim.Render("Losing one is not a problem: mint another.") + "\n"
	if m.roomFor(head, tail+prose, 3) >= m.listFloor(2) {
		tail += prose
	}
	return head, tail
}

// routesPage is the routes screen without the list in it, for the same reason.
func (m model) routesPage() (head, tail string) {
	var h, t strings.Builder
	h.WriteString("  " + m.st.title.Render("routes") + "\n\n")

	t.WriteString("  " + m.st.dim.Render("ask for one by putting its name in \"model\". Prices are per million tokens,") + "\n")
	t.WriteString("  " + m.st.dim.Render("and what they are is the rate your balance is actually billed at.") + "\n")
	t.WriteString("\n  " + m.listHint("") + "\n")
	return h.String(), t.String()
}

// listHint says what the list above it will answer to, and it depends on
// whether the list has the focus. Unfocused a list takes no keys at all, and
// saying so is the whole of why pressing b from the routes screen still opens
// the balance screen.
// listHint is the line under a list.
//
// What enter means on it differs between the two, so the caller says. On the
// routes it would be a lie to offer the binding at all: a route is named in
// the request, not chosen by standing on it here.
func (m model) listHint(enterMeans string) string {
	hint := m.st.key.Render("hjkl") + m.st.dim.Render(" to move a page")
	if enterMeans != "" {
		hint += "    " + m.st.key.Render("enter") + m.st.dim.Render(" "+enterMeans)
	}
	return hint
}

// listWidth is what a list gets inside the pane, which is the inside of the
// box. The list draws its own two-space indent on each row, so this is the
// whole inner width rather than that minus two.
func (m model) listWidth() int {
	return bodyWidth(m.width)
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

// wordmark is the name on the balance screen, spelled out.
//
// Clickable, like the name at the left of the bar: both go home, and both go
// through the same click handling. Where the bar's name is a way of getting
// back, this one is what somebody lands on when they arrive, and a logo you
// cannot click is a logo that is only decoration.
//
// Left out entirely on a terminal too narrow for it rather than shrunk or cut:
// a wordmark wrapped to two half-words is worse than no wordmark, and the
// balance is on the same screen either way.
func (m *model) wordmark() string {
	if m.width < wordmarkWidth+8 {
		return ""
	}
	// The top line is the brand colour and the two under it are the same
	// colour quieter. A wordmark in one flat colour is a block of text; a
	// wordmark that fades reads as a mark.
	// Inside the box, not inside the window: centring on the window's own
	// width puts the mark one column right of everything under it, and one
	// column is all it takes for the frame to wrap the line. The box's wall is
	// one column further left again, which is where the click offset comes
	// from - a mark that is centred but not clickable is decoration.
	inside := bodyWidth(m.width)
	widest, lines := 0, strings.Split(wordmark, "\n")
	for _, line := range lines {
		widest = max(widest, lipgloss.Width(line))
	}

	var b strings.Builder
	b.WriteString("\n")
	for i, line := range lines {
		style := m.st.brandDim
		if i == 0 {
			// The top line is the brand colour and the two under it are the
			// same colour quieter. A wordmark in one flat colour is a block of
			// text; one that fades reads as a mark.
			style = m.st.brand
		}
		b.WriteString(lipgloss.PlaceHorizontal(inside, lipgloss.Center, style.Render(line)) + "\n")
	}
	b.WriteString("\n")

	// The page's line one is the bar's three, so the blank above the mark is
	// the fourth of the screen and the mark is the fifth through the seventh.
	top := barLines + 1
	m.mark = box{
		x0: 1 + (inside-widest)/2, x0y: top,
		x1: 1 + (inside-widest)/2 + widest, y1: top + len(lines) - 1,
	}
	return b.String()
}

// wordmarkWidth is how wide the name is, and how a page decides whether there
// is room for it.
const wordmarkWidth = 52

// wordmark is RouterCafe, set in a fixed-width face. Generated once with
// figlet and pasted in rather than drawn: it is a piece of lettering, not a
// layout, and nothing about it wants to be computed at runtime.
//
// The face is `big` because the point of a wordmark is that you can read it.
// The three-line shadow faces are narrower and they are not: at that size the
// strokes of R and C run into the strokes beside them and it reads as a row of
// symbols rather than as a name.
var wordmark = strings.Join([]string{
	" _____             _             _____       __",
	"|  __ \\           | |           / ____|     / _|",
	"| |__) |___  _   _| |_ ___ _ __| |     __ _| |_ ___",
	"|  _  // _ \\ | | | | __/ _ \\ '__| |    / _` |  _/ _ \\",
	"| | \\ \\ (_) | |_| | ||  __/ |  | |___| (_| | ||  __/",
	"|_|  \\_\\___/ \\__,_|\\__|\\___|_|   \\_____|\\__,_|_| \\___|",
}, "\n")

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
	return m.wrapTo(s, style, m.contentWidth())
}

// wrapTo is wrap at a width the caller has been told about rather than one it
// has to guess, which is what a pager needs: it is told how wide it is, and
// prose wrapped to any other width is prose with its last few words off the
// right-hand edge of a box that is two columns wider than the one it was
// written for.
func (m model) wrapTo(s string, style lipgloss.Style, width int) string {
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

// fit cuts a string to n display columns, so a value too long for its column
// stops rather than pushing the frame past the edge of the terminal.
//
// Measured with lipgloss.Width rather than len, because the callers pass
// styled strings and a byte count would cut a colour escape in half.
func fit(s string, n int) string {
	if n <= 0 || lipgloss.Width(s) <= n {
		return s
	}
	cut := 0
	for i, r := range s {
		if lipgloss.Width(s[:i]) > n-1 {
			return s[:cut] + "…"
		}
		cut = i + len(string(r))
	}
	return s[:cut]
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
