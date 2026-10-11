package cafe

import (
	"fmt"
	"io"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// The two screens of this program that are a list rather than a page are the
// routes you can send to and the API keys on file. Both are built from the
// same component, so navigating one of them is learning how to navigate the
// other and hjkl works identically in both.
//
// ## Why this is not `list.New` with its defaults
//
// A list answers to `b`, `d`, `f` and `u` for paging and to `k` and `j` for
// the cursor. Three of those are page shortcuts here: b is balance, d is
// deposit, k is the API keys screen. Left alone a list would swallow them, and
// the footer at the bottom of every screen - the one that says what each
// letter does - would be lying on exactly the screens where you most need it.
//
// So paging is narrowed to the keys that cannot be mistaken for leaving: the
// arrows, h, l, pgup and pgdown. The cursor keeps k and j, because a list that
// ignored them would not be one anybody expects, and because the one letter
// that conflicts is only a conflict on a screen you are not on: pressing k
// while already on the API keys screen did nothing before and does nothing
// now.
//
// Filtering and the component's own help are off rather than re-bound. A
// filter wants esc, which is a page-level key here, and this program has its
// own help screen that explains the letters in a sentence rather than in
// bubbles' abbreviated table.

// listKeyMap is the bindings a list in this program is allowed to have.
//
// Written out rather than edited from the default, so that a binding added
// upstream shows up here as an absence - the thing worth noticing - instead of
// arriving quietly in a later release and taking a page shortcut with it.
func listKeyMap() list.KeyMap {
	off := key.NewBinding()
	return list.KeyMap{
		CursorUp:   key.NewBinding(key.WithKeys("up", "k")),
		CursorDown: key.NewBinding(key.WithKeys("down", "j")),
		PrevPage:   key.NewBinding(key.WithKeys("left", "h", "pgup")),
		NextPage:   key.NewBinding(key.WithKeys("right", "l", "pgdown")),
		GoToStart:  key.NewBinding(key.WithKeys("home", "g")),
		GoToEnd:    key.NewBinding(key.WithKeys("end", "G")),

		Filter:        off,
		ClearFilter:   off,
		ShowFullHelp:  off,
		CloseFullHelp: off,
		Quit:          off,
		ForceQuit:     key.NewBinding(key.WithKeys("ctrl+c")),
	}
}

// rowItem is anything a list here can show. It is one of the two concrete
// kinds below and nothing else.
//
// FilterValue is part of list.Item and filtering is off, so it returns
// nothing: leaving the method out is not an option, and returning something
// real would be a filter nobody can start.
type rowItem interface {
	list.Item
	// lines is the row as it appears, already styled. height is how many
	// terminal lines it occupies, which is what lets one delegate serve a
	// one-line list and a two-line one.
	lines(st *styles, sel, focused bool) (text string, height int)
}

// routeItem is one row of the routes list: what it is, who serves it, what it
// costs to talk to it.
type routeItem struct {
	id       string
	provider string
	in       string
	out      string
}

func (i routeItem) FilterValue() string { return i.id }

func (i routeItem) lines(st *styles, sel, focused bool) (string, int) {
	lead, trail, marker := rowStyles(st, sel, focused)
	return marker + " " +
		pad(lead.Render(i.id), 24) +
		pad(trail.Render(i.provider), 12) +
		pad(trail.Render(i.in), 20) +
		trail.Render(i.out+" out"), 1
}

// keyItem is one row of the API keys list, which is two lines: the key, and
// when it was made and last used.
type keyItem struct {
	label   string
	created string
	touched string
}

func (i keyItem) FilterValue() string { return i.label }

func (i keyItem) lines(st *styles, sel, focused bool) (string, int) {
	lead, trail, marker := rowStyles(st, sel, focused)
	return marker + " " +
		lead.Render("rc_live_"+i.label) + "\n" +
		"     " + trail.Render("made "+i.created+", last used "+i.touched), 2
}

// rowDelegate draws the rows and knows nothing about what they mean, so both
// lists share it and neither knows the shape of the other.
type rowDelegate struct {
	// focused is copied in when the delegate is set rather than read from the
	// model: the list calls Render from inside its own View and has no way to
	// be told what the rest of the program is doing.
	focused bool
}

func (d rowDelegate) Height() int { return maxRowHeight }

func (d rowDelegate) Spacing() int { return 0 }

func (d rowDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

func (d rowDelegate) Render(w io.Writer, m list.Model, index int, it list.Item) {
	row, ok := it.(rowItem)
	if !ok {
		return
	}
	text, _ := row.lines(&navStyles, index == m.Index(), d.focused)
	fmt.Fprint(w, text+"\n")
}

// maxRowHeight is the tallest row the delegate will be asked to draw. The
// component asks its delegate once for a height and gives every row that
// much, so this is the maximum over the items rather than each row's own.
var maxRowHeight = 2

// navStyles is the palette the delegates draw with.
//
// A package variable rather than a parameter because the delegate is handed to
// the list by value and the list calls Render long after the model that built
// it is gone; threading the styles through every Render call would mean
// rebuilding the delegate on every frame for no gain, since there is exactly
// one stylesheet in this program.
var navStyles = newStyles()

// rowStyles is how one row is drawn: the part that reads as the subject of
// the row, the part that is detail, and the cursor marker.
//
// Unfocused, the cursor is still drawn - there is no way to tell where a
// following enter would act without it - but quieter, so that "nothing here
// moves until you tab into it" is legible without having to read anything.
func rowStyles(st *styles, sel, focused bool) (lead, trail lipgloss.Style, marker string) {
	switch {
	case sel && focused:
		return st.caret, st.caret, st.caret.Render(">")
	case sel:
		return st.accent, st.dim, st.dim.Render(">")
	default:
		return st.value, st.dim, " "
	}
}

// routesList builds the list of routes, sized to the space it was given.
func routesList(catalogue *Catalogue, width, height int, focused bool) list.Model {
	models := catalogue.Models()
	items := make([]list.Item, 0, len(models))
	for _, route := range models {
		items = append(items, routeItem{
			id:       route.ID,
			provider: route.Provider,
			in:       perMTok(route.InputPerMTok),
			out:      perMTok(route.OutputPerMTok),
		})
	}
	return newNavList(items, width, height, focused, "route", "routes", 1)
}

// keysList builds the list of API keys on file.
func keysList(acct Account, width, height int, focused bool) list.Model {
	items := make([]list.Item, 0, len(acct.Keys))
	for _, k := range acct.Keys {
		items = append(items, keyItem{
			label:   k.Label,
			created: ago(k.Created),
			touched: ago(k.Touched),
		})
	}
	return newNavList(items, width, height, focused, "key", "keys", 2)
}

// newNavList is the one place a list is configured, so both of them get the
// same keymap, the same chrome and the same focus treatment without either
// screen having to know the other exists.
func newNavList(items []list.Item, width, height int, focused bool, one, many string, perRow int) list.Model {
	l := list.New(items, rowDelegate{focused: focused}, width, height)
	l.KeyMap = listKeyMap()
	l.SetShowTitle(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(false)
	l.SetShowFilter(false)
	l.SetStatusBarItemName(one, many)

	// The component counts its height in rows and this program counts in
	// terminal lines, so a two-line row halves how many fit. Three is the
	// floor: below that there is no room to move the cursor and say so.
	rows := height / perRow
	if rows < 3 {
		rows = 3
	}
	l.SetHeight(rows)

	dim := navStyles.dim
	l.Styles.StatusBar = l.Styles.StatusBar.PaddingLeft(2).Foreground(dim.GetForeground())
	l.Styles.StatusEmpty = l.Styles.StatusEmpty.PaddingLeft(2).Foreground(dim.GetForeground())
	l.Styles.NoItems = l.Styles.NoItems.PaddingLeft(2).Foreground(dim.GetForeground())
	l.Styles.PaginationStyle = l.Styles.PaginationStyle.PaddingLeft(2).Foreground(dim.GetForeground())

	l.SetDelegate(rowDelegate{focused: focused})
	return l
}

// nav is the list the current screen is showing, or nil on a screen with none.
func (m *model) nav() *list.Model {
	switch m.view {
	case screenKeys:
		return &m.apiKeys
	case screenModels:
		return &m.routes
	}
	return nil
}

// paintFocus tells whichever list is on screen whether it has the focus, so
// that the cursor is drawn differently and not merely behaves differently.
//
// A caret that moved but did not light up would leave the question "does
// anything here respond to what I just pressed" answerable only by pressing
// something else and finding out.
func (m *model) paintFocus() {
	if l := m.nav(); l != nil {
		l.SetDelegate(rowDelegate{focused: m.focus})
	}
}

// syncLists rebuilds both lists from the state they show.
//
// Not built once at construction because both change underneath the model:
// minting and revoking are changes to the account, and a session can be opened
// against a catalogue that is not the one the process started with.
//
// The cursor survives, clamped. Refreshing is a background thing that happens
// while somebody is looking at the list, and a refresh that threw them back to
// the top would move the target out from under a following enter.
func (m *model) syncLists() {
	idx := m.apiKeys.Index()
	m.routes = routesList(m.deps.catalogue(), m.listWidth(), m.listHeight(1), m.focus)
	m.apiKeys = keysList(m.account, m.listWidth(), m.listHeight(2), m.focus)
	if n := len(m.account.Keys); n > 0 {
		if idx >= n {
			idx = n - 1
		}
		if idx < 0 {
			idx = 0
		}
		m.apiKeys.Select(idx)
	}
}
