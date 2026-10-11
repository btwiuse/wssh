package cafe

import (
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
)

// The help screen.
//
// It is the one page in this program with more on it than a terminal shows.
// Every other page is either short or is a list, and a list already knows how
// to page itself; this one is prose in sentences and does not fit a laptop
// screen at the size the sentences were written for. It was drawn in full and
// the frame cut it, which meant the bottom of every page - including the
// version line and the "what this is not" - was invisible on exactly the
// terminals that had least room, and the missing text looked like the screen
// had failed rather than like there was more of it.
//
// So it is a viewport: the same component the rest of this program's prose
// would use if it had more of it, sized to the box, with the mouse wheel
// working because bubbles turns that on by default.

// helpKeys is what the pager is allowed to have.
//
// Written out rather than edited from the default, because the default is a
// pager's keymap and this is not quite a pager: it claims `space`, `b`, `d`,
// `f` and `u` for scrolling, and the two of those that are letters are letters
// this program means something else by. Narrowed to the keys that cannot be
// confused with leaving, in the same way the two lists are - see listnav.go,
// and for the same reason: a key the component swallows is a key the person
// pressing it is not told about anywhere else.
var helpKeys = map[string]bool{
	"up": true, "k": true, "down": true, "j": true,
	"pgup": true, "pgdown": true, "home": true, "end": true, "g": true, "G": true,
}

// newHelp is a pager with the keymap above rather than the default one.
func newHelp() viewport.Model {
	v := viewport.New()
	v.KeyMap = viewport.KeyMap{
		PageUp:       key.NewBinding(key.WithKeys("pgup")),
		PageDown:     key.NewBinding(key.WithKeys("pgdown")),
		HalfPageUp:   key.NewBinding(),
		HalfPageDown: key.NewBinding(),
		Up:           key.NewBinding(key.WithKeys("up", "k")),
		Down:         key.NewBinding(key.WithKeys("down", "j")),
		Left:         key.NewBinding(),
		Right:        key.NewBinding(),
	}
	// GoToStart and GoToEnd are not part of the viewport's keymap, so home,
	// end, g and G are handled here rather than by the component.
	return v
}

// scrollHelp is the whole pager: the keys it takes, plus the two a viewport
// has no binding for.
func (m model) scrollHelp(msg tea.KeyPressMsg) model {
	switch msg.String() {
	case "home", "g":
		m.help.GotoTop()
		return m
	case "end", "G":
		m.help.GotoBottom()
		return m
	}
	m.help, _ = m.help.Update(msg)
	return m
}

// helpOverflows is whether there is anything below the fold, which is what the
// footer says. Without it the hint claims the page scrolls on a terminal
// where it does not.
func (m model) helpOverflows() bool {
	return strings.Count(m.help.GetContent(), "\n")+1 > m.help.Height()
}

// renderHelp is the page inside the pager, which is otherwise just a window
// onto the help: the text and the size are set by sizeHelp, on a resize.
func (m model) renderHelp() string {
	m.help = m.helpPager()
	return m.help.View()
}

// sizeHelp fits the pager to the box, when the window changes.
//
// Not in renderHelp, which draws it: this program's View is a value receiver
// and everything it touches inside a render is thrown away when the frame is
// printed. A pager sized and filled during the draw is a pager of height zero
// with no content in it by the time the next keystroke arrives, and a pager
// that believes it has no room does not scroll. Same trap the two lists were
// nearly caught by, and the reason they are sized by the page rather than by
// the component.
func (m *model) sizeHelp() { m.help = m.helpPager() }

// helpPager is the pager as this window wants it: the right size, and filled
// with the help laid out at the width it will be read at.
//
// One definition used from two places on purpose. sizeHelp keeps the model
// carrying a pager that scrolls, because a pager that only knows its size
// during the frame it was drawn in is a pager of height zero by the time the
// next keystroke arrives. renderHelp sets it up on its own copy, because a
// model built by hand in a test never went near a window size and would
// otherwise draw an empty box.
func (m *model) helpPager() viewport.Model {
	m.help.SetWidth(bodyWidth(m.width))
	m.help.SetHeight(m.pageRoom())
	m.help.SetContent(m.helpText())
	return m.help
}

// helpText is the whole of the help, as prose, before the pager has had it.
func (m model) helpText() string {
	var b strings.Builder
	b.WriteString("  " + m.st.value.Render("An OpenRouter you reach with ssh, paid for in SOL.") + "\n\n")
	for _, k := range [][2]string{
		{"tab", "next page, and into the field when a page has one"},
		{"shift+tab", "previous page"},
		{"hjkl", "move through a list, and page it with h and l"},
		{"enter", "act on where the cursor is, or on the field"},
		{"esc", "put the caret down without leaving the page"},
		{"r", "re-read the balance"},
		{"y", "copy a key just minted, using OSC 52"},
		{"n", "mint a new API key"},
		{"q", "disconnect"},
	} {
		b.WriteString("  " + m.st.label.Render(pad(k[0], 10)) + m.st.dim.Render(k[1]) + "\n")
	}
	b.WriteString("\n")
	wide := m.wrapWidth()
	b.WriteString(m.wrapTo("There are no letters that jump between pages. The bar at the top is the whole of "+"the navigation, so nothing has to be remembered and nothing can mean two things on the same screen.", m.st.dim, wide) + "\n\n")

	b.WriteString("  " + m.st.title.Render("what this is not") + "\n\n")
	b.WriteString(m.wrapTo("There is no shell here. Nothing you type is run on this machine, because there is no way to ask it to: the session is a program, not a command line, and a command sent instead of a shell is ignored.", m.st.dim, wide) + "\n\n")
	b.WriteString(m.wrapTo("Your private key never leaves your machine. This server asks the agent you forwarded with ssh -A, and checks the transaction it gets back. The same, more carefully, is at "+Domain+".", m.st.dim, wide) + "\n")
	return b.String()
}

// wrapWidth is how wide the help's sentences are laid out: the inside of the
// pager, less the indent wrapTo puts on every line.
func (m model) wrapWidth() int {
	return bodyWidth(m.width) - 2
}
