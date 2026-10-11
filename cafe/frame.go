package cafe

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// The chrome every screen in this program wears.
//
// Three screens use it: the account screen, the screen a connection that
// proved nothing gets, and the one that refuses. They have to come out the
// same size, and that is not a tidiness point.
//
// A frame the height of its content is a different shape from a frame the
// height of the window, so moving between a screen with a lot on it and one
// with a little changes the size of everything - and the moment somebody
// notices is the moment after signing, when the box they were typing an
// address into is replaced by one twice as tall. It reads as the program
// having been swapped rather than the same program having changed page.

// chromeLines is what the frame spends on everything that is not the page: the
// brand line and the footer, plus the bar where there is one.
const (
	brandLines  = 1
	footerLines = 1
	barLines    = 3
)

// frame draws one screen: brand line, optional bar, page in a box, footer.
//
// The bar is empty for the screens that have no pages to move between. That
// makes those three lines shorter than the account screen's, which is the one
// place the frames are not identical - and it is deliberate, because a bar of
// five pages on a screen where four of them would refuse you is a lie about
// where you can go.
func frame(st styles, width, height int, bar, body, footer string) string {
	if width < 20 {
		width = 20
	}
	chrome := brandLines + footerLines
	if bar != "" {
		chrome += barLines
	}
	box := height - chrome
	if box < 3 {
		box = 3
	}

	var b strings.Builder
	b.WriteString(st.brand.Render("RouterCafe"))
	// The domain is dropped rather than wrapped when there is no room for it.
	// A brand line that breaks in two on a narrow terminal is worse than a
	// brand line without the address on it, and the address is in the help
	// screen and the landing page anyway.
	gap := width - lipgloss.Width("RouterCafe") - lipgloss.Width(Domain)
	if gap >= 1 {
		b.WriteString(strings.Repeat(" ", gap))
		b.WriteString(st.dim.Render(Domain))
	}
	if bar != "" {
		b.WriteString("\n" + bar)
	}
	// Width and Height are the total including the border, which is what makes
	// the box reach the edges of the terminal rather than stopping two columns
	// short of them.
	// MaxHeight and MaxWidth as well as Height and Width, because a page with
	// more content than fits must be cut rather than be allowed to push the
	// frame past the bottom of the terminal - a frame that grows with its
	// contents is the inconsistency this whole thing is here to remove. The
	// lists are sized to fit, so what gets cut is prose and the cut is visible.
	b.WriteString("\n" + st.window.
		Width(width).MaxWidth(width).
		Height(box).MaxHeight(box).
		Render(body))
	if footer != "" {
		b.WriteString("\n" + footer)
	}
	return b.String()
}

// bodyWidth is how much of the page there is to write in once the box's two
// walls are taken off the window.
//
// Two, not four: wrapText indents every line by two of its own and takes them
// off again, so passing width-2 here hands it the whole inside of the box and
// letting it do its own arithmetic. Passing width-4 counted the indent twice
// and quietly cut a token that used to fit.
func bodyWidth(width int) int {
	w := width - 2
	if w < 12 {
		w = 12
	}
	return w
}
