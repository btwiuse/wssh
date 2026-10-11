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
	brandLines   = 1
	footerLines  = 1
	barLines     = 3
	topEdgeLines = 1
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
	// A bar carries the brand on its own line, so there is nothing above it to
	// spend a line on. The three screens with no bar still get the brand line
	// and the line their top edge is drawn on.
	chrome := footerLines
	if bar != "" {
		chrome += barLines
	} else {
		chrome += brandLines + topEdgeLines
	}
	box := height - chrome
	if box < 3 {
		box = 3
	}

	var b strings.Builder
	if bar != "" {
		b.WriteString(bar)
	} else {
		// No bar, so the name goes on a line of its own - together with the
		// box's missing top edge. On a screen with a bar that edge is the
		// bar's bottom edge; with no bar there is nothing at all along the
		// top, and a frame open along one whole side reads as a panel still
		// loading rather than as a window. Drawn in the box's own colour, so
		// it is indistinguishable from the one the bar would have supplied.
		b.WriteString(st.brand.Render("RouterCafe"))
		// The domain is dropped rather than wrapped when there is no room for
		// it. A brand line that breaks in two on a narrow terminal is worse
		// than a brand line without the address on it, and the address is in
		// the help screen and the landing page anyway.
		gap := width - lipgloss.Width("RouterCafe") - lipgloss.Width(Domain)
		if gap >= 1 {
			b.WriteString(strings.Repeat(" ", gap))
			b.WriteString(st.dim.Render(Domain))
		}
		b.WriteString("\n" + edge.Render(strings.Repeat("\u2500", width)))
	}
	// The page is wrapped to the inside of the box before it is counted.
	// lipgloss wraps whatever is wider than that on its way into the border,
	// and counting the lines before it has done that is how a page of long
	// sentences comes out several lines taller than the window it is supposed
	// to be filling - the cut then happens in the wrong place entirely.
	wrapped := lipgloss.NewStyle().Width(bodyWidth(width)).Render(body)
	// And it is cut here rather than by MaxHeight, because MaxHeight cuts
	// from the bottom of the rendered box and the last thing it takes is the
	// bottom edge: a page with more on it than the window can show would
	// leave the frame open along one whole side. Cutting the page first means
	// the frame is closed whatever the page has on it, and what is lost is
	// prose.
	//
	// Width and Height are the total including the border, which is what makes
	// the box reach the edges of the terminal rather than stopping two columns
	// short of them. Height alone because the page has already been cut to
	// fit: the box is filling a fixed number of lines with what it was given.
	b.WriteString("\n" + st.window.
		Width(width).MaxWidth(width).
		Height(box).Render(trimLines(wrapped, box-1)))
	if footer != "" {
		b.WriteString("\n" + footer)
	}
	return b.String()
}

// edge is the box's own border colour, for the parts of its outline that are
// not the border: the top edge on the screens with no bar, and the run of it
// between the end of the tab bar and the right-hand corner.
var edge = lipgloss.NewStyle().Foreground(lipgloss.Color("#334155"))

// trimLines cuts a page to the n lines it is allowed, counting the lines it
// has rather than its bytes, so a page carrying colour escapes is not cut in
// the middle of one.
func trimLines(s string, n int) string {
	if n < 0 {
		n = 0
	}
	lines := strings.Split(s, "\n")
	// A trailing newline closes the last line rather than starting one, so it
	// is not a line of its own to count.
	if last := len(lines) - 1; last >= 0 && lines[last] == "" {
		lines = lines[:last]
	}
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:n], "\n")
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
