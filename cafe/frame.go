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

// frame draws one screen: brand line, optional bar, page in a box, the line at
// the foot of the page, and the footer.
//
// The bar is empty for the screens that have no pages to move between. That
// makes those three lines shorter than the account screen's, which is the one
// place the frames are not identical - and it is deliberate, because a bar of
// five pages on a screen where four of them would refuse you is a lie about
// where you can go.
func frame(st styles, width, height int, bar, body, hint, footer string) string {
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
		// The name and the address, set in from the edges by the same two
		// columns the bar sets them in by. On the screens with a bar they sit
		// at the ends of that line, and a screen without one whose name is
		// hard against column 0 looks like the same line drawn by somebody
		// else.
		b.WriteString(strings.Repeat(" ", barMargin) + st.brand.Render("RouterCafe"))
		// The domain is dropped rather than wrapped when there is no room for
		// it. A brand line that breaks in two on a narrow terminal is worse
		// than a brand line without the address on it, and the address is in
		// the help screen and the landing page anyway.
		gap := width - barMargin*2 - lipgloss.Width("RouterCafe") - lipgloss.Width(Domain)
		if gap >= 1 {
			b.WriteString(strings.Repeat(" ", gap))
			b.WriteString(st.dim.Render(Domain) + strings.Repeat(" ", barMargin))
		}
		// The edge is drawn here and not by the box, and it is drawn with the
		// corners the box would have had: this line is the box's top edge, so
		// it turns down into the box's own walls at both ends. A run of plain
		// rule here is a lid that overhangs the box on each side - open
		// underneath at the two corners, which is the shape a frame is not
		// allowed to be.
		b.WriteString("\n" + edge(st).Render(topEdge(width)))
	}
	// The page is wrapped to the inside of the box before it is counted.
	// lipgloss wraps whatever is wider than that on its way into the border,
	// and counting the lines before it has done that is how a page of long
	// sentences comes out several lines taller than the window it is supposed
	// to be filling - the cut then happens in the wrong place entirely.
	// The page keeps room for the line at its foot, so that a page with more on
	// it than fits loses prose rather than losing the one line that is the same
	// on every page. The frame cuts from the bottom, and the hint is the bottom.
	room := box - 1 - countLines(hint)
	// Wrapped first, then counted, then cut - in that order, because lipgloss
	// wraps whatever is too wide on the way into the border. Counting before it
	// has done that is how a page of long rows comes out three lines taller
	// than the window it is supposed to be filling.
	page := trimLines(lipgloss.NewStyle().Width(bodyWidth(width)).Render(body), room)
	if hint == "" {
		b.WriteString("\n" + st.window.
			Width(width).MaxWidth(width).
			Height(box).Render(page))
		if footer != "" {
			b.WriteString("\n" + footer)
		}
		return b.String()
	}
	// And then pushed to the foot of the box. A page is short more often than
	// it is long, and a hint that floats half way down one reads as part of the
	// prose above it rather than as the line every page ends on.
	for gap := room - countLines(page); gap > 0; gap-- {
		page += "\n"
	}
	wrapped := page + "\n" + hint
	b.WriteString("\n" + st.window.
		Width(width).MaxWidth(width).
		Height(box).Render(wrapped))
	if footer != "" {
		b.WriteString("\n" + footer)
	}
	return b.String()
}

// topEdge is the line across the top of a box that has no bar over it: the
// box's own top border, corners and all.
//
// It is a function of the width rather than a run of rule, because the two
// ends are the whole of it. The box is drawn with its top unset so that a bar
// can supply the edge instead; on the two screens with no bar the edge has to
// come from here, and a run of rule with no corner on it at either end is a
// frame open along its top at both corners.
func topEdge(width int) string {
	if width < 2 {
		return strings.Repeat("\u2500", max(0, width))
	}
	return "\u250c" + strings.Repeat("\u2500", width-2) + "\u2510"
}

// edge is the box's own border colour, for the parts of its outline that the
// border itself does not draw: the top edge on the screens with no bar.
//
// Taken from the box rather than written out, because a top edge in a
// different colour from the walls either end of it is not an edge.
func edge(st styles) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(st.window.GetBorderTopForeground())
}

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
