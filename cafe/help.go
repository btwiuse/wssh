package cafe

import (
	"strings"

	"charm.land/bubbles/v2/list"
)

// The FAQs screen.
//
// The only page here that is a list of questions rather than of things, and the
// only one with anything to expand. An answer is either on the screen or it is
// not, and a page with all seven of them at once is a page of prose with a
// scrollbar on it - so the questions are the list, the cursor moves between them
// the way it moves between API keys, and `enter` opens the one under it.
//
// The answers are the landing page's, from its "Questions people actually ask".
// One copy of them, kept here: the same seven questions answered twice is how
// the two stop agreeing.
type faq struct{ q, a string }

var faqs = []faq{
	{
		"Why not just use OpenRouter?",
		"You may well. RouterCafe is the same shape with two differences: you pay in SOL from the " +
			"terminal, and the front end is a terminal session rather than a dashboard. If you want " +
			"a web console and a card, they are the better product.",
	},
	{
		"What does a deposit cost?",
		"The Solana network fee, which is a few thousand lamports, taken out of the amount you " +
			"send. Deposits below roughly 0.00001 SOL are refused rather than spent entirely on " +
			"the fee, and the deposit screen says so before you sign anything.",
	},
	{
		"Why does it need ssh -A?",
		"Because that is how it asks your key to sign. Without agent forwarding there is no way " +
			"for the server to reach a key that is on your machine, and it would have to ask you " +
			"to hand it over, which is exactly the thing it should not do. The deposit screen " +
			"says this rather than failing quietly.",
	},
	{
		"Can I use a wallet instead of an SSH key?",
		"Yes. The browser terminal at /app signs in with a Solana wallet and shows the " +
			"transaction for you to approve before it is sent, which is the same flow through a " +
			"different key holder.",
	},
	{
		"What happens to my key if it leaks?",
		"Go to the api keys, press x on it, and mint another. The balance belongs to the account " +
			"rather than to the key, so revoking one does not touch your credit. A key is shown " +
			"once, when it is minted, and only its fingerprint is kept.",
	},
	{
		"Is the rate fixed?",
		"The SOL price is set by whoever runs this instance and recorded on every deposit, so " +
			"what you were credited at cannot change afterwards. It is shown on the deposit " +
			"screen before you sign anything.",
	},
	{
		"Can I self-host it?",
		"Yes. It is one binary and a few flags: cafe --treasury <address> --upstream <url> " +
			"--upstream-key <key>. The ledger is a JSON file; back it up or do not.",
	},
}

// faqItem is one question and its answer, wrapped when the list was built.
//
// **The answer is always there.** It was a disclosure - `enter` to open one -
// and it was wrong twice over: the answers came out below the whole list rather
// than under the question they answer, and a row that grew to hold an answer
// pushed the rest of the page off the bottom every time one was opened. So
// every question carries its answer, the rows are as tall as the longest one,
// and the list pages over them. Seven questions over four pages at a hundred
// columns is not a problem; an answer that appears somewhere else is.
type faqItem struct {
	n    int
	body []string
}

func (i faqItem) FilterValue() string { return faqs[i.n].q }

// lines is the whole block: the question with the cursor beside it, then the
// answer under it.
//
// No blank after the answer: the component already puts one between rows, and
// a second one costs a row a page for nothing.
func (i faqItem) lines(st *styles, sel, focused bool) (string, int) {
	lead, trail, marker := rowStyles(st, sel, focused)
	out := []string{marker + " " + lead.Render(faqs[i.n].q)}
	for _, line := range i.body {
		out = append(out, "  "+trail.Render(line))
	}
	return strings.Join(out, "\n"), len(out)
}

// faqsList builds the list of questions with their answers wrapped to the width
// the list has.
func faqsList(width int, focused bool) list.Model {
	items := make([]list.Item, 0, len(faqs))
	for i, f := range faqs {
		items = append(items, faqItem{n: i, body: wrapPlain(f.a, faqInner(width))})
	}
	return newNavListOfHeight(items, width, focused, "question", "questions", 1, faqRowHeight(width))
}

// faqInner is how wide an answer is written at, which is the list's width less
// the indent the rows carry.
func faqInner(width int) int { return max(20, width-4) }

// faqRowHeight is how tall a question and its answer are: the question, plus
// the longest answer on the page.
//
// The component asks its delegate once for a row height and gives every row
// that much, so this is one number for the whole list and the shorter answers
// are padded. It is read here as well as when the list is built, because the
// frame replaces the delegate on every frame and a delegate that has lost its
// height turns every entry back into a single line.
func faqRowHeight(width int) int {
	tallest := 1
	for _, f := range faqs {
		tallest = max(tallest, len(wrapPlain(f.a, faqInner(width))))
	}
	return tallest + 1
}

// wrapPlain breaks a paragraph into lines of at most n columns, on spaces.
//
// Plain rather than lipgloss's Wrap, for the reason the rest of this program
// does its own wrapping: that one is happy to lose a token too long for a
// line, and a URL in an answer has to survive.
func wrapPlain(s string, n int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var out []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > n {
			out = append(out, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(out, line)
}

// faqPage is the page: the questions, with their answers, as a list.
func (m model) faqPage() (head, tail string) { return "", m.faqTail() }

// faqTail is the line under the list.
func (m model) faqTail() string {
	return "  " + m.st.dim.Render("the same questions as "+Domain+"'s landing page") + "\n"
}
