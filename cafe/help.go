package cafe

import (
	"strconv"
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

// faqItem is one question in the list, and whether its answer is showing.
//
// Open on the row itself, not only by what is under the list. A page that
// changes under the cursor and changes back when the cursor moves away is a
// cursor, and somebody reading two answers wants to see that both are open.
//
// It is a field on the item rather than something the delegate looks up
// because the delegate cannot see the model - see `navStyles` in listnav.go -
// so the list is rebuilt when the set changes, which is seven items and a
// keystroke.
type faqItem struct {
	n    int
	open bool
}

func (i faqItem) FilterValue() string { return faqs[i.n].q }

func (i faqItem) lines(st *styles, sel, focused bool) (string, int) {
	lead, trail, marker := rowStyles(st, sel, focused)
	if i.open {
		return marker + " " + lead.Render("v ") + trail.Render(faqs[i.n].q), 1
	}
	return marker + " " + trail.Render(faqs[i.n].q), 1
}

// faqsList builds the list of questions.
func faqsList(width int, focused bool, open map[int]bool) list.Model {
	items := make([]list.Item, 0, len(faqs))
	for i := range faqs {
		items = append(items, faqItem{n: i, open: open[i]})
	}
	return newNavList(items, width, focused, "question", "questions", 1)
}

// faqPage is the page: the questions as a list, and under it the answers of
// whichever ones are open.
//
// Split that way because an answer is not one line, and a row that grew to hold
// one would push the rest of the page off the bottom every time somebody
// opened a long question.
func (m model) faqPage() (head, tail string) {
	// Nothing above the list: the questions are the page, and the answers
	// belong under the thing they answer rather than over it.
	var t strings.Builder
	if n := len(m.open); n == 0 {
		t.WriteString("  " + m.st.dim.Render("enter on a question to open its answer") + "\n")
	} else {
		t.WriteString("  " + m.st.dim.Render(strconv.Itoa(n)+" open") +
			m.st.dim.Render(", enter on another to open it too") + "\n")
	}
	t.WriteString("\n  " + m.st.dim.Render("the same questions as "+Domain+"'s landing page") + "\n")
	return "", m.openAnswers() + "\n" + t.String()
}

// openAnswers is the block under the list: the answer of every question that is
// open, each under its own question so that it is answerable on its own.
func (m model) openAnswers() string {
	var b strings.Builder
	for _, n := range sortedKeys(m.open) {
		b.WriteString("\n  " + m.st.title.Render(faqs[n].q) + "\n")
		b.WriteString(m.wrap(m.st.dim.Render(faqs[n].a), m.st.dim) + "\n")
	}
	return b.String()
}

// sortedKeys is a map's keys in order, because the answers come out in the
// order the questions are asked in rather than in Go's map order, which is not
// an order at all.
func sortedKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// toggleFAQ opens the question under the cursor, or closes it if it is open.
func (m *model) toggleFAQ() {
	i := m.faqs.Index()
	if i < 0 || i >= len(faqs) {
		return
	}
	if m.open[i] {
		delete(m.open, i)
	} else {
		m.open[i] = true
	}
	m.faqs = faqsList(m.listWidth(), m.focus, m.open)
	m.faqs.Select(i)
	m.paintFocus()
}
