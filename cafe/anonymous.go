package cafe

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/routercafe/routercafe/solana"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// What a session that proved nothing does.
//
// A server that accepts "none" accepts it from everybody, because a client
// sends it first as a probe and the handshake ends there. So opening the door
// for somebody who has no key also means every client arrives with no key, and
// the question "who is this" can no longer be answered by SSH. It has to be
// answered by something the client does after connecting.
//
// What it does here: if the session forwarded an agent, the keys in that agent
// are offered, and whichever one is chosen is proved by having the agent sign a
// nonce this server made up. Not "the client says it has this key" - the agent
// signs, and a signature that verifies is possession.
//
// With no agent there is still somewhere to go, because naming an account is
// not proof and does not need to be: it is a view, and a view is what somebody
// who only wanted to look came for. So the same screen that offers the agent's
// keys also takes an address, and the two differ in exactly one way - a key
// gets signed for, an address does not - which is the difference between
// read-only and not.

// anonymousModel is the screen for a session that proved nothing: the keys the
// agent holds, and the address of an account somebody would rather only look at.
type anonymousModel struct {
	deps deps
	st   styles

	keys []*agent.Key

	// typed is the address row, which is the last row of the list whether or
	// not there are keys above it. Always present, so the screen has somewhere
	// to go on a connection that forwarded no agent.
	typed string

	width   int
	height  int
	picked  int
	notice  notice
	busy    string
	keysErr string
}

func (m anonymousModel) Init() tea.Cmd {
	// A named account is a view rather than a wall, and the same agent that
	// would let somebody adopt a key can also prove one they already named.
	if m.deps.Address != "" {
		return proveCmd(m.deps.SockPath, m.deps.Address)
	}
	// Listed once at open rather than on a keystroke: the agent is on the
	// far end of a channel and answering is not instant, and a person who
	// has just connected is waiting to find out whether there is anything here.
	if m.keysErr == "" && len(m.keys) == 0 {
		return listKeysCmd(m.deps.SockPath)
	}
	return nil
}

// keysListedMsg is the agent's answer to being asked what it holds.
type keysListedMsg struct {
	keys []*agent.Key
	err  error
}

// nonceSignedMsg is the outcome of adopting a key out of the agent.
type nonceSignedMsg struct {
	address string
	err     error
}

// provenMsg reports whether an agent turned out to hold the key for an address
// the session had already named. A false one is not a failure: most agents will
// not, and the session is still a perfectly good read-only view.
type provenMsg struct{ proven bool }

func (m anonymousModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case keysListedMsg:
		if msg.err != nil {
			m.keysErr = msg.err.Error()
			return m, nil
		}
		m.keys = orderableKeys(msg.keys)
		if len(m.keys) == 0 {
			m.keysErr = "the forwarded agent holds no keys"
		}
		return m, nil

	case provenMsg:
		// Silent either way: somebody reading somebody else's balance is the
		// ordinary case for this screen, not an error worth reporting.
		if msg.proven {
			m.deps.Proven = true
		}
		return m, nil

	case nonceSignedMsg:
		m.busy = ""
		if msg.err != nil {
			m.notice = notice{noticeBad, msg.err.Error()}
			return m, nil
		}
		// Proved. From here this is an ordinary session, so the screen it was
		// refused a moment ago is what it gets.
		d := m.deps
		d.Address, d.Proven = msg.address, true
		return intoAccount(d, m.width, m.height), nil

	case tea.KeyPressMsg:
		return m.onKey(msg)
	}
	return m, nil
}

// rows is every choice on this screen, and the address field is always the last
// one of them so that it is always somewhere to go.
func (m anonymousModel) rows() int       { return len(m.keys) + 1 }
func (m anonymousModel) addressRow() int { return len(m.keys) }

// onKey is one screen with two ways through it: a key the agent holds, which
// the agent will sign for, and an address somebody types, which nothing will.
//
// A printable character always goes to the address row and takes the selection
// with it, so a person who has started typing never has to know which row they
// were on. That is also why 'q' cannot quit from this screen: q is a base58
// character and the address row is most of what the screen does.
func (m anonymousModel) onKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		if m.typed == "" {
			return m, tea.Quit
		}
		m.typed = ""
		m.picked = m.addressRow()
		return m, nil
	case "up", "ctrl+p":
		if m.picked > 0 {
			m.picked--
		}
		return m, nil
	case "down", "ctrl+n":
		if m.picked < m.rows()-1 {
			m.picked++
		}
		return m, nil
	case "backspace":
		if r := []rune(m.typed); len(r) > 0 {
			m.typed = string(r[:len(r)-1])
			m.picked = m.addressRow()
		}
		return m, nil
	case "enter":
		if m.picked == m.addressRow() {
			return m.openAddress()
		}
		if m.picked < len(m.keys) {
			m.busy = "asking the agent to sign, so this key is really yours"
			return m, adoptCmd(m.deps, m.keys[m.picked])
		}
		return m, nil
	}

	// Filtered to the alphabet an address is written in rather than accepted and
	// rejected later, so there is no state in which the row holds something
	// ValidateAddress is about to refuse. Same rule as the deposit amount.
	if len(msg.Text) == 1 && isBase58(msg.Text[0]) {
		m.typed += msg.Text
		m.picked = m.addressRow()
	}
	return m, nil
}

// openAddress takes the address the field holds and turns it into a session.
//
// It is a view and not a refusal, because that is what somebody with no key
// came for. Proven is false here no matter how many keys are listed above: a
// typed address has proved nothing. If a forwarded agent does hold that
// address's key, the ordinary session proves it on open - the same upgrade
// `ssh <address>@host` gets - and this screen does not have to know.
func (m anonymousModel) openAddress() (tea.Model, tea.Cmd) {
	address := strings.TrimSpace(m.typed)
	if address == "" {
		return m, nil
	}
	if err := ValidateAddress(address); err != nil {
		m.notice = notice{noticeBad, reasonText(err.Error())}
		return m, nil
	}
	m.notice = notice{}
	d := m.deps
	d.Address, d.Proven = address, false
	return intoAccount(d, m.width, m.height), nil
}

// intoAccount hands the session the screen it was refused a moment ago.
//
// Proven is the caller's to set, and is the whole of what separates the two
// ways in: a key the agent signed for is owned, an address somebody typed is
// only named, and everything that changes an account reads that one field.
func intoAccount(d deps, width, height int) model {
	return model{
		deps:    d,
		st:      newStyles(),
		view:    screenHome,
		account: d.Ledger.Account(d.Address),
		width:   width,
		height:  height,
	}
}

// isBase58 is the alphabet an address is written in. Zero, O, I and l are left
// out because base58 leaves them out, so taking them would only build a field
// that cannot be an address.
func isBase58(c byte) bool {
	switch {
	case c >= '1' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return c != 'l' && c != 'I' && c != 'O'
	}
	return false
}

func (m anonymousModel) View() tea.View {
	st := m.st
	var b strings.Builder
	b.WriteString("\n  " + st.brand.Render("RouterCafe") + "  " + st.dim.Render(m.deps.host()) + "\n\n")

	if m.busy != "" {
		b.WriteString(wrapText(m.busy, m.width, st.warn) + "\n")
		return ownedView(b.String())
	}

	if len(m.keys) > 0 {
		b.WriteString(wrapText("Which of these is yours?", m.width, st.title) + "\n\n")
	} else {
		if m.deps.Local {
			b.WriteString(wrapText("No ssh-agent, so nothing here can sign.", m.width, st.title) + "\n")
			b.WriteString(wrapText("An account is an ed25519 public key. Paste one to look at it:", m.width, st.dim) + "\n\n")
		} else {
			b.WriteString(wrapText("This connection proved nothing, so nothing here can sign.", m.width, st.title) + "\n")
			b.WriteString(wrapText("An account is an ed25519 public key. Paste one to look at it:", m.width, st.dim) + "\n\n")
		}
	}

	for i, k := range m.keys {
		marker, style := "  ", st.value
		if i == m.picked {
			marker, style = "> ", st.accent
		}
		b.WriteString(wrapText(marker+labelForKey(k), m.width, style) + "\n")
	}
	if len(m.keys) > 0 {
		b.WriteString("\n")
	}

	// A real failure is worth a line; "you forwarded no agent" is not, because
	// the field below is the answer to it.
	if m.keysErr != "" && !strings.Contains(m.keysErr, "forwarded no agent") {
		b.WriteString(wrapText(m.keysErr+".", m.width, st.warn) + "\n\n")
	}

	marker := "  "
	if m.picked == m.addressRow() {
		marker = "> "
	}
	b.WriteString("  " + marker + st.label.Render("address  ") +
		st.accent.Render(m.typed) + st.dim.Render("█") + "\n\n")

	if len(m.keys) == 0 {
		b.WriteString(wrapText("enter to open it", m.width, st.dim) + "\n\n")
	} else {
		b.WriteString(wrapText("up/down to choose, enter to sign with a key or open an address", m.width, st.dim) + "\n\n")
	}

	if m.notice.kind != noticeNone {
		b.WriteString(wrapText(m.notice.text, m.width, st.errText) + "\n\n")
	}
	b.WriteString(wrapText("ctrl+c to disconnect", m.width, st.dim) + "\n")
	return ownedView(b.String())
}

// host is where to tell somebody to connect, which is this server's own name.
func (d deps) host() string {
	if strings.TrimSpace(d.Host) != "" {
		return d.Host
	}
	return Domain
}

// orderableKeys keeps only the keys that name an account, and sorts them.
//
// A key that is not ed25519 is dropped rather than shown-and-then-refused:
// this screen is a list of things that will work, and a row that says no is a
// row somebody tries.
func orderableKeys(keys []*agent.Key) []*agent.Key {
	var out []*agent.Key
	for _, k := range keys {
		if k == nil || len(k.Blob) == 0 || k.Format != gossh.KeyAlgoED25519 {
			continue
		}
		out = append(out, k)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Comment < out[j].Comment })
	return out
}

// labelForKey is what a key is called in the list: the agent's own comment,
// which is ssh-add's "user@host" for a key it loaded from a file.
func labelForKey(k *agent.Key) string {
	if strings.TrimSpace(k.Comment) != "" {
		return strings.TrimSpace(k.Comment)
	}
	return "(no comment)"
}

func listKeysCmd(sockPath string) tea.Cmd {
	return func() tea.Msg {
		conn, err := dialAgent(sockPath)
		if err != nil {
			return keysListedMsg{err: err}
		}
		defer conn.Close() //nolint:errcheck
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		held, err := agent.NewClient(conn).List()
		if err != nil {
			return keysListedMsg{err: fmt.Errorf("ask the agent what it holds: %w", err)}
		}
		return keysListedMsg{keys: held}
	}
}

// proveCmd turns a named address into an owned one, when the agent can.
//
// The nonce is made here and never leaves this process; what comes back is a
// signature over it by the key for that address, and ed25519.Verify is the whole
// of the check. An agent that does not hold the key proves nothing and the
// session stays a view, which is not an error: it is somebody reading a
// balance they are allowed to read.
func proveCmd(sockPath, address string) tea.Cmd {
	return func() tea.Msg {
		if sockPath == "" {
			return provenMsg{}
		}
		conn, err := dialAgent(sockPath)
		if err != nil {
			return provenMsg{}
		}
		defer conn.Close() //nolint:errcheck
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

		client := agent.NewClient(conn)
		held, err := client.List()
		if err != nil {
			return provenMsg{}
		}
		for _, k := range orderableKeys(held) {
			pub, sshPub, ok := pubkeyOf(k)
			if !ok {
				continue
			}
			candidate, err := solana.AddressFor(sshPub)
			if err != nil || candidate != address {
				continue
			}
			nonce := make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				return provenMsg{}
			}
			answer, err := client.Sign(sshPub, nonce)
			if err != nil || !ed25519.Verify(pub, nonce, answer.Blob) {
				return provenMsg{}
			}
			return provenMsg{proven: true}
		}
		return provenMsg{}
	}
}

// adoptCmd proves one key out of the agent and reports the account it names.
//
// The same proof as proveCmd, run against a key chosen from a list rather than
// against an address the session already carried.
func adoptCmd(d deps, key *agent.Key) tea.Cmd {
	return func() tea.Msg {
		pub, sshPub, ok := pubkeyOf(key)
		if !ok {
			return nonceSignedMsg{err: errors.New("that key is not one this can name as an account")}
		}
		conn, err := dialAgent(d.SockPath)
		if err != nil {
			return nonceSignedMsg{err: err}
		}
		defer conn.Close() //nolint:errcheck
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nonceSignedMsg{err: fmt.Errorf("make a nonce: %w", err)}
		}
		answer, err := agent.NewClient(conn).Sign(sshPub, nonce)
		if err != nil {
			return nonceSignedMsg{err: fmt.Errorf("the agent did not sign with that key: %w", err)}
		}
		if !ed25519.Verify(pub, nonce, answer.Blob) {
			// A signature that does not check out is not a small thing to
			// shrug at: it is the one thing this screen exists to rule out.
			return nonceSignedMsg{err: errors.New("the agent returned a signature that does not verify for that key")}
		}
		address, err := solana.AddressFor(sshPub)
		if err != nil {
			return nonceSignedMsg{err: err}
		}
		return nonceSignedMsg{address: address}
	}
}

// pubkeyOf reads an agent key's blob into both forms this needs: the raw 32
// bytes ed25519.Verify takes, and the SSH key everything else is named with.
func pubkeyOf(k *agent.Key) (ed25519.PublicKey, gossh.PublicKey, bool) {
	pub, err := parseEd25519Blob(k.Blob)
	if err != nil {
		return nil, nil, false
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, false
	}
	return pub, sshPub, true
}

func dialAgent(sockPath string) (net.Conn, error) {
	if sockPath == "" {
		return nil, errors.New("this session forwarded no agent")
	}
	var dialer net.Dialer
	conn, err := dialer.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("reach the agent: %w", err)
	}
	return conn, nil
}

// parseEd25519Blob reads the raw public key out of an agent key.
//
// The blob is the algorithm name and then the key body, each under its own
// four-byte length, which is what the protocol sends rather than the bare 32
// bytes an address is made of. Both lengths are walked and checked, because
// slicing them off by hand is how a reader ends up holding the wrong thing -
// and the wrong 32 bytes is an address belonging to somebody else.
func parseEd25519Blob(blob []byte) (ed25519.PublicKey, error) {
	rest := blob
	read := func(what string) ([]byte, error) {
		if len(rest) < 4 {
			return nil, fmt.Errorf("the agent's key ends inside the length of its %s", what)
		}
		n := int(uint32(rest[0])<<24 | uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3]))
		if n < 0 || len(rest) < 4+n {
			return nil, fmt.Errorf("the agent's key claims %d bytes of %s and has %d", n, what, len(rest)-4)
		}
		out := rest[4 : 4+n]
		rest = rest[4+n:]
		return out, nil
	}
	if _, err := read("algorithm name"); err != nil {
		return nil, err
	}
	body, err := read("key")
	if err != nil {
		return nil, err
	}
	if len(body) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the agent's ed25519 key is %d bytes, not %d", len(body), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(body), nil
}
