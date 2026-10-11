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
	"github.com/btwiuse/wssh/solana"
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
// With no agent and nothing to adopt there is nowhere to keep a balance, so the
// session is shown what this is and how to get in. That is a landing screen
// rather than a refusal: the person who typed `ssh` here is a person who wants
// to use it.

// anonymousModel is the screen for a session that proved nothing: either the
// list of keys in the forwarded agent, or the landing screen.
type anonymousModel struct {
	deps deps
	st   styles

	keys    []*agent.Key
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
		m.deps.Address = msg.address
		return model{
			deps:    m.deps,
			st:      newStyles(),
			view:    screenHome,
			account: m.deps.Ledger.Account(msg.address),
			width:   m.width,
			height:  m.height,
		}, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.picked > 0 {
				m.picked--
			}
		case "down", "j":
			if m.picked < len(m.keys)-1 {
				m.picked++
			}
		case "enter":
			if len(m.keys) == 0 {
				return m, nil
			}
			m.busy = "asking the agent to sign, so this key is really yours"
			return m, adoptCmd(m.deps, m.keys[m.picked])
		}
	}
	return m, nil
}

func (m anonymousModel) View() tea.View {
	st := m.st
	var b strings.Builder
	b.WriteString("\n  " + st.brand.Render("RouterCafe") + "  " + st.dim.Render(m.deps.host()) + "\n\n")

	if m.busy != "" {
		b.WriteString(wrapText(m.busy, m.width, st.warn) + "\n")
		return tea.NewView(b.String())
	}

	if len(m.keys) == 0 {
		// A landing screen, not a wall.
		//
		// The useful answer to a connection that proved nothing is what this
		// is and how to get in, not a report that there was nothing here to
		// prove - which is a sentence about the protocol rather than about the
		// reader's next step. And there are two next steps, not one: open your
		// own account, or look at any account without a key at all.
		b.WriteString(wrapText("An OpenRouter you reach with ssh.", m.width, st.title) + "\n\n")
		b.WriteString(wrapText("One key, every model, one balance, paid for in SOL. "+
			"An account here is an ed25519 public key.", m.width, st.dim) + "\n\n")

		b.WriteString(wrapText("to open your own account:", m.width, st.title) + "\n")
		b.WriteString(wrapText("ssh-add ~/.ssh/id_ed25519", m.width, st.accent) + "\n")
		b.WriteString(wrapText("ssh -A -i ~/.ssh/id_ed25519 "+m.deps.host(), m.width, st.accent) + "\n\n")

		b.WriteString(wrapText("to look at any account, no key needed:", m.width, st.title) + "\n")
		b.WriteString(wrapText("ssh <address>@"+m.deps.host(), m.width, st.accent) + "\n\n")

		// A real failure is worth a line; "you forwarded no agent" is not,
		// because it is the ordinary case for somebody who only wanted to
		// look, and the two commands above already say what to do about it.
		if m.keysErr != "" && !strings.Contains(m.keysErr, "forwarded no agent") {
			b.WriteString(wrapText(m.keysErr+".", m.width, st.warn) + "\n\n")
		}
		b.WriteString(wrapText("The -A is what carries your key: this connection proved nothing by "+
			"itself, so a forwarded agent is what turns it into an account.", m.width, st.dim) + "\n\n")
	} else {
		b.WriteString(wrapText("Which of these is yours?", m.width, st.title) + "\n\n")
		for i, k := range m.keys {
			marker, style := "  ", st.value
			if i == m.picked {
				marker, style = "> ", st.accent
			}
			b.WriteString(wrapText(marker+labelForKey(k), m.width, style) + "\n")
		}
		b.WriteString("\n" + wrapText("up/down to choose, enter to sign with it", m.width, st.dim) + "\n\n")
	}

	if m.notice.kind != noticeNone {
		b.WriteString(wrapText(m.notice.text, m.width, st.errText) + "\n\n")
	}
	b.WriteString(wrapText("q to disconnect", m.width, st.dim) + "\n")
	return tea.NewView(b.String())
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
