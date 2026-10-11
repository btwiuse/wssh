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

// What a session with no key does.
//
// A server that accepts "none" accepts it from everybody, because a client
// sends it first as a probe and the handshake ends there. So opening the door
// for somebody who has no key also means every client arrives with no key, and
// the question "who is this" can no longer be answered by SSH. It has to be
// answered by something the client does after connecting.
//
// What it does here: if the client forwarded an agent, the keys in that agent
// are offered and whichever one is chosen is proved by having the agent sign a
// nonce this server made up. Not "the client says it has this key" - the agent
// signs, and a signature that verifies is possession.
//
// With no agent and nothing to adopt, there is nothing to prove and nowhere to
// keep a balance, so the session says how to get a key and stops. That is the
// one case where the message a person reads is a command they have not run
// yet, and it is shown to exactly those people: anyone with a forwarded agent
// never sees it.

// AdoptCommand is what the notice tells somebody to run.
//
// Both halves matter. The -A is what lets the server ask their agent to sign,
// and the key path is what makes sure the agent has that key at all - a key
// on disk that the agent does not hold is invisible from in here, and without
// -A the connection comes back to this same screen.
const AdoptCommand = "ssh-add ~/.ssh/id_ed25519 && ssh -A -i ~/.ssh/id_ed25519 " + Domain

// anonymousModel is the screen for a session that proved nothing: either the
// list of keys in the forwarded agent, or the notice.
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
	// Listed once at open rather than on a keystroke: the agent is on the
	// far end of a channel and answering is not instant, and a person who
	// just connected is waiting to find out whether there is anything here.
	if m.keysErr == "" && len(m.keys) == 0 {
		return listKeysCmd(m.deps.SockPath)
	}
	return nil
}

type keysListedMsg struct {
	keys []*agent.Key
	err  error
}

// nonceSignedMsg is the outcome of asking the agent to prove a key.
type nonceSignedMsg struct {
	address string
	keys    []*agent.Key
	err     error
}

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

	case nonceSignedMsg:
		m.busy = ""
		if msg.err != nil {
			m.notice = notice{noticeBad, msg.err.Error()}
			return m, nil
		}
		// Proved. From here this session is an ordinary one, so the UI it
		// was refused a moment ago is what it gets.
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

// orderableKeys keeps only the keys that name an account, and sorts them.
//
// A key that is not ed25519 is dropped rather than shown-and-then-refused:
// the whole of this screen is a list of things that will work, and a row that
// says no would be the one somebody tries.
func orderableKeys(keys []*agent.Key) []*agent.Key {
	var out []*agent.Key
	for _, k := range keys {
		if k == nil {
			continue
		}
		// Only keys that name an account are offered. A key that is not
		// ed25519 would be refused a moment later, and a list where one row
		// says no is a list somebody tries every row of.
		if len(k.Blob) == 0 || k.Format != gossh.KeyAlgoED25519 {
			continue
		}
		out = append(out, k)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Comment < out[j].Comment
	})
	return out
}

func listKeysCmd(sockPath string) tea.Cmd {
	return func() tea.Msg {
		if sockPath == "" {
			return keysListedMsg{err: errors.New("this session forwarded no agent, so there is nothing here to prove")}
		}
		conn, err := dialAgent(sockPath)
		if err != nil {
			return keysListedMsg{err: err}
		}
		defer conn.Close() //nolint:errcheck
		held, err := agent.NewClient(conn).List()
		if err != nil {
			return keysListedMsg{err: fmt.Errorf("ask the agent what it holds: %w", err)}
		}
		return keysListedMsg{keys: held}
	}
}

// adoptCmd proves one key out of the agent and reports the account it names.
//
// The nonce is made here and never leaves this process; what comes back is a
// signature over it by the key being adopted, and ed25519.Verify is the whole
// of the check. An agent that cannot sign that key fails, which is the point:
// possession is established by the signature, not asserted by the request.
func adoptCmd(d deps, key *agent.Key) tea.Cmd {
	return func() tea.Msg {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nonceSignedMsg{err: fmt.Errorf("make a nonce: %w", err)}
		}
		pub, err := parseEd25519Blob(key.Blob)
		if err != nil {
			return nonceSignedMsg{err: err}
		}
		sshPub, err := gossh.NewPublicKey(pub)
		if err != nil {
			return nonceSignedMsg{err: fmt.Errorf("that key is not one this can name: %w", err)}
		}

		conn, err := dialAgent(d.SockPath)
		if err != nil {
			return nonceSignedMsg{err: err}
		}
		defer conn.Close() //nolint:errcheck

		// Bounded: the agent is across a channel to the client, and one that
		// never answers should not hold this screen for ever.
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
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
		return nonceSignedMsg{address: address, keys: []*agent.Key{key}}
	}
}

func dialAgent(sockPath string) (net.Conn, error) {
	if sockPath == "" {
		return nil, errors.New("this session forwarded no agent")
	}
	var dialer net.Dialer
	conn, err := dialer.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("reach the agent at %s: %w", shortBase(sockPath), err)
	}
	return conn, nil
}

// parseEd25519Blob reads the raw public key out of an agent key.
//
// The blob is the algorithm name and then the key body, each under its own
// four-byte length, which is what the protocol sends rather than the bare 32
// bytes an address is made of. Both lengths are walked and checked, because
// slicing them off by hand is how a reader ends up holding the wrong thing.
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

func shortBase(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

func (m anonymousModel) View() tea.View {
	st := m.st
	var b strings.Builder
	b.WriteString("\n  " + st.brand.Render("RouterCafe") + "  " + st.dim.Render(Domain) + "\n\n")

	if m.busy != "" {
		b.WriteString(wrapText(m.busy, m.width, st.warn))
		b.WriteString("\n")
		return tea.NewView(b.String())
	}

	if len(m.keys) == 0 {
		b.WriteString(wrapText("Nothing to prove yet.", m.width, st.errText))
		b.WriteString("\n\n")
		if m.keysErr != "" {
			b.WriteString(wrapText(m.keysErr+".", m.width, st.dim))
			b.WriteString("\n\n")
		}
		b.WriteString(wrapText(
			"This server did not get a key from your connection, and an account here is "+
				"an ed25519 public key. Forward an agent holding one and this screen becomes "+
				"your account, proved by having the agent sign.", m.width, st.dim))
		b.WriteString("\n\n")
		b.WriteString(wrapText("make a key, put it in your agent, and connect with -A:", m.width, st.title))
		b.WriteString("\n\n")
		b.WriteString(wrapText("ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''", m.width, st.accent))
		b.WriteString("\n")
		b.WriteString(wrapText(AdoptCommand, m.width, st.accent))
		b.WriteString("\n\n")
		b.WriteString(wrapText("Without the -A the agent is not on this side, and the key on disk is invisible from here.",
			m.width, st.dim))
		b.WriteString("\n\n")
	} else {
		b.WriteString(wrapText("Which of these is yours?", m.width, st.title))
		b.WriteString("\n\n")
		for i, k := range m.keys {
			marker := "  "
			style := st.value
			if i == m.picked {
				marker = "> "
				style = st.accent
			}
			b.WriteString(wrapText(marker+labelForKey(k), m.width, style))
			b.WriteString("\n")
		}
		b.WriteString("\n")
		b.WriteString(wrapText("up/down to choose, enter to sign with it", m.width, st.dim))
		b.WriteString("\n\n")
	}

	if m.notice.kind != noticeNone {
		b.WriteString(wrapText(m.notice.text, m.width, st.errText))
		b.WriteString("\n\n")
	}
	b.WriteString(wrapText("q to disconnect", m.width, st.dim))
	b.WriteString("\n")
	return tea.NewView(b.String())
}

// labelForKey is what a key is called in the list: the agent's own comment,
// which is ssh-add's "user@host" for a key it loaded from a file.
func labelForKey(k *agent.Key) string {
	if strings.TrimSpace(k.Comment) != "" {
		return strings.TrimSpace(k.Comment)
	}
	return "(no comment)"
}

// Upgrading a named account into a proved one.
//
// A connection that arrived with no key names an account by its username, and
// that is enough to look at it. When it also forwarded an agent, the agent is
// asked whether it holds the key for that address and, if it does, asked to
// sign: the same proof, run against a name that is already known rather than
// chosen from a list.
func proveCmd(sockPath, address string) tea.Cmd {
	return func() tea.Msg {
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
			pub, err := parseEd25519Blob(k.Blob)
			if err != nil {
				continue
			}
			sshPub, err := gossh.NewPublicKey(pub)
			if err != nil {
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

// provenMsg reports whether a forwarded agent turned out to hold the key for
// the address this session named. A false one is not a failure: most agents
// will not, and the session is still perfectly usable as a read-only view.
type provenMsg struct{ proven bool }
