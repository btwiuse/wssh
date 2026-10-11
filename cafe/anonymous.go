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

// What a session that proved nothing does, and where it happens.
//
// A server that accepts "none" accepts it from everybody, because a client
// sends it first as a probe and the handshake ends there. So opening the door
// for somebody who has no key also means every client arrives with no key, and
// the question "who is this" can no longer be answered by SSH. It has to be
// answered by something the client does after connecting.
//
// It used to be answered by a separate program - a screen of its own, drawn
// by its own rules, with no tab bar and its own frame - which handed the
// ordinary session over the moment it worked out who it was. That is now the
// first page of the ordinary session: see renderPick and onPickKey. Same
// window, same bar, same frame, and the question asked on the first page
// rather than in a program that then asked you to leave it.
//
// What the page does: if the session forwarded an agent, the keys in that
// agent are offered, and whichever one is chosen is proved by having the agent
// sign a nonce this server made up. Not "the client says it has this key" - the
// agent signs, and a signature that verifies is possession.
//
// With no agent there is still somewhere to go, because naming an account is
// not proof and does not need to be: it is a view, and a view is what somebody
// who only wanted to look came for. So the same page that offers the agent's
// keys also takes an address, and the two differ in exactly one way - a key
// gets signed for, an address does not - which is the difference between
// read-only and not.

// The messages the picker sends, all handled by the session model: there is
// one program now, so there is one place its messages arrive.

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

// pickKeyMsg is a click on a row of the picker's list.
type pickKeyMsg struct{ row int }

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
