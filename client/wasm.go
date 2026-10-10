//go:build js && wasm

// This file is the browser half of the package: a bridge from JavaScript to a
// session in this package. It exports its functions through the global
// websshGoExportResolve hook rather than owning a main, so the browser binary
// and anything else that wants the same bridge can share it.
//
// One rule governs this file. A js.Func is invoked on whichever goroutine last
// handed control back to JavaScript, and calling into Go resumes the Go
// scheduler. That goroutine must therefore return promptly. Opening a session
// dials a socket and performs a key exchange, far too slow to do inline: the
// browser's WebSocket events arrive on the very thread we would be blocking.
// Every operation here starts a goroutine and returns.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"syscall/js"
	"time"

	"github.com/btwiuse/wssh/auth/agentkey"
	gossh "golang.org/x/crypto/ssh"
)

// ExportResolver is the global the host page installs, called once the
// exported functions are ready.
const ExportResolver = "websshGoExportResolve"

// The globals worker.js installs for Go to call back into. They live in the
// worker's scope, not the page's, which is why a prompt has to make the round
// trip as a message rather than being a closure handed over: the page and the
// worker cannot see each other's globals.
const (
	askPassphraseHook = "__websshAskPassphraseFn"
	askSignatureHook  = "__websshAskSignature"
)

// Start registers the JavaScript bridge and then parks forever. The browser
// binary calls this from its main; nothing else needs to.
func Start() {

	js.Global().Get(ExportResolver).Invoke(map[string]any{
		"connect":     js.FuncOf(jsConnect),
		"write":       js.FuncOf(jsWrite),
		"resize":      js.FuncOf(jsResize),
		"disconnect":  js.FuncOf(jsDisconnect),
		"generateKey": js.FuncOf(jsGenerateKey),
		"keyInfo":     js.FuncOf(jsKeyInfo),
	})

	// keepAlive is not decoration. WebAssembly is single-threaded, and once
	// every goroutine is parked with nothing pending the runtime calls
	// wasmExit and the program dies in silence. The next call from JavaScript
	// then fails with "Go program has already exited", which points nowhere
	// near the cause. A pending timer is one of the few states that stops
	// runtime.checkdead from declaring that deadlock; a blocked channel is
	// not, so this has to be a sleep.
	go keepAlive()
	<-make(chan struct{})
}

func keepAlive() {
	for {
		time.Sleep(time.Hour)
	}
}

var current struct {
	s *Session
}

func jsConnect(_ js.Value, args []js.Value) any {
	url := args[0].String()
	user := args[1].String()
	cols, rows := 80, 24
	if len(args) > 2 {
		cols, rows = args[2].Int(), args[3].Int()
	}
	// Optional command: when set, the remote side runs it and exits, the way
	// `ssh host -- command` does. Empty keeps the existing interactive shell.
	command := ""
	if len(args) > 6 && args[6].Type() == js.TypeString {
		command = args[6].String()
	}

	// Credentials come across as JSON rather than as loose arguments: the page
	// may have any number of keys, each with its own passphrase, and this is
	// the one place that shape has to be understood.
	var creds credentials
	if len(args) > 4 && args[4].Type() == js.TypeString {
		if err := json.Unmarshal([]byte(args[4].String()), &creds); err != nil {
			post(map[string]any{"type": "error", "message": "bad credentials: " + err.Error()})
			return nil
		}
	}
	// The password is asked for by the page, at the moment the handshake
	// actually wants one, so this is a function rather than a string.
	var askPassword func() (string, error)
	if len(args) > 5 && args[5].Type() == js.TypeFunction {
		fn := args[5]
		askPassword = func() (string, error) {
			value, err := awaitString(fn)
			if err != nil || value == "" {
				return "", errNoPassword
			}
			return value, nil
		}
	}

	// An encrypted key is opened by asking the page for its passphrase. The
	// private key itself never has to be understood by JavaScript: the page
	// hands over the text, Go does the cryptography.
	// The name has to be the one worker.js installs on its own global, with the
	// double underscore. Reading anything else finds nothing, and a missing
	// hook does not fail loudly: an encrypted key simply reports that no
	// passphrase was given instead of asking for one.
	var askKeyPassphrase func(name string) (string, error)
	if hook := js.Global().Get(askPassphraseHook); hook.Type() == js.TypeFunction {
		askKeyPassphrase = func(name string) (string, error) {
			value, err := awaitString(hook, name)
			if err != nil || value == "" {
				return "", nil //nolint:nilnil
			}
			return value, nil
		}
	}

	// What a signature needs the page to approve. Only consulted when the
	// user asked for the agent to be forwarded, so a session that never
	// forwards never shows a dialog.
	var confirmSignature AskSignature
	if creds.ForwardAgent {
		hook := js.Global().Get(askSignatureHook)
		confirmSignature = func(summary string) (bool, error) {
			answer, err := awaitStringTimeout(hook, []string{summary}, signatureTimeout)
			if err != nil {
				return false, err
			}
			return answer == "yes", nil
		}
	}

	go func() {
		auth, signers, err := buildAuth(creds, askPassword, askKeyPassphrase)
		if err != nil {
			post(map[string]any{"type": "error", "message": err.Error()})
			return
		}

		// Signing in with a wallet is not the same as using its key for SSH.
		// The wallet is on this page, so this is the only place that can ask
		// it; the exchange itself is in Go and only needs somewhere to put
		// the answer.
		var walletSIWSSigner SIWSSigner
		if creds.SignIn {
			walletSIWSSigner = walletSignerFn()
		}

		// A connected wallet joins the same keyring. It is a signer like any
		// other here; what makes it different is where the private half
		// lives, which is entirely on the other side of the bridge.
		// The extension is attached whenever the agent is served, wallet or
		// not, so that "no wallet here" comes back as an answer rather than
		// as the same refusal a real ssh-agent would give.
		var walletRing agentkey.Agent
		if creds.WalletPublicKey != "" {
			wallet, err := walletSigner(creds.WalletPublicKey, creds.WalletAddress)
			if err != nil {
				post(map[string]any{"type": "error",
					"message": "the connected wallet could not be used: " + err.Error()})
				return
			}
			auth = append(auth, gossh.PublicKeys(wallet))
			signers = append(signers, wallet)
		}

		if len(signers) > 0 {
			// The keyring answers Solana transactions, so anything in the
			// session can ask the wallet to sign one. There is no switch for
			// this: forwarding a wallet is already the decision, and a
			// remembered approval would hand it open to whatever got as far
			// as a shell.
			//
			// Without a wallet the extension is attached with nothing behind
			// it, so the refusal names that rather than looking like an agent
			// that has never heard of transactions.
			ring, err := agentkey.Keyring(signers)
			if err != nil {
				post(map[string]any{"type": "error",
					"message": "could not prepare the signing keyring: " + err.Error()})
				return
			}
			asker := solanaAsker()
			if creds.WalletPublicKey == "" {
				asker = nil
			}
			if err := agentkey.WithSolana(ring, asker, solanaBuilder()); err != nil {
				post(map[string]any{"type": "error",
					"message": "could not offer Solana transactions: " + err.Error()})
				return
			}
			walletRing = ring
		}

		sess, err := Dial(context.Background(), Options{
			Auth:       auth,
			SIWSSigner: walletSIWSSigner,
			URL:        url,
			User:       user,
			Cols:       cols,
			Rows:       rows,
			Command:    command,
			// Wrapping in ConfirmingSigner is what makes forwarding
			// acceptable from a browser: the keys stay here, and nothing is
			// signed without a yes first. Every signature asks again; a yes
			// is never remembered.
			AgentSigners: confirmAll(signers, creds.ForwardAgent, confirmSignature),
			AgentKeyring: walletRing,
			OnData:       postData,
			OnClose: func(err error) {
				// Forget the session first. The page keeps delivering keystrokes
				// after the far side has gone, and reporting each one as an
				// error would fill the screen with noise about something the
				// user already did on purpose.
				current.s = nil
				// A shell that exits because someone typed "exit" is not a
				// failure; the SSH session simply ends without an exit status.
				var missing *gossh.ExitMissingError
				if err != nil && !errors.As(err, &missing) {
					post(map[string]any{"type": "error", "message": err.Error()})
				}
				post(map[string]any{"type": "closed"})
			},
		})
		if err != nil {
			post(map[string]any{"type": "error", "message": err.Error()})
			return
		}

		current.s = sess
		post(map[string]any{"type": "connected"})
	}()

	return nil
}

func jsWrite(_ js.Value, args []js.Value) any {
	if current.s == nil {
		return nil
	}
	if err := current.s.Write(uint8ArrayToBytes(args[0])); err != nil {
		post(map[string]any{"type": "error", "message": err.Error()})
	}
	return nil
}

// jsResize forwards a terminal resize as an SSH window-change request. Without
// it a resized terminal leaves full-screen programs drawing to stale
// dimensions.
func jsResize(_ js.Value, args []js.Value) any {
	if current.s == nil {
		return nil
	}
	if err := current.s.Resize(args[0].Int(), args[1].Int()); err != nil {
		post(map[string]any{"type": "error", "message": err.Error()})
	}
	return nil
}

func jsDisconnect(_ js.Value, _ []js.Value) any {
	if sess := current.s; sess != nil {
		current.s = nil
		go func() { _ = sess.Close() }()
	}
	return nil
}

// uint8ArrayToBytes copies a JS Uint8Array into a Go slice.
func uint8ArrayToBytes(v js.Value) []byte {
	buf := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(buf, v)
	return buf
}

// post sends an event to the host page. syscall/js turns a Go map straight into
// a JS object, so there is no serialisation step to keep in sync.
func post(event map[string]any) {
	js.Global().Call("postMessage", event)
}

// postBytes sends an event with a binary payload, copied because the buffer it
// came from is Go-owned and reused on the next read.
func postBytes(event map[string]any, payload []byte) {
	view := js.Global().Get("Uint8Array").New(len(payload))
	js.CopyBytesToJS(view, payload)
	event["payload"] = view
	post(event)
}

func postData(payload []byte) { postBytes(map[string]any{"type": "data"}, payload) }

// connectAskPassphrase points the passphrase hook at the page's function, once
// the module has loaded.

// awaitString calls a JavaScript function and waits for the promise it returns.
//
// A prompt cannot block in JavaScript, so the page answers with a promise.
// Invoking it directly would hand back the promise object rather than its
// value, and a caller waiting on the answer would get the string
// "[object Promise]". Blocking here is safe: the handshake runs on its own
// goroutine, so the runtime stays free to service the promise while we wait.
func awaitString(fn js.Value, args ...any) (string, error) {
	if fn.Type() != js.TypeFunction {
		return "", errNoFunction
	}

	incoming := make([]any, 0, len(args))
	for _, arg := range args {
		incoming = append(incoming, arg)
	}

	type settledValue struct {
		value string
		fail  string
	}
	settled := make(chan settledValue, 1)

	resolve := js.FuncOf(func(_ js.Value, a []js.Value) any {
		settled <- settledValue{value: a[0].String()}
		return nil
	})
	defer resolve.Release()

	reject := js.FuncOf(func(_ js.Value, a []js.Value) any {
		reason := ""
		if len(a) > 0 {
			reason = a[0].String()
		}
		settled <- settledValue{fail: reason}
		return nil
	})
	defer reject.Release()

	fn.Invoke(incoming...).Call("then", resolve, reject)

	out := <-settled
	if out.fail != "" {
		return "", errors.New(out.fail)
	}
	return out.value, nil
}
