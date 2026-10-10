//go:build js && wasm

package client

import (
	"errors"
	"fmt"
	"syscall/js"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// signatureTimeout bounds how long a signature waits for the user.
//
// Without it a user who walks away from the dialog wedges the agent channel:
// agent.ServeAgent handles one request at a time, so the blocked signature
// holds up every other agent request behind it, and the program on the far end
// waits on that. Giving up is the better failure: the far end sees a refused
// signature, which is an answer it can report, instead of a hang.
const signatureTimeout = 2 * time.Minute

// confirmAll wraps each signer so that nothing is signed without a yes.
//
// It returns nil when forwarding is off, which is what keeps the ordinary
// case ordinary: without it the session never opens an agent channel and the
// page is never asked anything about signing.
//
// The names come from the key material so the question can say which key is
// asking, but the wrapping happens after parsing, where the names have been
// dropped, so the public key's own type and fingerprint stand in.
func confirmAll(signers []gossh.Signer, forward bool, ask AskSignature) []gossh.Signer {
	if !forward || ask == nil || len(signers) == 0 {
		return nil
	}
	wrapped := make([]gossh.Signer, 0, len(signers))
	for _, signer := range signers {
		wrapped = append(wrapped, NewConfirmingSigner(signer, keyLabel(signer), ask))
	}
	return wrapped
}

// keyLabel names a key the way a person would recognise it.
func keyLabel(signer gossh.Signer) string {
	pub := signer.PublicKey()
	if fp := gossh.FingerprintSHA256(pub); fp != "" {
		return fmt.Sprintf("%s %s", pub.Type(), fp)
	}
	return pub.Type()
}

// awaitStringTimeout is awaitString with a deadline. It returns an error rather
// than blocking forever when the page does not answer.
//
// This cannot use a plain timer: in WebAssembly a goroutine parked on a
// channel with a timer pending is the only thing keeping the runtime from
// declaring deadlock, and both are here, so a timeout is safe. What is not safe
// is adding a second parking goroutine per call, so the timer is the select's
// other arm rather than something of its own.
func awaitStringTimeout(fn js.Value, args []string, limit time.Duration) (string, error) {
	if fn.Type() != js.TypeFunction {
		return "", errNoFunction
	}

	type settled struct {
		value string
		fail  string
	}
	settledCh := make(chan settled, 1)

	resolve := js.FuncOf(func(_ js.Value, a []js.Value) any {
		settledCh <- settled{value: a[0].String()}
		return nil
	})
	defer resolve.Release()

	reject := js.FuncOf(func(_ js.Value, a []js.Value) any {
		reason := ""
		if len(a) > 0 {
			reason = a[0].String()
		}
		settledCh <- settled{fail: reason}
		return nil
	})
	defer reject.Release()

	incoming := make([]any, 0, len(args))
	for _, arg := range args {
		incoming = append(incoming, arg)
	}
	fn.Invoke(incoming...).Call("then", resolve, reject)

	timer := time.NewTimer(limit)
	defer timer.Stop()

	select {
	case out := <-settledCh:
		if out.fail != "" {
			return "", errors.New(out.fail)
		}
		return out.value, nil
	case <-timer.C:
		return "", fmt.Errorf("no answer within %s", limit)
	}
}
