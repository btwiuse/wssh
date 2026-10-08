//go:build js && wasm

// Command client is the browser front end for webssh: a thin bridge between
// JavaScript and the SSH-over-WebSocket session in package sshclient.
//
// The session logic lives in sshclient precisely so it can be tested natively.
// Everything here is plumbing: a js.Func per operation, and a postMessage for
// everything coming back.
//
// One rule governs this file. A js.Func is invoked on whichever Go goroutine
// last handed control back to JavaScript, and calling into Go resumes the Go
// scheduler. That goroutine must therefore return promptly. Opening a session
// dials a socket and performs a key exchange, which is far too slow to do
// inline: the browser's WebSocket events are delivered on the very thread we
// would be blocking. Every operation here starts a goroutine and returns.
package main

import (
	"context"
	"syscall/js"
	"time"

	"github.com/btwiuse/wssh/sshclient"
)

func main() {
	js.Global().Get("websshGoExportResolve").Invoke(map[string]any{
		"connect":    js.FuncOf(jsConnect),
		"write":      js.FuncOf(jsWrite),
		"resize":     js.FuncOf(jsResize),
		"disconnect": js.FuncOf(jsDisconnect),
	})

	// Park forever, because the exported functions are driven by the page.
	//
	// keepAlive is not decoration. WebAssembly is single-threaded, and once
	// every goroutine is parked with nothing pending the runtime calls
	// wasmExit and the program dies in silence. The next call from JavaScript
	// then fails with "Go program has already exited", which points nowhere
	// near the cause. A pending timer is one of the few states that stops
	// runtime.checkdead from declaring that deadlock; a blocked channel is
	// not, so this has to be a sleep.
	go keepAlive()
	select {}
}

func keepAlive() {
	for {
		time.Sleep(time.Hour)
	}
}

var current struct {
	s *sshclient.Session
}

func jsConnect(_ js.Value, args []js.Value) any {
	url := args[0].String()
	user := args[1].String()
	cols, rows := 80, 24
	if len(args) > 2 {
		cols, rows = args[2].Int(), args[3].Int()
	}

	go func() {
		sess, err := sshclient.Dial(context.Background(), sshclient.Options{
			URL:    url,
			User:   user,
			Cols:   cols,
			Rows:   rows,
			OnData: postData,
			OnClose: func(err error) {
				if err != nil {
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
