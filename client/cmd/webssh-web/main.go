//go:build js && wasm

// Command webssh-web is the browser build of package client, loaded as a
// WebAssembly module by cmd/wssh/static/worker.js.
//
// It exists only to give the package a main. Everything that makes it work
// lives in package client, so the same session code serves the browser and
// the wssh client subcommand.
package main

import "github.com/btwiuse/wssh/client"

func main() {
	client.Start()
}
