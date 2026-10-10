//go:build tools

// A local stand-in for the wallet side of the agent, for working on
// scripts/sol-tx without a browser in the way.
//
// It runs a real ssh-agent on a real unix socket with the Solana extension
// attached, and signs with a key it generates on the spot. That is enough to
// exercise everything up to the browser: the extension framing, the request
// parse, the refusal paths, the signature check on the way back. What it cannot
// exercise is the page's own transaction builder, which is the half that has to
// load web3.js and needs a real browser.
//
// Usage:
//
//	go run -tags tools ./harness        # prints the socket path, then waits
//	deno run -A scripts/sol-tx/main.ts memo --memo hi --agent <path>
//
// The build tag keeps it out of every normal build; nothing imports it.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/btwiuse/wssh/auth/agentkey"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		panic(err)
	}
	ring, err := agentkey.Keyring([]gossh.Signer{signer})
	if err != nil {
		panic(err)
	}

	pubkey := pub

	err = agentkey.WithSolana(ring, func(req agentkey.SolanaTxRequest) (agentkey.SolanaTxResponse, ed25519.PublicKey, error) {
		// Stand in for the browser: describe what arrived so the run is
		// auditable, then sign a synthetic transaction over it.
		fmt.Fprintf(os.Stderr, "[harness] wallet asked, %d instruction(s)\n", len(req.Instructions))
		for i, in := range req.Instructions {
			fmt.Fprintf(os.Stderr, "[harness]   [%d] program=%s accounts=%d data=%s\n",
				i, in.ProgramID, len(in.Accounts), in.DataBase58)
		}

		message := []byte(strings.Join([]string{req.Blockhash, req.Label}, "|"))
		for _, in := range req.Instructions {
			message = append(message, in.ProgramID...)
			message = append(message, in.DataBase58...)
		}
		sig := ed25519.Sign(priv, message)
		return agentkey.SolanaTxResponse{
			Signature:         sig,
			SignedTransaction: append(append([]byte{1}, sig...), message...),
		}, pubkey, nil
	}, nil, nil)
	if err != nil {
		panic(err)
	}

	dir, err := os.MkdirTemp("", "wssh-harness-")
	if err != nil {
		panic(err)
	}
	path := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		panic(err)
	}
	fmt.Println(path)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck
				_ = agent.ServeAgent(ring.(agent.Agent), conn)
			}()
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}
