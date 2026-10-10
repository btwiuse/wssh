package solana

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/btwiuse/wssh/auth/agentkey"
	"github.com/btwiuse/wssh/auth/siws"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SignWithAgent builds the transaction here and has the agent sign the
// message, rather than asking the agent to build one.
//
// The two are not the same request. An agent that knows the extension does
// the whole job: the wallet builds the transaction, shows it to a person, and
// returns it signed. A plain ssh-agent has never heard of the extension and
// never will - it signs whatever bytes it is handed, and knows nothing about
// what a transaction is.
//
// For that agent the work splits. Building is ours, because that is the part
// that needs to know the format and the agent has no reason to. Signing is
// theirs, because that is the only thing an agent is for, and asking is what
// an ssh-agent is good at. So the bytes are built here and handed over as an
// ordinary signature request, which is one every agent has understood since
// the protocol was written.
func SignWithAgent(ctx context.Context, sockPath string, req agentkey.SolanaTxRequest) (agentkey.SolanaTxResponse, error) {
	var resp agentkey.SolanaTxResponse

	if sockPath == "" {
		return resp, errors.New("no agent socket to sign through")
	}

	sock, err := net.Dial("unix", sockPath)
	if err != nil {
		return resp, fmt.Errorf("reach the agent: %w", err)
	}
	defer sock.Close() //nolint:errcheck

	deadline := time.Now().Add(solanaTxTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := sock.SetDeadline(deadline); err != nil {
		return resp, fmt.Errorf("bound the request: %w", err)
	}
	conn := agent.NewClient(sock)

	// A wallet decides which of its accounts to use and answers a request
	// that is already built. An agent cannot: it signs with whatever key it
	// is asked to, so the session has to say which. When there is one key on
	// offer there is nothing to decide, and taking it is the difference
	// between this working in a session and this working only when the
	// account happens to be named.
	if req.Payer == "" {
		payer, err := soleKeyOn(conn)
		if err != nil {
			return resp, err
		}
		req.Payer = payer
	}

	payer, err := decode32(req.Payer, "payer")
	if err != nil {
		return resp, err
	}
	unsigned, err := BuildTransaction(req)
	if err != nil {
		return resp, err
	}
	// Everything past the signature count and the slot is what gets signed;
	// the slot is only there because that is the shape the result goes back
	// into.
	message := unsigned[1+ed25519.SignatureSize:]

	key, err := gossh.NewPublicKey(ed25519.PublicKey(payer))
	if err != nil {
		return resp, fmt.Errorf("the payer is not a key the agent protocol can name: %w", err)
	}

	answer, err := conn.Sign(key, message)
	if err != nil {
		return resp, fmt.Errorf("the agent did not sign with %s: %w", req.Payer, err)
	}
	sig := answer.Blob
	if len(sig) != ed25519.SignatureSize {
		return resp, fmt.Errorf("the agent returned a %d byte signature, want %d",
			len(sig), ed25519.SignatureSize)
	}

	// The signature takes the slot the build left empty. It does not follow
	// it: a versioned transaction has one signature region, and anything else
	// reads back as a transaction with two.
	signed := make([]byte, 0, len(unsigned))
	signed = append(signed, unsigned[0]) // the compact-u16 signature count
	signed = append(signed, sig...)
	signed = append(signed, message...)

	return agentkey.SolanaTxResponse{
		Signature:         sig,
		SignedTransaction: signed,
	}, nil
}

// soleKeyOn is the only key the agent holds, as a base58 account address.
//
// More than one is not an error so much as an unanswerable question: an agent
// with three keys signs with whichever one is named, and naming the wrong one
// gives a transaction the cluster rejects with nothing pointing here. So the
// caller is asked instead. None is the same question with an empty agent.
func soleKeyOn(conn agent.ExtendedAgent) (string, error) {
	keys, err := conn.List()
	if err != nil {
		return "", fmt.Errorf("ask the agent what keys it holds: %w", err)
	}
	switch len(keys) {
	case 0:
		return "", errors.New("the agent holds no keys, so there is nothing to sign with")
	case 1:
	default:
		return "", fmt.Errorf(
			"the agent holds %d keys and signs with whichever one is named, "+
				"so pass --payer with the account to use", len(keys))
	}

	// An agent hands keys back in the wire form the protocol uses, which is
	// the algorithm name and then the key body, each under its own four-byte
	// length. For ed25519 the body is the 32 raw bytes an account address is
	// made of, but they are behind both lengths and not only the first.
	if keys[0].Format != gossh.KeyAlgoED25519 {
		return "", fmt.Errorf(
			"the only key the agent holds is a %s, and an account address can "+
				"only be named for an ed25519 key", keys[0].Format)
	}
	blob := keys[0].Blob
	const algo = gossh.KeyAlgoED25519
	const lenPrefix = 4
	if len(blob) < 2*lenPrefix+len(algo)+ed25519.PublicKeySize ||
		string(blob[lenPrefix:lenPrefix+len(algo)]) != algo {
		return "", errors.New("the only key the agent holds is not in the shape the protocol describes")
	}
	start := 2*lenPrefix + len(algo)
	return siws.Base58Encode(blob[start : start+ed25519.PublicKeySize]), nil
}
