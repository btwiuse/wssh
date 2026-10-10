package wssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/btwiuse/wssh/auth/siws"
	"github.com/coder/websocket"
)

// The wallet sign-in exchange.
//
// It runs on the WebSocket itself, as ordinary messages, before a single byte
// of SSH is sent. That placement is the point:
//
//   - The connection is already open, so asking and answering on it needs no
//     second endpoint and no second protocol beside the SSH one.
//   - A refusal can say why. A credential refused part way through a handshake
//     is a closed connection and nothing else.
//   - Nothing sensitive goes in the URL, so it does not end up in proxy logs,
//     browser history or a process list.
//
// It is in band for exactly the reason public key authentication is: the server
// has state and the client answers it, both on a connection that already
// exists.

// siwsMessage is the shape of one frame in the exchange. Every frame carries a
// kind, so an unreadable one can be refused rather than guessed at.
type siwsMessage struct {
	Kind string `json:"kind"`

	// Challenge is on the server's first frame.
	Challenge *siws.SIWSInput `json:"challenge,omitempty"`

	// Message and Signature are the client's answer.
	Message   []byte `json:"message,omitempty"`
	Signature []byte `json:"signature,omitempty"`

	// Address is on a successful frame, so the page can show who it signed in
	// as without reading the signed text back.
	Address string `json:"address,omitempty"`

	// Reason is on a refusal. It is written for the person who has to act on
	// it, not for a log.
	Reason string `json:"reason,omitempty"`
}

// SIWSSubprotocol is how a client says it is willing to sign in, before
// either side has said anything. It is echoed back only by a server that will
// actually ask, so a client against an ordinary server never waits to be told
// there is nothing to answer.
const SIWSSubprotocol = "wssh.wssh-siws.v1"

const (
	siwsKindChallenge = "challenge"
	siwsKindSignIn    = "signin"
	siwsKindReady     = "ready"
	siwsKindError     = "error"
)

// siwsExchangeTimeout bounds the whole exchange. It is generous enough for a
// person to read a message and answer a wallet prompt, and short enough that a
// client which has gone away does not hold a connection open.
const siwsExchangeTimeout = 3 * time.Minute

// exchangeSignIn asks the client to prove an account and reports whether it
// did.
//
// host is the one this client actually reached, which is what the signed
// message has to name. It is not fixed at startup because one server can be
// reachable under more than one name.
func (s *Server) exchangeSignIn(ctx context.Context, conn *websocket.Conn, host string) bool {
	cfg := s.opts.WalletAuth

	challenge, err := cfg.Challenge(host)
	if err != nil {
		s.refuse(ctx, conn, fmt.Sprintf("the server could not make a sign-in request: %v", err))
		return false
	}
	if err := writeSIWS(ctx, conn, siwsMessage{
		Kind:      siwsKindChallenge,
		Challenge: &challenge,
	}); err != nil {
		s.opts.Logger.Debug("could not send the sign-in challenge", "error", err)
		return false
	}

	var answer siwsMessage
	if err := readSIWS(ctx, conn, &answer); err != nil {
		s.refuse(ctx, conn, "the sign-in could not be read: "+err.Error())
		return false
	}
	if answer.Kind != siwsKindSignIn {
		s.refuse(ctx, conn, fmt.Sprintf("expected a sign-in, got %q", answer.Kind))
		return false
	}
	if len(answer.Signature) != 64 {
		s.refuse(ctx, conn, "the wallet returned no signature to check")
		return false
	}

	// The account comes back even when the check failed, which is the whole
	// point of returning it: a refusal that cannot name the account is a
	// refusal nobody can act on.
	address, err := cfg.Verify(answer.Message, answer.Signature, host)
	if err != nil {
		reason := err.Error()
		if errors.Is(err, siws.ErrNotAuthorized) {
			reason += "; add it to --authorized-addresses"
		}
		s.opts.Logger.Warn("wallet sign-in refused", "reason", err, "account", address, "host", host)
		s.refuse(ctx, conn, reason)
		return false
	}

	if err := writeSIWS(ctx, conn, siwsMessage{Kind: siwsKindReady, Address: address}); err != nil {
		s.opts.Logger.Debug("could not confirm the sign-in", "error", err)
		return false
	}
	s.opts.Logger.Debug("wallet sign-in accepted", "address", address, "host", host)
	return true
}

// refuse sends the reason back over the socket, where the client is still
// listening for it. Failing to send it is not worth anything louder than a
// debug line: the connection is about to close either way.
func (s *Server) refuse(ctx context.Context, conn *websocket.Conn, reason string) {
	if err := writeSIWS(ctx, conn, siwsMessage{Kind: siwsKindError, Reason: reason}); err != nil {
		s.opts.Logger.Debug("could not explain the refusal", "error", err)
	}
}

func writeSIWS(ctx context.Context, conn *websocket.Conn, msg siwsMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("pack the sign-in frame: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, siwsFrameTimeout)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		return fmt.Errorf("write a sign-in frame: %w", err)
	}
	return nil
}

// siwsFrameTimeout is a backstop on any single frame, so one stuck read cannot
// hold the connection past the exchange as a whole.
const siwsFrameTimeout = 30 * time.Second

func readSIWS(ctx context.Context, conn *websocket.Conn, out *siwsMessage) error {
	ctx, cancel := context.WithTimeout(ctx, siwsExchangeTimeout)
	defer cancel()

	_, body, err := conn.Read(ctx)
	if err != nil {
		return err
	}
	if len(body) > siwsMaxFrame {
		return fmt.Errorf("sign-in frame is %d bytes", len(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("the sign-in frame is not readable: %w", err)
	}
	return nil
}

// siwsMaxFrame is well above a sign-in message and its signature together, and
// far below anything a hostile client would want to be sent.
const siwsMaxFrame = 64 << 10
