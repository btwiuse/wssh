package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/btwiuse/wssh/auth/siws"
	"github.com/coder/websocket"
)

// The frames of the wallet sign-in exchange. They mirror the server's exactly;
// they are spelled out separately rather than shared because the two sides
// build for different things and a shared package would drag a websocket
// dependency into code that has no business having one.
const (
	siwsKindChallenge = "challenge"
	siwsKindSignIn    = "signin"
	siwsKindReady     = "ready"
	siwsKindError     = "error"
)

// siwsFrame is one message of the exchange. Every frame says what it is, so an
// unexpected one can be refused rather than guessed at.
type siwsFrame struct {
	Kind string `json:"kind"`

	Challenge *siws.SIWSInput `json:"challenge,omitempty"`

	Message   []byte `json:"message,omitempty"`
	Signature []byte `json:"signature,omitempty"`

	Address string `json:"address,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// siwsFrameTimeout bounds a read or write after the first one, so a client that
// goes quiet holding a wallet prompt does not hold the connection open.
const siwsFrameTimeout = 3 * time.Minute

// siwsMaxFrame is well above a sign-in message and its signature together, and
// far below anything worth sending on behalf of a client that has gone wrong.
const siwsMaxFrame = 64 << 10

func readSIWSFrame(ctx context.Context, conn *websocket.Conn, wait time.Duration) (siwsFrame, error) {
	var frame siwsFrame

	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	_, body, err := conn.Read(ctx)
	if err != nil {
		return frame, err
	}
	if len(body) > siwsMaxFrame {
		return frame, fmt.Errorf("sign-in frame is %d bytes", len(body))
	}
	if err := json.Unmarshal(body, &frame); err != nil {
		return frame, fmt.Errorf("the sign-in frame is not readable: %w", err)
	}
	return frame, nil
}

func writeSIWSFrame(ctx context.Context, conn *websocket.Conn, frame siwsFrame) error {
	body, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("pack the sign-in frame: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, siwsFrameTimeout)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, body)
}

// SIWSSubprotocol is the subprotocol a client offers to say it is willing to
// sign in. A server echoes it only when it will ask, which is what spares an
// ordinary connection from waiting for a question that is never coming.
const SIWSSubprotocol = "wssh.wssh-siws.v1"
