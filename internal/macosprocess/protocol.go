package macosprocess

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

var shortDigest = regexp.MustCompile(`^[a-f0-9]{32}$`)
var longDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Selection contains only public immutable identities. Credentials and source
// documents remain in the inherited original private workspace.
type Selection struct {
	Session          string `json:"session"`
	Source           string `json:"source"`
	Config           string `json:"config"`
	CallerUID        uint32 `json:"caller_uid"`
	WorkspaceDevice  uint64 `json:"workspace_device"`
	WorkspaceInode   uint64 `json:"workspace_inode"`
	EngineSHA256     string `json:"engine_sha256"`
	ControllerSHA256 string `json:"controller_sha256"`
	CatalogSHA256    string `json:"catalog_sha256"`
	InputsSHA256     string `json:"inputs_sha256"`
}

func (s Selection) valid() bool {
	return shortDigest.MatchString(s.Session) && longDigest.MatchString(s.Source) && longDigest.MatchString(s.Config) &&
		s.CallerUID != 0 && s.CallerUID != ^uint32(0) && s.WorkspaceInode != 0 && longDigest.MatchString(s.EngineSHA256) && longDigest.MatchString(s.ControllerSHA256) && longDigest.MatchString(s.CatalogSHA256) && longDigest.MatchString(s.InputsSHA256)
}

type frame struct {
	Selection
	Schema   int    `json:"schema"`
	Sequence uint64 `json:"sequence"`
	Stage    string `json:"stage"`
	Nonce    string `json:"nonce"`
}

type transport interface {
	Send(context.Context, json.RawMessage) error
	Receive(context.Context, uint32) (json.RawMessage, error)
	Close() error
}

func decodeFrame(raw []byte) (frame, error) {
	var value frame
	if len(raw) == 0 || len(raw) > 8192 {
		return value, errors.New("native child frame exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return value, errors.New("native child frame is not one object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return value, errors.New("native child frame repeats an identity")
		}
		seen[name] = true
		var field json.RawMessage
		if err := decoder.Decode(&field); err != nil {
			return value, err
		}
		if bytes.Equal(field, []byte("null")) {
			return value, errors.New("native child frame contains a null identity")
		}
	}
	if last, err := decoder.Token(); err != nil || last != json.Delim('}') || len(seen) != 14 {
		return value, errors.New("native child frame has incomplete identities")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || value.Schema != 1 || !value.Selection.valid() || !longDigest.MatchString(value.Nonce) || value.Sequence > 6 {
		return value, errors.New("native child frame has another bounded capture")
	}
	switch value.Stage {
	case "offer", "ready", "ack", "accepted", "stop", "stopped", "finish":
	default:
		return value, errors.New("native child frame has another operation")
	}
	return value, nil
}

type protocol struct {
	channel   transport
	selection Selection
	nonce     string
	peer      uint32 // Obtained from actual creation/inheritance, never decoded.
	current   func(context.Context) error
}

func (p *protocol) send(ctx context.Context, stage string, sequence uint64) error {
	if err := p.current(ctx); err != nil {
		return err
	}
	raw, err := json.Marshal(frame{p.selection, 1, sequence, stage, p.nonce})
	if err != nil {
		return err
	}
	if err = p.channel.Send(ctx, raw); err != nil {
		return err
	}
	if stage == "finish" {
		// Receiving finish permits the child to exit. Its earlier stopped
		// receipt was fenced while it still awaited this message; only the
		// creator's original exec.Cmd waiter proves the subsequent exit.
		return ctx.Err()
	}
	return p.current(ctx)
}

func (p *protocol) receive(ctx context.Context, stage string, sequence uint64, offer bool) error {
	if err := p.current(ctx); err != nil {
		return err
	}
	raw, err := p.channel.Receive(ctx, p.peer)
	if err != nil {
		return err
	}
	value, err := decodeFrame(raw)
	if err != nil {
		return err
	}
	if value.Selection != p.selection || value.Stage != stage || value.Sequence != sequence || !offer && value.Nonce != p.nonce {
		return errors.New("native child frame belongs to another original source or operation")
	}
	if err := p.current(ctx); err != nil {
		return err
	}
	if offer {
		p.nonce = value.Nonce
	}
	return nil
}

func handshakeParent(ctx context.Context, p *protocol) error {
	if p == nil || p.channel == nil || p.current == nil || p.peer <= 1 || !p.selection.valid() {
		return errors.New("native parent bootstrap has no original capture")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	p.nonce = hex.EncodeToString(nonce[:])
	if err := p.send(ctx, "offer", 0); err != nil {
		return err
	}
	if err := p.receive(ctx, "ready", 1, false); err != nil {
		return err
	}
	if err := p.send(ctx, "ack", 2); err != nil {
		return err
	}
	return p.receive(ctx, "accepted", 3, false)
}

func handshakeChild(ctx context.Context, p *protocol) error {
	if p == nil || p.channel == nil || p.current == nil || p.peer <= 1 || !p.selection.valid() {
		return errors.New("native child bootstrap has no inherited capture")
	}
	if err := p.receive(ctx, "offer", 0, true); err != nil {
		return err
	}
	if err := p.send(ctx, "ready", 1); err != nil {
		return err
	}
	if err := p.receive(ctx, "ack", 2, false); err != nil {
		return err
	}
	return p.send(ctx, "accepted", 3)
}

func (p *protocol) stop(ctx context.Context) error {
	if err := p.send(ctx, "stop", 4); err != nil {
		return err
	}
	if err := p.receive(ctx, "stopped", 5, false); err != nil {
		return err
	}
	// The child stays alive through the final native peer/main-image check.
	// Only the original exec.Cmd waiter can subsequently prove its exit.
	return p.send(ctx, "finish", 6)
}

func (p *protocol) waitStop(ctx context.Context, closeNative func(context.Context) error) error {
	if closeNative == nil {
		return errors.New("native child has no original cleanup callback")
	}
	if err := p.receive(ctx, "stop", 4, false); err != nil {
		return err
	}
	if err := closeNative(ctx); err != nil {
		return err
	}
	if err := p.send(ctx, "stopped", 5); err != nil {
		return err
	}
	return p.receive(ctx, "finish", 6, false)
}
