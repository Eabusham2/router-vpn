package macosprocess

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testTransport struct {
	incoming, outgoing chan json.RawMessage
	done               chan struct{}
	once               sync.Once
	mutate             func(json.RawMessage) json.RawMessage
	sentFinish         func()
}

func (c *testTransport) Send(ctx context.Context, raw json.RawMessage) error {
	if c.mutate != nil {
		raw = c.mutate(raw)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return errors.New("closed")
	case c.outgoing <- append(json.RawMessage(nil), raw...):
	}
	var f frame
	_ = json.Unmarshal(raw, &f)
	if f.Stage == "finish" && c.sentFinish != nil {
		c.sentFinish()
	}
	return nil
}
func (c *testTransport) Receive(ctx context.Context, peer uint32) (json.RawMessage, error) {
	if peer <= 1 {
		return nil, errors.New("missing native peer")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, errors.New("closed")
	case raw := <-c.incoming:
		return raw, nil
	}
}
func (c *testTransport) Close() error { c.once.Do(func() { close(c.done) }); return nil }
func testSelection() Selection {
	return Selection{strings.Repeat("1", 32), strings.Repeat("2", 64), strings.Repeat("3", 64), 501, 42, 73, strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64), strings.Repeat("9", 64)}
}
func protocolPair() (*protocol, *protocol, *testTransport, *testTransport) {
	a, b := make(chan json.RawMessage, 1), make(chan json.RawMessage, 1)
	left := &testTransport{incoming: a, outgoing: b, done: make(chan struct{})}
	right := &testTransport{incoming: b, outgoing: a, done: make(chan struct{})}
	check := func(ctx context.Context) error { return ctx.Err() }
	return &protocol{channel: left, selection: testSelection(), peer: 99, current: check}, &protocol{channel: right, selection: testSelection(), peer: 98, current: check}, left, right
}
func TestNativeChildProtocolOriginalHandshakeAndJoinedCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, c, left, _ := protocolPair()
	defer p.channel.Close()
	defer c.channel.Close()
	child := make(chan error, 1)
	var cleaned, exited atomic.Bool
	left.sentFinish = func() { exited.Store(true) }
	p.current = func(ctx context.Context) error {
		if exited.Load() {
			return errors.New("child exited")
		}
		return ctx.Err()
	}
	go func() {
		err := handshakeChild(ctx, c)
		if err == nil {
			err = c.waitStop(ctx, func(context.Context) error { cleaned.Store(true); return nil })
		}
		child <- err
	}()
	if err := handshakeParent(ctx, p); err != nil {
		t.Fatal(err)
	}
	if cleaned.Load() {
		t.Fatal("cleanup preceded stop")
	}
	if err := p.stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-child; err != nil {
		t.Fatal(err)
	}
	if !cleaned.Load() || !exited.Load() {
		t.Fatal("missing stopped cleanup or final release")
	}
}
func TestNativeChildProtocolRejectsForeignSelectionAndOrder(t *testing.T) {
	for _, change := range []string{"session", "source", "config", "caller_uid", "workspace_device", "workspace_inode", "engine_sha256", "controller_sha256", "catalog_sha256", "inputs_sha256", "nonce", "sequence", "stage"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			p, c, _, right := protocolPair()
			defer p.channel.Close()
			defer c.channel.Close()
			right.mutate = func(raw json.RawMessage) json.RawMessage {
				var values map[string]any
				_ = json.Unmarshal(raw, &values)
				if values["stage"] != "ready" {
					return raw
				}
				switch change {
				case "stage":
					values[change] = "accepted"
				case "sequence":
					values[change] = 3
				case "caller_uid", "workspace_device", "workspace_inode":
					values[change] = 777
				case "session":
					values[change] = strings.Repeat("7", 32)
				default:
					values[change] = strings.Repeat("7", 64)
				}
				out, _ := json.Marshal(values)
				return out
			}
			joined := make(chan error, 1)
			go func() { joined <- handshakeChild(ctx, c) }()
			if err := handshakeParent(ctx, p); err == nil {
				t.Fatal("accepted foreign capture")
			}
			cancel()
			<-joined
		})
	}
}
func TestNativeChildProtocolCleanupFailureCannotAcknowledge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	p, c, _, _ := protocolPair()
	defer p.channel.Close()
	defer c.channel.Close()
	sentinel := errors.New("native grants still retained")
	joined := make(chan error, 1)
	go func() {
		err := handshakeChild(ctx, c)
		if err == nil {
			err = c.waitStop(ctx, func(context.Context) error { return sentinel })
		}
		joined <- err
	}()
	if err := handshakeParent(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := p.stop(ctx); err == nil {
		t.Fatal("cleanup failure was acknowledged")
	}
	if err := <-joined; !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}
func TestNativeChildProtocolCancellationAndCurrentFailure(t *testing.T) {
	p, _, _, _ := protocolPair()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handshakeParent(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	sentinel := errors.New("actual runtime main image replaced")
	p.current = func(context.Context) error { return sentinel }
	if err := handshakeParent(context.Background(), p); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}
func TestNativeChildFrameExactObject(t *testing.T) {
	f := frame{testSelection(), 1, 0, "offer", strings.Repeat("8", 64)}
	raw, _ := json.Marshal(f)
	if _, err := decodeFrame(raw); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"duplicate": append([]byte(`{"schema":1,`), raw[1:]...), "null": []byte(strings.Replace(string(raw), `"schema":1`, `"schema":null`, 1)), "unknown": append([]byte(`{"unknown":1,`), raw[1:]...), "missing": []byte(strings.Replace(string(raw), `"schema":1,`, "", 1)), "trailing": append(raw, []byte(`{}`)...), "array": append(append([]byte("["), raw...), ']'), "large": []byte(strings.Repeat(" ", 8193))} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeFrame(body); err == nil {
				t.Fatal("accepted malformed frame")
			}
		})
	}
}
