package startwhitening

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// DialAuthenticatedStream publishes a duplex stream only after its initial
// authenticated request is complete. SS2022's lazy request publishes the salt
// after writing the header; a concurrent first Read must not observe it early.
// The raw socket is still private here, so cancellation closes that exact
// socket and joins its close before any failed construction can finish.
func DialAuthenticatedStream(ctx context.Context, raw net.Conn, handshake func(net.Conn) (net.Conn, error)) (net.Conn, error) {
	if ctx == nil || raw == nil || handshake == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, errors.New("authenticated stream requires its captured context and socket")
	}
	var closeOnce sync.Once
	var closeErr error
	closed := make(chan struct{})
	closeRaw := func() { closeOnce.Do(func() { closeErr = raw.Close(); close(closed) }) }
	fail := func(cipher net.Conn, cause error) (net.Conn, error) {
		closeRaw()
		if cipher != nil {
			cause = errors.Join(cause, cipher.Close())
		}
		return nil, errors.Join(cause, closeErr)
	}
	if err := ctx.Err(); err != nil {
		return fail(nil, err)
	}
	// The pinned WebSocket transport deliberately does not expose deadlines.
	// Keep the construction bound independent of that optional capability:
	// expiry closes this captured socket and construction still joins the close.
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deadline, _ := bounded.Deadline()
	deadlineSupported := true
	if err := raw.SetDeadline(deadline); err != nil {
		if !errors.Is(err, os.ErrInvalid) {
			return fail(nil, err)
		}
		deadlineSupported = false
	}
	stop := context.AfterFunc(bounded, closeRaw)
	cipher, err := handshake(raw)
	if !stop() {
		<-closed
	}
	if err != nil || bounded.Err() != nil {
		return fail(cipher, errors.Join(err, bounded.Err()))
	}
	if cipher == nil {
		return fail(nil, errors.New("authenticated handshake returned no captured stream"))
	}
	if deadlineSupported {
		if err := raw.SetDeadline(time.Time{}); err != nil {
			return fail(cipher, err)
		}
	}
	if err := bounded.Err(); err != nil {
		return fail(cipher, err)
	}
	return GuardAuthenticatedStream(raw, cipher), nil
}

// StreamGuard owns a physical stream and its authenticated wrapper. Closing
// the physical stream first interrupts blocked cipher I/O; closing the cipher
// after both directions drain avoids races with lazy reader/writer creation.
// It intentionally does not expose Upstream/ReaderReplaceable fast paths that
// would let native copy routines bypass the lifecycle locks.
type StreamGuard struct {
	self      *StreamGuard
	closeDone chan struct{}
	raw       net.Conn
	cipher    net.Conn
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closed    atomic.Bool
	once      sync.Once
	closeErr  error
}

func GuardAuthenticatedStream(raw, cipher net.Conn) *StreamGuard {
	guard := &StreamGuard{raw: raw, cipher: cipher, closeDone: make(chan struct{})}
	guard.self = guard
	return guard
}
func (c *StreamGuard) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.cipher.Read(p)
}
func (c *StreamGuard) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.cipher.Write(p)
}
func (c *StreamGuard) NeedHandshake() bool {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return false
	}
	h, ok := c.cipher.(interface{ NeedHandshake() bool })
	return ok && h.NeedHandshake()
}
func (c *StreamGuard) Close() error {
	c.once.Do(func() {
		defer close(c.closeDone)
		c.closed.Store(true)
		interrupt := c.raw.Close()
		c.readMu.Lock()
		defer c.readMu.Unlock()
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.closeErr = errors.Join(interrupt, c.cipher.Close())
	})
	return c.closeErr
}
func (c *StreamGuard) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *StreamGuard) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *StreamGuard) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *StreamGuard) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *StreamGuard) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

var _ net.Conn = (*StreamGuard)(nil)

// CaptureJoinedRetirement reveals no transport or cipher. An owner that already
// holds the exact raw connection may capture this cleanup-only acknowledgement
// while live. It becomes usable only after Close joins the original raw close,
// both I/O directions and the original cipher close. Close still returns errors.
func (c *StreamGuard) CaptureJoinedRetirement(knownRaw net.Conn) func(context.Context) error {
	if c == nil || c.self != c || knownRaw == nil || reflect.ValueOf(knownRaw).Kind() != reflect.Pointer || c.raw != knownRaw || c.cipher == nil || reflect.ValueOf(c.cipher).Kind() != reflect.Pointer || c.closeDone == nil || c.closed.Load() {
		return nil
	}
	raw, cipher, done := c.raw, c.cipher, c.closeDone
	return func(ctx context.Context) error {
		if ctx == nil || ctx.Err() != nil || c.self != c || c.raw != raw || c.cipher != cipher || c.closeDone != done {
			return errors.New("authenticated retirement lost its original stream")
		}
		select {
		case <-done:
		default:
			return errors.New("authenticated original stream has not joined")
		}
		return ctx.Err()
	}
}
