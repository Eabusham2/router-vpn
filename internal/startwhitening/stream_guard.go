package startwhitening

import (
	"context"
	"errors"
	"net"
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
	deadline := time.Now().Add(10 * time.Second)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return fail(nil, err)
	}
	stop := context.AfterFunc(ctx, closeRaw)
	cipher, err := handshake(raw)
	if !stop() {
		<-closed
	}
	if err != nil || ctx.Err() != nil {
		return fail(cipher, errors.Join(err, ctx.Err()))
	}
	if cipher == nil {
		return fail(nil, errors.New("authenticated handshake returned no captured stream"))
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return fail(cipher, err)
	}
	if err := ctx.Err(); err != nil {
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
	raw      net.Conn
	cipher   net.Conn
	readMu   sync.Mutex
	writeMu  sync.Mutex
	closed   atomic.Bool
	once     sync.Once
	closeErr error
}

func GuardAuthenticatedStream(raw, cipher net.Conn) *StreamGuard {
	return &StreamGuard{raw: raw, cipher: cipher}
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
