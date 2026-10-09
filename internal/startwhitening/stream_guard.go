package startwhitening

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

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
