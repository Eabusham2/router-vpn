package startwhitening

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PacketGuard retains the original socket and authenticated datagram wrapper.
// Authentication consumes a complete ciphertext frame before a caller's
// smaller plaintext buffer truncates the result. Closing interrupts the exact
// socket, joins both cipher directions, and only then releases cipher state.
// No upstream/replaceable fast path may bypass these ownership boundaries.
type PacketGuard struct {
	raw      net.Conn
	cipher   net.PacketConn
	readMu   sync.Mutex
	writeMu  sync.Mutex
	scratch  []byte
	closed   atomic.Bool
	once     sync.Once
	closeErr error
}

// Construct the cipher around this same idempotent socket owner: interruption
// and the cipher's own Close must join one physical close without suppressing
// unrelated cipher errors or closing a replacement socket.
func GuardAuthenticatedPacket(raw net.Conn, construct func(net.Conn) net.PacketConn) *PacketGuard {
	owned := &packetGuardSocket{Conn: raw}
	return &PacketGuard{raw: owned, cipher: construct(owned)}
}

type packetGuardSocket struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *packetGuardSocket) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}

func (c *PacketGuard) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if c.scratch == nil {
		c.scratch = make([]byte, 65535)
	}
	n, address, err := c.cipher.ReadFrom(c.scratch)
	if n < 0 || n > len(c.scratch) {
		return 0, nil, io.ErrShortBuffer
	}
	if err != nil {
		return 0, address, err
	}
	return copy(p, c.scratch[:n]), address, nil
}

func (c *PacketGuard) WriteTo(p []byte, address net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.cipher.WriteTo(p, address)
}

func (c *PacketGuard) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		interrupt := c.raw.Close()
		c.readMu.Lock()
		defer c.readMu.Unlock()
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.closeErr = errors.Join(interrupt, c.cipher.Close())
		clear(c.scratch)
		c.scratch = nil
	})
	return c.closeErr
}

func (c *PacketGuard) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *PacketGuard) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *PacketGuard) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *PacketGuard) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

var _ net.PacketConn = (*PacketGuard)(nil)
