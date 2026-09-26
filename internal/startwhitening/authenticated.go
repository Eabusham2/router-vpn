package startwhitening

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The vetted cipher owns mutable reader/writer state. Guard directions
// independently and interrupt its physical socket BEFORE waiting for active
// calls, so Close never races cipher construction or hangs behind a read.
// The owner retains the complete cipher handle until cleanup has finished.
type cipherGuard struct {
	raw             *Conn
	readMu, writeMu sync.Mutex
	closed          atomic.Bool
	once            sync.Once
	closeErr        error
}

func (g *cipherGuard) adopt(closer io.Closer) error {
	if g.raw == nil || g.raw.owner == nil {
		return errors.New("cipher has no native physical owner")
	}
	o := g.raw.owner
	o.mu.Lock()
	ok := !o.closed && o.ctx.Err() == nil && o.generation == g.raw.generation && o.conns[g.raw] == g.raw
	if ok {
		o.conns[g.raw] = closer
	}
	o.mu.Unlock()
	if !ok {
		_ = closer.Close()
		return net.ErrClosed
	}
	return nil
}
func (g *cipherGuard) close(closer io.Closer, cipher io.Closer) error {
	g.once.Do(func() {
		g.closed.Store(true)
		first := g.raw.Close()
		g.readMu.Lock()
		g.writeMu.Lock()
		second := cipher.Close()
		g.writeMu.Unlock()
		g.readMu.Unlock()
		o := g.raw.owner
		if o != nil {
			o.mu.Lock()
			if o.conns[g.raw] == closer {
				delete(o.conns, g.raw)
			}
			o.mu.Unlock()
		}
		g.closeErr = errors.Join(first, second)
	})
	return g.closeErr
}

type AuthenticatedStream struct {
	net.Conn
	guard cipherGuard
}

func OwnAuthenticatedStream(raw *Conn, cipher net.Conn) (*AuthenticatedStream, error) {
	if raw == nil || cipher == nil {
		return nil, errors.New("missing authenticated stream")
	}
	c := &AuthenticatedStream{Conn: cipher, guard: cipherGuard{raw: raw}}
	if err := c.guard.adopt(c); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *AuthenticatedStream) Read(b []byte) (int, error) {
	c.guard.readMu.Lock()
	defer c.guard.readMu.Unlock()
	if c.guard.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(b)
}
func (c *AuthenticatedStream) Write(b []byte) (int, error) {
	c.guard.writeMu.Lock()
	defer c.guard.writeMu.Unlock()
	if c.guard.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}
func (c *AuthenticatedStream) Close() error                  { return c.guard.close(c, c.Conn) }
func (c *AuthenticatedStream) SetDeadline(t time.Time) error { return c.guard.raw.SetDeadline(t) }
func (c *AuthenticatedStream) SetReadDeadline(t time.Time) error {
	return c.guard.raw.SetReadDeadline(t)
}
func (c *AuthenticatedStream) SetWriteDeadline(t time.Time) error {
	return c.guard.raw.SetWriteDeadline(t)
}

type AuthenticatedPacket struct {
	net.PacketConn
	guard   cipherGuard
	scratch []byte // private ciphertext buffer, protected by readMu
}

func OwnAuthenticatedPacket(raw *Conn, cipher net.PacketConn) (*AuthenticatedPacket, error) {
	if raw == nil || cipher == nil {
		return nil, errors.New("missing authenticated packet transport")
	}
	c := &AuthenticatedPacket{PacketConn: cipher, guard: cipherGuard{raw: raw}}
	if err := c.guard.adopt(c); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *AuthenticatedPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	c.guard.readMu.Lock()
	defer c.guard.readMu.Unlock()
	if c.guard.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	// A caller's plaintext buffer may be smaller than the encrypted frame.
	// Authenticate a WHOLE datagram first, then apply net.PacketConn truncation.
	if c.scratch == nil {
		c.scratch = make([]byte, 65535)
	}
	n, a, err := c.PacketConn.ReadFrom(c.scratch)
	if n < 0 || n > len(c.scratch) {
		return 0, nil, io.ErrShortBuffer
	}
	if err != nil {
		return 0, a, err
	}
	return copy(b, c.scratch[:n]), a, nil
}
func (c *AuthenticatedPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	c.guard.writeMu.Lock()
	defer c.guard.writeMu.Unlock()
	if c.guard.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.PacketConn.WriteTo(b, a)
}
func (c *AuthenticatedPacket) Close() error                  { return c.guard.close(c, c.PacketConn) }
func (c *AuthenticatedPacket) SetDeadline(t time.Time) error { return c.guard.raw.SetDeadline(t) }
func (c *AuthenticatedPacket) SetReadDeadline(t time.Time) error {
	return c.guard.raw.SetReadDeadline(t)
}
func (c *AuthenticatedPacket) SetWriteDeadline(t time.Time) error {
	return c.guard.raw.SetWriteDeadline(t)
}
