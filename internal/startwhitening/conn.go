// Package startwhitening implements only Router VPN's reversible ciphertext
// whitening. Authentication and encryption MUST be provided by Shadowsocks
// 2022 AES-256-GCM; whitening itself is not a security layer.
package startwhitening

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

const Method = "2022-blake3-aes-256-gcm"
const Type = "routervpn-aes-xor"
const label = "router-vpn-xor-whitening-v1\x00"
const MaxConnections = 256

// Key uses the existing server's exact domain-separated whitening schedule.
// The original password bytes are preserved; no authentication key is changed.
func Key(method, password string) ([32]byte, error) {
	if strings.ToLower(strings.TrimSpace(method)) != Method || len(password) < 16 || len(password) > 4096 || strings.ContainsRune(password, '\x00') {
		return [32]byte{}, errors.New("whitening requires an authenticated Shadowsocks 2022 AES-256-GCM profile")
	}
	return sha256.Sum256([]byte(label + password)), nil
}

// Owner bounds physical connections and cancels both established and in-flight
// dials on teardown or interface changes. Adoption is generation-checked.
type Owner struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	generation context.Context
	reset      context.CancelFunc
	closed     bool
	closeDone  chan struct{}
	closeErr   error
	pending    int
	conns      map[*Conn]struct{}
}

func NewOwner(parent context.Context) *Owner {
	ctx, cancel := context.WithCancel(parent)
	gen, reset := context.WithCancel(ctx)
	o := &Owner{ctx: ctx, cancel: cancel, generation: gen, reset: reset, conns: make(map[*Conn]struct{}), closeDone: make(chan struct{})}
	go func() { <-ctx.Done(); _ = o.Close() }()
	return o
}

// Open never uses net.Dial itself. The host supplies its native protected
// physical dialer, so no request can escape to an ordinary-interface fallback.
func (o *Owner) Open(ctx context.Context, key [32]byte, datagram bool, dial func(context.Context) (net.Conn, error)) (*Conn, error) {
	if ctx == nil || dial == nil {
		return nil, errors.New("missing whitening connection owner")
	}
	o.mu.Lock()
	if o.closed || o.ctx.Err() != nil || o.pending+len(o.conns) >= MaxConnections {
		o.mu.Unlock()
		return nil, errors.New("whitening owner is closed or at its connection limit")
	}
	generation := o.generation
	o.pending++
	o.mu.Unlock()
	dctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(generation, cancel)
	if generation.Err() != nil {
		cancel()
	}
	raw, err := dial(dctx)
	expired := dctx.Err() != nil
	stop()
	cancel()
	o.mu.Lock()
	o.pending--
	if err != nil || expired || o.closed || o.generation != generation || generation.Err() != nil {
		o.mu.Unlock()
		if raw != nil {
			_ = raw.Close()
		}
		if err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	if raw == nil {
		o.mu.Unlock()
		return nil, errors.New("native dialer returned no whitening connection")
	}
	conn := &Conn{Conn: raw, key: key, datagram: datagram, owner: o}
	o.conns[conn] = struct{}{}
	o.mu.Unlock()
	return conn, nil
}

func (o *Owner) Reset()       { _ = o.finish(false) }
func (o *Owner) Close() error { return o.finish(true) }
func (o *Owner) finish(closeOwner bool) error {
	o.mu.Lock()
	if o.closed {
		done := o.closeDone
		o.mu.Unlock()
		<-done // A second Close cannot certify a still-running first teardown.
		return o.closeErr
	}
	o.reset()
	if closeOwner {
		o.closed = true
		o.cancel()
	} else {
		o.generation, o.reset = context.WithCancel(o.ctx)
	}
	all := make([]*Conn, 0, len(o.conns))
	for conn := range o.conns {
		all = append(all, conn)
	}
	o.mu.Unlock()
	var errs []error
	for _, conn := range all {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	err := errors.Join(errs...)
	if closeOwner {
		o.mu.Lock()
		o.closeErr = err
		close(o.closeDone)
		o.mu.Unlock()
	}
	return err
}

// Conn whitens ciphertext without altering caller buffers. A TCP direction
// advances only by bytes actually transferred; every UDP datagram starts at 0.
// Deadlines are the actual native socket deadlines, not simulated success.
type Conn struct {
	net.Conn
	key                     [32]byte
	datagram                bool
	readMu, writeMu         sync.Mutex
	readOffset, writeOffset uint64
	closeOnce               sync.Once
	closeErr                error
	owner                   *Owner
}

func apply(b []byte, key [32]byte, offset uint64) {
	for i := range b {
		b[i] ^= key[(offset+uint64(i))%uint64(len(key))]
	}
}
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, err := c.Conn.Read(b)
	if n < 0 || n > len(b) {
		return 0, errors.New("native whitening read violated the socket contract")
	}
	apply(b[:n], c.key, c.readOffset)
	if !c.datagram {
		c.readOffset += uint64(n)
	}
	return n, err
}
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.datagram && len(b) > 65535 {
		return 0, io.ErrShortBuffer
	}
	// Bound each TCP scratch allocation; do not split a UDP datagram.
	const chunkSize = 32 * 1024
	total := 0
	for total < len(b) || (c.datagram && total == 0) {
		end := len(b)
		if !c.datagram && end-total > chunkSize {
			end = total + chunkSize
		}
		out := append([]byte(nil), b[total:end]...)
		apply(out, c.key, c.writeOffset)
		n, err := c.Conn.Write(out)
		if n < 0 || n > len(out) {
			return total, errors.New("native whitening write violated the socket contract")
		}
		if !c.datagram {
			c.writeOffset += uint64(n)
		}
		total += n
		if err != nil {
			return total, err
		}
		if n != len(out) {
			return total, io.ErrShortWrite
		}
		if c.datagram {
			break
		}
	}
	return total, nil
}
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		// Closing the physical socket must interrupt pending I/O BEFORE taking
		// the offset locks. This also avoids a close/read deadlock.
		c.closeErr = c.Conn.Close()
		c.readMu.Lock()
		c.writeMu.Lock()
		clear(c.key[:])
		c.writeMu.Unlock()
		c.readMu.Unlock()
		if c.owner != nil {
			c.owner.mu.Lock()
			delete(c.owner.conns, c)
			c.owner.mu.Unlock()
		}
	})
	return c.closeErr
}
func (c *Conn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}
