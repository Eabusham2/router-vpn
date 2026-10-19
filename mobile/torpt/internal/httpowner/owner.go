// Package httpowner retires captured physical HTTP work before a transport owner is released.
package httpowner

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// ErrClose retains a native socket close failure without exposing its credentials.
var ErrClose = errors.New("captured HTTP socket did not close cleanly")

// Owner retires the physical work of one HTTP exchange. net/http can
// return from RoundTrip before an asynchronous TLS or HTTP worker finishes.
// Admission is therefore frozen before closing sockets, and every admitted
// dial, socket close, read and write must finish before this owner is released.
// Late standard-library housekeeping can only observe net.ErrClosed; it cannot
// perform another operation on the captured lower network.
type Owner struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dial       func(context.Context, string, string) (net.Conn, error)
	mu         sync.Mutex
	closing    bool
	sockets    map[*connection]struct{}
	pending    sync.WaitGroup
	done       chan struct{}
	failure    error
	parentStop func() bool
	parentDone chan struct{}
	parentOnce sync.Once
}

func New(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (*Owner, error) {
	if ctx == nil || ctx.Err() != nil || dial == nil {
		return nil, errors.New("HTTP transport requires an active captured network")
	}
	lifetime, cancel := context.WithCancel(ctx)
	o := &Owner{ctx: lifetime, cancel: cancel, dial: dial,
		sockets: make(map[*connection]struct{}), done: make(chan struct{}), parentDone: make(chan struct{})}
	o.parentStop = context.AfterFunc(ctx, func() { defer close(o.parentDone); o.BeginClose() })
	return o, nil
}

func (o *Owner) begin(conn *connection) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closing || o.ctx.Err() != nil || (conn != nil && conn.closing) {
		return net.ErrClosed
	}
	o.pending.Add(1)
	return nil
}

func (o *Owner) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("HTTP dial context is missing")
	}
	if err := o.begin(nil); err != nil {
		return nil, err
	}
	defer o.pending.Done()
	combined, cancel := context.WithCancel(ctx)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(o.ctx, func() { cancel(); close(callbackDone) })
	defer func() {
		if !stop() {
			<-callbackDone
		}
		cancel()
	}()
	if combined.Err() != nil || o.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	raw, err := o.dial(combined, network, address)
	if err != nil || raw == nil {
		if raw != nil {
			o.recordClose(raw.Close())
		}
		return nil, errors.New("captured HTTP dial failed")
	}
	conn := &connection{owner: o, conn: raw,
		local: captureAddr(raw.LocalAddr()), remote: captureAddr(raw.RemoteAddr())}
	o.mu.Lock()
	if o.closing || o.ctx.Err() != nil || ctx.Err() != nil || combined.Err() != nil {
		o.mu.Unlock()
		// The original pending dial retains even a late successful socket until
		// its actual Close finishes. It is never published to HTTP or another owner.
		o.recordClose(raw.Close())
		return nil, net.ErrClosed
	}
	o.pending.Add(1) // Retain the adopted socket through its actual native Close.
	o.sockets[conn] = struct{}{}
	o.mu.Unlock()
	return conn, nil
}

func (o *Owner) recordClose(err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	o.mu.Lock()
	o.failure = ErrClose
	o.mu.Unlock()
	return ErrClose
}

func (o *Owner) BeginClose() {
	o.mu.Lock()
	if o.closing {
		o.mu.Unlock()
		return
	}
	o.closing = true
	sockets := make([]*connection, 0, len(o.sockets))
	for conn := range o.sockets {
		sockets = append(sockets, conn)
	}
	o.mu.Unlock()
	o.cancel()
	// One slow native Close must not delay cancellation of the other sockets.
	// Their existing ownership tokens keep the completion barrier nonzero.
	for _, conn := range sockets {
		go func(conn *connection) { _ = conn.Close() }(conn)
	}
	go func() { o.pending.Wait(); close(o.done) }()
}

// Close is an actual completion barrier, without a fabricated timeout success.
// An enclosing transport Close(context) can bound its wait while retaining this
// owner in quarantine until its worker returns. Repeated calls are safe.
func (o *Owner) Close() error {
	o.BeginClose()
	o.parentOnce.Do(func() {
		if o.parentStop() {
			close(o.parentDone)
		}
	})
	<-o.parentDone
	<-o.done
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.failure
}

type connection struct {
	owner   *Owner
	conn    net.Conn
	local   net.Addr
	remote  net.Addr
	closing bool // owner.mu
	once    sync.Once
	err     error
}

func (c *connection) Read(b []byte) (int, error) {
	if err := c.owner.begin(c); err != nil {
		return 0, err
	}
	defer c.owner.pending.Done()
	return c.conn.Read(b)
}
func (c *connection) Write(b []byte) (int, error) {
	if err := c.owner.begin(c); err != nil {
		return 0, err
	}
	defer c.owner.pending.Done()
	return c.conn.Write(b)
}
func (c *connection) Close() error {
	c.once.Do(func() {
		c.owner.mu.Lock()
		c.closing = true
		c.owner.mu.Unlock()
		c.err = c.owner.recordClose(c.conn.Close())
		c.owner.mu.Lock()
		delete(c.owner.sockets, c)
		c.owner.mu.Unlock()
		c.owner.pending.Done()
	})
	return c.err
}
func (c *connection) LocalAddr() net.Addr  { return c.local }
func (c *connection) RemoteAddr() net.Addr { return c.remote }
func (c *connection) SetDeadline(deadline time.Time) error {
	if err := c.owner.begin(c); err != nil {
		return err
	}
	defer c.owner.pending.Done()
	return c.conn.SetDeadline(deadline)
}
func (c *connection) SetReadDeadline(deadline time.Time) error {
	if err := c.owner.begin(c); err != nil {
		return err
	}
	defer c.owner.pending.Done()
	return c.conn.SetReadDeadline(deadline)
}
func (c *connection) SetWriteDeadline(deadline time.Time) error {
	if err := c.owner.begin(c); err != nil {
		return err
	}
	defer c.owner.pending.Done()
	return c.conn.SetWriteDeadline(deadline)
}

// Address methods are immutable metadata and never call the lower socket
// after shutdown. The wrapper intentionally exposes no raw-socket interfaces.
type frozenAddr struct{ network, address string }

func (a frozenAddr) Network() string { return a.network }
func (a frozenAddr) String() string  { return a.address }
func captureAddr(address net.Addr) net.Addr {
	if address == nil {
		return nil
	}
	return frozenAddr{network: address.Network(), address: address.String()}
}
