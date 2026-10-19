package snowflake_client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var errBrokerSocketClose = errors.New("captured Snowflake broker socket did not close cleanly")

// brokerIOOwner retires the physical work of one HTTP exchange. net/http can
// return from RoundTrip before an asynchronous TLS or HTTP worker finishes.
// Admission is therefore frozen before closing sockets, and every admitted
// dial, socket close, read and write must finish before this owner is released.
// Late standard-library housekeeping can only observe net.ErrClosed; it cannot
// perform another operation on the captured lower network.
type brokerIOOwner struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dial       func(context.Context, string, string) (net.Conn, error)
	mu         sync.Mutex
	closing    bool
	sockets    map[*brokerIOConn]struct{}
	pending    sync.WaitGroup
	done       chan struct{}
	failure    error
	parentStop func() bool
	parentDone chan struct{}
	parentOnce sync.Once
}

func newBrokerIOOwner(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (*brokerIOOwner, error) {
	if ctx == nil || ctx.Err() != nil || dial == nil {
		return nil, errors.New("Snowflake broker requires an active captured network")
	}
	lifetime, cancel := context.WithCancel(ctx)
	o := &brokerIOOwner{ctx: lifetime, cancel: cancel, dial: dial,
		sockets: make(map[*brokerIOConn]struct{}), done: make(chan struct{}), parentDone: make(chan struct{})}
	o.parentStop = context.AfterFunc(ctx, func() { defer close(o.parentDone); o.beginClose() })
	return o, nil
}

func (o *brokerIOOwner) begin(conn *brokerIOConn) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closing || o.ctx.Err() != nil || (conn != nil && conn.closing) {
		return net.ErrClosed
	}
	o.pending.Add(1)
	return nil
}

func (o *brokerIOOwner) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("Snowflake broker dial context is missing")
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
		return nil, errors.New("captured Snowflake broker dial failed")
	}
	conn := &brokerIOConn{owner: o, conn: raw,
		local: captureBrokerAddr(raw.LocalAddr()), remote: captureBrokerAddr(raw.RemoteAddr())}
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

func (o *brokerIOOwner) recordClose(err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	o.mu.Lock()
	o.failure = errBrokerSocketClose
	o.mu.Unlock()
	return errBrokerSocketClose
}

func (o *brokerIOOwner) beginClose() {
	o.mu.Lock()
	if o.closing {
		o.mu.Unlock()
		return
	}
	o.closing = true
	sockets := make([]*brokerIOConn, 0, len(o.sockets))
	for conn := range o.sockets {
		sockets = append(sockets, conn)
	}
	o.mu.Unlock()
	o.cancel()
	// One slow native Close must not delay cancellation of the other sockets.
	// Their existing ownership tokens keep the completion barrier nonzero.
	for _, conn := range sockets {
		go func(conn *brokerIOConn) { _ = conn.Close() }(conn)
	}
	go func() { o.pending.Wait(); close(o.done) }()
}

// Close is an actual completion barrier, without a fabricated timeout success.
// The enclosing Bridges.Close(context) provides a bounded wait and retains this
// exchange in quarantine until its worker returns. Repeated calls are safe.
func (o *brokerIOOwner) Close() error {
	o.beginClose()
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

type brokerIOConn struct {
	owner   *brokerIOOwner
	conn    net.Conn
	local   net.Addr
	remote  net.Addr
	closing bool // owner.mu
	once    sync.Once
	err     error
}

func (c *brokerIOConn) Read(b []byte) (int, error) {
	if err := c.owner.begin(c); err != nil {
		return 0, err
	}
	defer c.owner.pending.Done()
	return c.conn.Read(b)
}
func (c *brokerIOConn) Write(b []byte) (int, error) {
	if err := c.owner.begin(c); err != nil {
		return 0, err
	}
	defer c.owner.pending.Done()
	return c.conn.Write(b)
}
func (c *brokerIOConn) Close() error {
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
func (c *brokerIOConn) LocalAddr() net.Addr  { return c.local }
func (c *brokerIOConn) RemoteAddr() net.Addr { return c.remote }
func (c *brokerIOConn) SetDeadline(deadline time.Time) error {
	if err := c.owner.begin(c); err != nil {
		return err
	}
	defer c.owner.pending.Done()
	return c.conn.SetDeadline(deadline)
}
func (c *brokerIOConn) SetReadDeadline(deadline time.Time) error {
	if err := c.owner.begin(c); err != nil {
		return err
	}
	defer c.owner.pending.Done()
	return c.conn.SetReadDeadline(deadline)
}
func (c *brokerIOConn) SetWriteDeadline(deadline time.Time) error {
	if err := c.owner.begin(c); err != nil {
		return err
	}
	defer c.owner.pending.Done()
	return c.conn.SetWriteDeadline(deadline)
}

// Address methods are immutable metadata and never call the lower socket
// after shutdown. The wrapper intentionally exposes no raw-socket interfaces.
type brokerAddr struct{ network, address string }

func (a brokerAddr) Network() string { return a.network }
func (a brokerAddr) String() string  { return a.address }
func captureBrokerAddr(address net.Addr) net.Addr {
	if address == nil {
		return nil
	}
	return brokerAddr{network: address.Network(), address: address.String()}
}
