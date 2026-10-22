package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

// DialRetainedContext is the explicit retained-socket boundary used by DNS
// measurements. Unlike DialContext, it returns every non-nil native socket,
// including one delivered with an error or after cancellation. The caller must
// retain that socket and retry Close until it succeeds. Network.Close continues
// waiting for that actual closure; a failed first Close cannot retire its owner.
// The ordinary dial API and its publication semantics are unchanged.
func (n *Network) DialRetainedContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("native Tor retained dial context is unavailable")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("native Tor retained dial carries only TCP")
	}
	if err := n.begin(); err != nil {
		return nil, err
	}
	combined := n.operationContext(ctx)
	connection, dialErr := n.dial(combined, network, address)
	if connection == nil {
		combined.release()
		n.discard(nil)
		return nil, errors.New("native Tor retained dial returned no socket")
	}
	owned := &retainedNetworkConnection{Conn: connection, network: n, release: combined.release}
	// These sockets deliberately do not use socketOwner's one-shot Close.
	// Their session callback and returned owner retain the same pending count.
	owned.mu.Lock()
	owned.stop = context.AfterFunc(n.ctx, func() { _ = owned.Close() })
	owned.mu.Unlock()
	if dialErr != nil {
		return owned, errors.New("native Tor retained dial failed")
	}
	if err := combined.publish(); err != nil {
		return owned, errors.New("native Tor retained dial was cancelled")
	}
	n.mu.Lock()
	closing := n.closing || n.ctx.Err() != nil
	n.mu.Unlock()
	if closing {
		return owned, net.ErrClosed
	}
	return owned, nil
}

type retainedNetworkConnection struct {
	net.Conn
	mu      sync.Mutex
	network *Network
	stop    func() bool
	release func()
	closed  bool
}

func (c *retainedNetworkConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	err := c.Conn.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		return errors.New("native Tor retained socket close is pending")
	}
	c.closed = true
	if c.stop != nil {
		c.stop()
	}
	c.release()
	c.network.mu.Lock()
	c.network.count--
	c.network.mu.Unlock()
	c.network.pending.Done()
	return nil
}
