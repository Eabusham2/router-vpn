package applexray

import (
	"context"
	"io"
	"net"
	"sync"
)

// StreamConn gives Xray's in-process TCP connection real net.Conn deadlines.
// net.Pipe provides the deadline semantics; two bounded copy loops feed the
// actual encrypted dispatcher. No TCP listener, loopback proxy or OS socket is
// opened. A cancelled owner closes both directions and the underlying ray.
type StreamConn struct {
	net.Conn
	transport net.Conn
	bridge    net.Conn
	remote    net.Addr
	done      chan struct{}
	once      sync.Once
	closeErr  error
}

func NewStreamConn(owner context.Context, transport net.Conn, remote net.Addr) *StreamConn {
	client, bridge := net.Pipe()
	conn := &StreamConn{Conn: client, transport: transport, bridge: bridge, remote: remote, done: make(chan struct{})}
	go func() {
		select {
		case <-owner.Done():
			_ = conn.Close()
		case <-conn.done:
		}
	}()
	go func() { _, _ = io.CopyBuffer(bridge, transport, make([]byte, 32*1024)); _ = conn.Close() }()
	go func() { _, _ = io.CopyBuffer(transport, bridge, make([]byte, 32*1024)); _ = conn.Close() }()
	return conn
}
func (c *StreamConn) Close() error {
	c.once.Do(func() {
		_ = c.Conn.Close()
		_ = c.bridge.Close()
		c.closeErr = c.transport.Close()
		close(c.done)
	})
	return c.closeErr
}
func (c *StreamConn) LocalAddr() net.Addr  { return c.transport.LocalAddr() }
func (c *StreamConn) RemoteAddr() net.Addr { return c.remote }
