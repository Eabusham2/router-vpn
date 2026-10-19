package turbotunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RedialPacketConn retains Snowflake's persistent KCP packet stream across
// short-lived WebRTC peers. Every dial and both packet pumps belong to this
// owner; Close returns only after they have actually exited.
type RedialPacketConn struct {
	localAddr   net.Addr
	remoteAddr  net.Addr
	dialContext func(context.Context) (net.PacketConn, error)
	ctx         context.Context
	cancel      context.CancelFunc
	recvQueue   chan []byte
	sendQueue   chan []byte
	closed      chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
	err         atomic.Value
}

func NewRedialPacketConn(localAddr, remoteAddr net.Addr, dialContext func(context.Context) (net.PacketConn, error)) *RedialPacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &RedialPacketConn{localAddr: localAddr, remoteAddr: remoteAddr, dialContext: dialContext,
		ctx: ctx, cancel: cancel, recvQueue: make(chan []byte, queueSize), sendQueue: make(chan []byte, queueSize),
		closed: make(chan struct{}), done: make(chan struct{})}
	go c.dialLoop()
	return c
}

func (c *RedialPacketConn) dialLoop() {
	defer close(c.done)
	defer c.beginClose(nil)
	for c.ctx.Err() == nil {
		conn, err := c.dialContext(c.ctx)
		if err != nil || c.ctx.Err() != nil {
			// Even a failed dial may return an owned connection. A canceled
			// wait never grants permission to discard its real close.
			if conn != nil {
				_ = conn.Close()
			}
			c.beginClose(err)
			return
		}
		if conn == nil {
			c.beginClose(errors.New("Snowflake redial returned no connection"))
			return
		}
		c.exchange(conn)
	}
}

func (c *RedialPacketConn) exchange(conn net.PacketConn) {
	stop := make(chan struct{})
	readDone, writeDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			var buf [1500]byte
			n, _, err := conn.ReadFrom(buf[:])
			if err != nil {
				return
			}
			select {
			case <-stop:
				return
			case <-c.closed:
				return
			default:
			}
			packet := append([]byte(nil), buf[:n]...)
			select {
			case c.recvQueue <- packet:
			default: // KCP retransmits dropped packets when the bounded queue fills.
			}
		}
	}()
	go func() {
		defer close(writeDone)
		for {
			select {
			case <-stop:
				return
			case <-c.closed:
				return
			case packet := <-c.sendQueue:
				if c.ctx.Err() != nil {
					return
				}
				if _, err := conn.WriteTo(packet, c.remoteAddr); err != nil {
					return
				}
			}
		}
	}()
	select {
	case <-c.closed:
	case <-readDone:
	case <-writeDone:
	}
	close(stop)
	// Closing the current peer interrupts any read or backpressured write.
	// No send on an unbuffered error channel can outlive the receiver.
	_ = conn.Close()
	<-readDone
	<-writeDone
}

func (c *RedialPacketConn) opError(op string) error {
	return &net.OpError{Op: op, Net: c.localAddr.Network(), Source: c.localAddr, Addr: c.remoteAddr, Err: c.err.Load().(error)}
}

func (c *RedialPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, c.opError("read")
	default:
	}
	select {
	case <-c.closed:
		return 0, nil, c.opError("read")
	case packet := <-c.recvQueue:
		return copy(p, packet), c.remoteAddr, nil
	}
}

func (c *RedialPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, c.opError("write")
	default:
	}
	packet := append([]byte(nil), p...)
	select {
	case <-c.closed:
		return 0, c.opError("write")
	case c.sendQueue <- packet:
	default: // Retain upstream bounded, lossy datagram semantics.
	}
	return len(p), nil
}

func (c *RedialPacketConn) beginClose(err error) {
	c.closeOnce.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		c.err.Store(err)
		close(c.closed)
		c.cancel()
	})
}

func (c *RedialPacketConn) Close() error {
	c.beginClose(nil)
	<-c.done
	return nil
}

func (c *RedialPacketConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *RedialPacketConn) SetDeadline(time.Time) error      { return errNotImplemented }
func (c *RedialPacketConn) SetReadDeadline(time.Time) error  { return errNotImplemented }
func (c *RedialPacketConn) SetWriteDeadline(time.Time) error { return errNotImplemented }
