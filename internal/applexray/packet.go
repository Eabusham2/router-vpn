package applexray

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// PacketIO is implemented by the owned Xray dispatcher. Close must interrupt
// blocked reads and writes. It consumes/copies packets before returning.
type PacketIO interface {
	ReadPacket() ([]byte, net.Addr, error)
	WritePacket([]byte, net.Addr) error
	Close() error
}
type packet struct {
	data []byte
	addr net.Addr
	err  error
}
type packetWrite struct {
	data  []byte
	addr  net.Addr
	reply chan error
}
type packetDeadline struct {
	when    time.Time
	changed chan struct{}
}

// PacketConn adds real deadlines, cancellation, and bounded queues to the
// native packet dispatcher. Timed-out writes close the ray, so an abandoned
// write cannot be delivered later through a replacement session.
type PacketConn struct {
	io          PacketIO
	ctx         context.Context
	cancel      context.CancelFunc
	once        sync.Once
	closeErr    error
	incoming    chan packet
	outgoing    chan packetWrite
	mu          sync.Mutex
	read, write packetDeadline
}

func NewPacketConn(owner context.Context, transport PacketIO) *PacketConn {
	ctx, cancel := context.WithCancel(owner)
	p := &PacketConn{io: transport, ctx: ctx, cancel: cancel, incoming: make(chan packet, 16), outgoing: make(chan packetWrite, 16), read: packetDeadline{changed: make(chan struct{})}, write: packetDeadline{changed: make(chan struct{})}}
	// Do not publish a callback handle before construction is complete.
	go func() { <-ctx.Done(); p.Close() }()
	go p.readLoop()
	go p.writeLoop()
	return p
}
func (p *PacketConn) readLoop() {
	defer close(p.incoming)
	for {
		b, a, e := p.io.ReadPacket()
		select {
		case <-p.ctx.Done():
			return
		case p.incoming <- packet{b, a, e}:
		}
		if e != nil {
			return
		}
	}
}
func (p *PacketConn) writeLoop() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case w := <-p.outgoing:
			if p.ctx.Err() != nil {
				w.reply <- net.ErrClosed
				continue
			}
			e := p.io.WritePacket(w.data, w.addr)
			w.reply <- e
		}
	}
}
func (p *PacketConn) deadline(read bool) (time.Time, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := p.write
	if read {
		d = p.read
	}
	return d.when, d.changed
}
func timer(when time.Time) (<-chan time.Time, func()) {
	if when.IsZero() {
		return nil, func() {}
	}
	t := time.NewTimer(time.Until(when))
	return t.C, func() { t.Stop() }
}
func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		if p.ctx.Err() != nil {
			return 0, nil, net.ErrClosed
		}
		when, changed := p.deadline(true)
		if !when.IsZero() && !when.After(time.Now()) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timeout, stop := timer(when)
		select {
		case <-p.ctx.Done():
			stop()
			return 0, nil, net.ErrClosed
		case <-changed:
			stop()
			continue
		case <-timeout:
			stop()
			return 0, nil, os.ErrDeadlineExceeded
		case v, ok := <-p.incoming:
			stop()
			if !ok {
				return 0, nil, io.EOF
			}
			if p.ctx.Err() != nil {
				return 0, nil, net.ErrClosed
			}
			if v.err != nil {
				return 0, nil, v.err
			}
			return copy(b, v.data), v.addr, nil
		}
	}
}
func (p *PacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	if len(b) > 65535 || a == nil {
		return 0, io.ErrShortBuffer
	}
	w := packetWrite{data: append([]byte(nil), b...), addr: packetAddress{a.Network(), a.String()}, reply: make(chan error, 1)}
	queued := false
	for {
		if p.ctx.Err() != nil {
			return 0, net.ErrClosed
		}
		when, changed := p.deadline(false)
		if !when.IsZero() && !when.After(time.Now()) {
			if queued {
				p.Close()
			}
			return 0, os.ErrDeadlineExceeded
		}
		timeout, stop := timer(when)
		var send chan packetWrite
		var reply <-chan error
		if queued {
			reply = w.reply
		} else {
			send = p.outgoing
		}
		select {
		case <-p.ctx.Done():
			stop()
			return 0, net.ErrClosed
		case <-changed:
			stop()
			continue
		case <-timeout:
			stop()
			if queued {
				p.Close()
			}
			return 0, os.ErrDeadlineExceeded
		case send <- w:
			stop()
			queued = true
		case e := <-reply:
			stop()
			if e != nil {
				return 0, e
			}
			if p.ctx.Err() != nil {
				return 0, net.ErrClosed
			}
			return len(b), nil
		}
	}
}
func (p *PacketConn) Close() error {
	p.once.Do(func() { p.cancel(); p.closeErr = p.io.Close() })
	return p.closeErr
}
func (p *PacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (p *PacketConn) setDeadline(t time.Time, read, write bool) error {
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if read {
		close(p.read.changed)
		p.read = packetDeadline{t, make(chan struct{})}
	}
	if write {
		close(p.write.changed)
		p.write = packetDeadline{t, make(chan struct{})}
	}
	return nil
}
func (p *PacketConn) SetDeadline(t time.Time) error      { return p.setDeadline(t, true, true) }
func (p *PacketConn) SetReadDeadline(t time.Time) error  { return p.setDeadline(t, true, false) }
func (p *PacketConn) SetWriteDeadline(t time.Time) error { return p.setDeadline(t, false, true) }

// Freeze the destination before enqueueing; callers may reuse a UDPAddr.
type packetAddress struct{ network, address string }

func (a packetAddress) Network() string { return a.network }
func (a packetAddress) String() string  { return a.address }
