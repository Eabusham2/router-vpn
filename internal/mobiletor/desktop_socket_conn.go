package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

func (s *desktopSocket) allowed(remote netip.AddrPort) bool {
	if !s.live() {
		return false
	}
	s.mu.Lock()
	peer := s.peers[remote]
	s.mu.Unlock()
	return peer != nil && peer.live(time.Now())
}

func (s *desktopSocket) leaseDeadline() time.Time {
	s.mu.Lock()
	peers := make([]*desktopSocketPeer, 0, len(s.peers))
	for _, peer := range s.peers {
		peers = append(peers, peer)
	}
	s.mu.Unlock()
	var result time.Time
	for _, peer := range peers {
		receipt, valid := peer.snapshot()
		if !valid {
			continue
		}
		until := time.UnixMilli(min(receipt.ExpiresAt, receipt.ObservedAt+DesktopSocketReadbackAge.Milliseconds()))
		if result.IsZero() || until.Before(result) {
			result = until
		}
	}
	return result
}

func desktopSocketDeadline(user, lease time.Time) time.Time {
	if user.IsZero() || (!lease.IsZero() && lease.Before(user)) {
		return lease
	}
	return user
}

func (s *desktopSocket) updateDeadlines() {
	lease := s.leaseDeadline()
	s.mu.Lock()
	defer s.mu.Unlock()
	read, write := desktopSocketDeadline(s.readUntil, lease), desktopSocketDeadline(s.writeUntil, lease)
	if s.closing {
		read, write = time.Now(), time.Now()
	}
	if s.conn != nil {
		_ = s.conn.SetReadDeadline(read)
		_ = s.conn.SetWriteDeadline(write)
	}
	if s.packet != nil {
		_ = s.packet.SetReadDeadline(read)
		_ = s.packet.SetWriteDeadline(write)
	}
}

func (s *desktopSocket) deadline(value time.Time, read, write bool) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if read {
		s.readUntil = value
	}
	if write {
		s.writeUntil = value
	}
	s.mu.Unlock()
	s.updateDeadlines()
	if !s.live() {
		return net.ErrClosed
	}
	return nil
}

func (s *desktopSocket) beginIO() error {
	if !s.broker.Current() {
		s.stop()
		return net.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return net.ErrClosed
	}
	s.io.Add(1)
	return nil
}

func (s *desktopSocket) close() error { s.stop(); <-s.done; return nil }

type desktopSocketConn struct{ socket *desktopSocket }

func (c *desktopSocketConn) Read(data []byte) (int, error) {
	s := c.socket
	if !s.allowed(s.remote) {
		s.stop()
		return 0, net.ErrClosed
	}
	if err := s.beginIO(); err != nil {
		return 0, err
	}
	defer s.io.Done()
	n, err := s.conn.Read(data)
	if !s.allowed(s.remote) {
		s.stop()
		return n, errors.Join(err, net.ErrClosed)
	}
	return n, err
}

func (c *desktopSocketConn) Write(data []byte) (int, error) {
	s := c.socket
	if !s.allowed(s.remote) {
		s.stop()
		return 0, net.ErrClosed
	}
	if err := s.beginIO(); err != nil {
		return 0, err
	}
	defer s.io.Done()
	n, err := s.conn.Write(data)
	if !s.allowed(s.remote) {
		s.stop()
		return n, errors.Join(err, net.ErrClosed)
	}
	return n, err
}

func (c *desktopSocketConn) Close() error                  { return c.socket.close() }
func (c *desktopSocketConn) LocalAddr() net.Addr           { return net.TCPAddrFromAddrPort(c.socket.local) }
func (c *desktopSocketConn) RemoteAddr() net.Addr          { return net.TCPAddrFromAddrPort(c.socket.remote) }
func (c *desktopSocketConn) SetDeadline(t time.Time) error { return c.socket.deadline(t, true, true) }
func (c *desktopSocketConn) SetReadDeadline(t time.Time) error {
	return c.socket.deadline(t, true, false)
}
func (c *desktopSocketConn) SetWriteDeadline(t time.Time) error {
	return c.socket.deadline(t, false, true)
}

type desktopSocketPacket struct {
	socket    *desktopSocket
	connected bool
}

func (p *desktopSocketPacket) ReadFrom(data []byte) (int, net.Addr, error) {
	s := p.socket
	if err := s.beginIO(); err != nil {
		return 0, nil, err
	}
	defer s.io.Done()
	// Never put an ungranted peer's datagram in application-owned memory.
	buffer := make([]byte, min(len(data), 65535))
	for discarded := 0; discarded < DesktopSocketPeerLimit; discarded++ {
		n, address, err := s.packet.ReadFrom(buffer)
		if err != nil {
			return 0, nil, err
		}
		remote, parseErr := netip.ParseAddrPort(address.String())
		if parseErr == nil && s.allowed(remote) && (!p.connected || remote == s.remote) {
			if !s.live() {
				return 0, nil, net.ErrClosed
			}
			return copy(data, buffer[:n]), net.UDPAddrFromAddrPort(remote), nil
		}
		if !s.live() {
			return 0, nil, net.ErrClosed
		}
	}
	return 0, nil, errors.New("desktop physical socket rejected ungranted UDP peers")
}

func (p *desktopSocketPacket) WriteTo(data []byte, address net.Addr) (int, error) {
	if address == nil || address.Network() != "udp" || len(data) > 65507 {
		return 0, errors.New("desktop physical UDP requires a bounded datagram and numeric peer")
	}
	_, remote, err := desktopSocketDestination("udp", address.String())
	if err != nil || (p.connected && remote != p.socket.remote) {
		return 0, errors.New("desktop physical UDP peer changed")
	}
	s := p.socket
	if err := s.beginIO(); err != nil {
		return 0, err
	}
	defer s.io.Done()
	// A per-peer grant is established before the first byte, including STUN,
	// ICE and a new Snowflake peer on an already retained UDP socket.
	if _, err := s.permit(s.ctx, remote); err != nil {
		return 0, err
	}
	if !s.allowed(remote) {
		s.stop()
		return 0, net.ErrClosed
	}
	n, err := s.packet.WriteTo(data, net.UDPAddrFromAddrPort(remote))
	if !s.allowed(remote) {
		s.stop()
		return n, errors.Join(err, net.ErrClosed)
	}
	return n, err
}

func (p *desktopSocketPacket) Close() error                  { return p.socket.close() }
func (p *desktopSocketPacket) LocalAddr() net.Addr           { return net.UDPAddrFromAddrPort(p.socket.local) }
func (p *desktopSocketPacket) SetDeadline(t time.Time) error { return p.socket.deadline(t, true, true) }
func (p *desktopSocketPacket) SetReadDeadline(t time.Time) error {
	return p.socket.deadline(t, true, false)
}
func (p *desktopSocketPacket) SetWriteDeadline(t time.Time) error {
	return p.socket.deadline(t, false, true)
}

type desktopConnectedPacket struct {
	packet *desktopSocketPacket
	remote *net.UDPAddr
}

func (c *desktopConnectedPacket) Read(p []byte) (int, error) {
	n, _, err := c.packet.ReadFrom(p)
	return n, err
}
func (c *desktopConnectedPacket) Write(p []byte) (int, error)   { return c.packet.WriteTo(p, c.remote) }
func (c *desktopConnectedPacket) Close() error                  { return c.packet.Close() }
func (c *desktopConnectedPacket) LocalAddr() net.Addr           { return c.packet.LocalAddr() }
func (c *desktopConnectedPacket) RemoteAddr() net.Addr          { return c.remote }
func (c *desktopConnectedPacket) SetDeadline(t time.Time) error { return c.packet.SetDeadline(t) }
func (c *desktopConnectedPacket) SetReadDeadline(t time.Time) error {
	return c.packet.SetReadDeadline(t)
}
func (c *desktopConnectedPacket) SetWriteDeadline(t time.Time) error {
	return c.packet.SetWriteDeadline(t)
}

// Cancel has a synchronous admission effect; Close is the separately bounded
// acknowledgment that both policy removal and all actual socket work joined.
var _ interface{ Close(context.Context) error } = (*DesktopSocketBroker)(nil)
