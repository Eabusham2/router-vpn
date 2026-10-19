package pionnet

import (
	"context"
	"errors"
	"github.com/pion/transport/v4"
	"net"
	"net/netip"
	"strings"
)

type packet struct {
	net.PacketConn
	local  *net.UDPAddr
	remote *net.UDPAddr
}

func (n *Network) ListenPacket(network, address string) (net.PacketConn, error) {
	local, err := n.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	return n.listenUDP(n.ctx, network, local)
}
func (n *Network) ListenUDP(network string, local *net.UDPAddr) (transportPacket, error) {
	return n.listenUDP(n.ctx, network, local)
}

// This alias documents the complete typed interface without exposing a raw
// UDP socket or its SyscallConn outside the captured network owner.
type transportPacket = transport.UDPConn

func (n *Network) listenUDP(ctx context.Context, network string, local *net.UDPAddr) (transportPacket, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, ErrUnsupported
	}
	if err := n.active(); err != nil {
		return nil, err
	}
	if local == nil {
		local = &net.UDPAddr{}
	}
	if local.Port < 0 || local.Port > 65535 {
		return nil, ErrUnsupported
	}
	// The native packet callback chooses the real protected/detoured socket.
	// It is not a source-port binding API; never pretend it honored a fixed port.
	if local.Port != 0 {
		return nil, ErrUnsupported
	}
	ip := local.IP
	if len(ip) == 0 {
		if strings.HasSuffix(network, "6") {
			ip = net.IPv6unspecified
		} else {
			ip = net.IPv4zero
		}
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, ErrUnsupported
	}
	address = address.Unmap().WithZone(local.Zone)
	if (network == "udp4" && !address.Is4()) || (network == "udp6" && !address.Is6()) {
		return nil, ErrUnsupported
	}
	connection, err := n.packets.ListenPacket(ctx, network, net.JoinHostPort(address.String(), "0"))
	if err != nil {
		return nil, err
	}
	actual, err := literalUDP(connection.LocalAddr())
	if err != nil {
		connection.Close()
		return nil, errors.New("captured Snowflake UDP socket has no literal local address")
	}
	if !ip.IsUnspecified() && !actual.IP.Equal(ip) {
		connection.Close()
		return nil, errors.New("captured Snowflake UDP socket cannot honor the requested source address")
	}
	return &packet{PacketConn: connection, local: actual}, nil
}

func (n *Network) DialUDP(network string, local, remote *net.UDPAddr) (transportPacket, error) {
	return n.dialUDP(n.ctx, network, local, remote)
}
func (n *Network) dialUDP(ctx context.Context, network string, local, remote *net.UDPAddr) (transportPacket, error) {
	if remote == nil {
		return nil, ErrUnsupported
	}
	destination, err := literalUDP(remote)
	if err != nil || destination.Port == 0 {
		return nil, ErrUnsupported
	}
	connection, err := n.listenUDP(ctx, network, local)
	if err != nil {
		return nil, err
	}
	result := connection.(*packet)
	result.remote = destination
	return result, nil
}

func literalUDP(address net.Addr) (*net.UDPAddr, error) {
	if address == nil {
		return nil, ErrUnsupported
	}
	parsed, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return nil, ErrUnsupported
	}
	ip := parsed.Addr().Unmap()
	return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(parsed.Port()), Zone: ip.Zone()}, nil
}
func copyUDP(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}
func (p *packet) LocalAddr() net.Addr { return copyUDP(p.local) }
func (p *packet) RemoteAddr() net.Addr {
	if p.remote == nil {
		return nil
	}
	return copyUDP(p.remote)
}
func (p *packet) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		count, source, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			return count, source, err
		}
		address, err := literalUDP(source)
		if err != nil {
			return 0, nil, err
		}
		if p.remote != nil && (!address.IP.Equal(p.remote.IP) || address.Port != p.remote.Port || address.Zone != p.remote.Zone) {
			continue
		}
		return count, address, nil
	}
}
func (p *packet) Read(b []byte) (int, error) { count, _, err := p.ReadFrom(b); return count, err }
func (p *packet) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	count, source, err := p.ReadFrom(b)
	if source == nil {
		return count, nil, err
	}
	address, addressErr := literalUDP(source)
	if err == nil {
		err = addressErr
	}
	return count, address, err
}
func (p *packet) Write(b []byte) (int, error) {
	if p.remote == nil {
		return 0, errors.New("captured Snowflake UDP socket is not connected")
	}
	return p.PacketConn.WriteTo(b, p.remote)
}
func (p *packet) WriteTo(b []byte, destination net.Addr) (int, error) {
	if p.remote != nil {
		return 0, errors.New("captured connected UDP socket cannot write to another destination")
	}
	address, err := literalUDP(destination)
	if err != nil || address.Port == 0 || address.IP.IsUnspecified() || address.IP.IsMulticast() {
		return 0, ErrUnsupported
	}
	return p.PacketConn.WriteTo(b, address)
}
func (p *packet) WriteToUDP(b []byte, destination *net.UDPAddr) (int, error) {
	if destination == nil {
		return 0, ErrUnsupported
	}
	return p.WriteTo(b, destination)
}
func (p *packet) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	if len(oob) > 0 {
		return 0, 0, 0, nil, ErrUnsupported
	}
	count, address, err := p.ReadFromUDP(b)
	return count, 0, 0, address, err
}
func (p *packet) WriteMsgUDP(b, oob []byte, address *net.UDPAddr) (int, int, error) {
	if len(oob) > 0 {
		return 0, 0, ErrUnsupported
	}
	if p.remote != nil {
		if address != nil {
			return 0, 0, ErrUnsupported
		}
		count, err := p.Write(b)
		return count, 0, err
	}
	count, err := p.WriteToUDP(b, address)
	return count, 0, err
}
func (*packet) SetReadBuffer(int) error  { return ErrUnsupported }
func (*packet) SetWriteBuffer(int) error { return ErrUnsupported }
