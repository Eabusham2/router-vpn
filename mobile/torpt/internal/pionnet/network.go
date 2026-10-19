// Package pionnet binds Pion's network interface to one captured VPN owner.
// It never embeds stdnet or creates a physical dialer, resolver, or socket.
package pionnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/pion/transport/v4"
	"router-vpn/internal/mobiletor"
)

type Resolve func(context.Context, string, string) ([]netip.Addr, error)

type Network struct {
	ctx        context.Context
	cancel     context.CancelFunc
	packets    *mobiletor.Network
	resolve    Resolve
	interfaces []*transport.Interface
	mu         sync.Mutex
	closing    bool
	lookups    int
	pending    sync.WaitGroup
	done       chan struct{}
	failure    error
	parentStop func() bool
}

var ErrUnsupported = errors.New("operation is not supported by the captured Snowflake network")

var _ transport.Net = (*Network)(nil)

// New captures a separate child owner for this Snowflake connection. Interface
// data is a copied snapshot supplied by the native VPN network manager, never
// an implicit read of the process's default interfaces.
func New(ctx context.Context, lower *mobiletor.Network, resolve Resolve, interfaces []*transport.Interface) (*Network, error) {
	if ctx == nil || ctx.Err() != nil || lower == nil || !lower.HasPackets() || resolve == nil || interfaces == nil {
		return nil, errors.New("Snowflake requires captured UDP, DNS, and interface ownership")
	}
	clone, err := cloneInterfaces(interfaces)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	packets, err := mobiletor.NewNetwork(lifetime, lower.DialContext, lower.ListenPacket)
	if err != nil {
		cancel()
		return nil, err
	}
	n := &Network{ctx: lifetime, cancel: cancel, packets: packets, resolve: resolve, interfaces: clone, done: make(chan struct{})}
	n.parentStop = context.AfterFunc(ctx, n.beginClose)
	return n, nil
}

func (n *Network) beginClose() {
	n.mu.Lock()
	if n.closing {
		n.mu.Unlock()
		return
	}
	n.closing = true
	n.cancel()
	n.mu.Unlock()
	go func() {
		err := n.packets.Close(context.Background())
		n.pending.Wait()
		n.mu.Lock()
		n.failure = err
		n.mu.Unlock()
		close(n.done)
	}()
}

// Close can be retried after a bounded wait. An ignored DNS cancellation stays
// counted until its actual callback returns; late answers cannot be adopted.
func (n *Network) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("Snowflake close context is missing")
	}
	n.parentStop()
	n.beginClose()
	select {
	case <-n.done:
		n.mu.Lock()
		defer n.mu.Unlock()
		return n.failure
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *Network) active() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing || n.ctx.Err() != nil {
		return net.ErrClosed
	}
	return nil
}

func (n *Network) lookup(ctx context.Context, network, host string) (netip.Addr, error) {
	if ctx == nil {
		return netip.Addr{}, ErrUnsupported
	}
	if err := n.active(); err != nil {
		return netip.Addr{}, err
	}
	if ctx.Err() != nil {
		return netip.Addr{}, ctx.Err()
	}
	family := "ip"
	switch network {
	case "ip4", "udp4", "tcp4":
		family = "ip4"
	case "ip6", "udp6", "tcp6":
		family = "ip6"
	case "ip", "udp", "tcp":
	default:
		return netip.Addr{}, ErrUnsupported
	}
	if literal, err := netip.ParseAddr(host); err == nil {
		literal = literal.Unmap()
		if (family == "ip4" && !literal.Is4()) || (family == "ip6" && !literal.Is6()) {
			return netip.Addr{}, errors.New("Snowflake address family does not match")
		}
		return literal, nil
	}
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n\x00/:?#@") {
		return netip.Addr{}, errors.New("Snowflake DNS name is invalid")
	}
	n.mu.Lock()
	if n.closing || n.ctx.Err() != nil {
		n.mu.Unlock()
		return netip.Addr{}, net.ErrClosed
	}
	if n.lookups >= 64 {
		n.mu.Unlock()
		return netip.Addr{}, errors.New("Snowflake DNS operation limit reached")
	}
	n.lookups++
	n.pending.Add(1)
	n.mu.Unlock()
	defer func() { n.mu.Lock(); n.lookups--; n.mu.Unlock(); n.pending.Done() }()
	combined, cancel := context.WithCancel(ctx)
	stopped := make(chan struct{})
	stop := context.AfterFunc(n.ctx, func() { cancel(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
		cancel()
	}()
	addresses, err := n.resolve(combined, family, host)
	if n.ctx.Err() != nil {
		return netip.Addr{}, net.ErrClosed
	}
	if ctx.Err() != nil {
		return netip.Addr{}, ctx.Err()
	}
	if err != nil {
		return netip.Addr{}, errors.New("captured Snowflake DNS lookup failed")
	}
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
			continue
		}
		if (family == "ip4" && !address.Is4()) || (family == "ip6" && !address.Is6()) {
			continue
		}
		return address, nil
	}
	return netip.Addr{}, errors.New("captured Snowflake DNS returned no matching address")
}

func (n *Network) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	ip, err := n.lookup(n.ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &net.IPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()}, nil
}

func (n *Network) resolveAddress(ctx context.Context, network, address string) (netip.Addr, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, 0, errors.New("Snowflake endpoint is invalid")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 0 || value > 65535 {
		return netip.Addr{}, 0, errors.New("Snowflake endpoint port is invalid")
	}
	if host == "" {
		if strings.HasSuffix(network, "6") {
			host = "::"
		} else {
			host = "0.0.0.0"
		}
	}
	ip, err := n.lookup(ctx, network, host)
	return ip, value, err
}
func (n *Network) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return n.ResolveUDPAddrContext(n.ctx, network, address)
}
func (n *Network) ResolveUDPAddrContext(ctx context.Context, network, address string) (*net.UDPAddr, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, ErrUnsupported
	}
	ip, port, err := n.resolveAddress(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: port, Zone: ip.Zone()}, nil
}
func (n *Network) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return n.resolveTCPAddrContext(n.ctx, network, address)
}
func (n *Network) resolveTCPAddrContext(ctx context.Context, network, address string) (*net.TCPAddr, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrUnsupported
	}
	ip, port, err := n.resolveAddress(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: net.IP(ip.AsSlice()), Port: port, Zone: ip.Zone()}, nil
}

func cloneInterfaces(input []*transport.Interface) ([]*transport.Interface, error) {
	if len(input) > 128 {
		return nil, errors.New("Snowflake interface snapshot is too large")
	}
	result := make([]*transport.Interface, 0, len(input))
	for _, iface := range input {
		if iface == nil {
			return nil, errors.New("Snowflake interface snapshot contains no interface")
		}
		original := iface.Interface
		original.HardwareAddr = append(net.HardwareAddr(nil), original.HardwareAddr...)
		copy := transport.NewInterface(original)
		addresses, err := iface.Addrs()
		if err != nil && !errors.Is(err, transport.ErrNoAddressAssigned) {
			return nil, errors.New("Snowflake interface addresses are missing")
		}
		if len(addresses) > 128 {
			return nil, errors.New("Snowflake interface address snapshot is too large")
		}
		for _, address := range addresses {
			switch address := address.(type) {
			case *net.IPNet:
				if address == nil {
					return nil, ErrUnsupported
				}
				copy.AddAddress(&net.IPNet{IP: append(net.IP(nil), address.IP...), Mask: append(net.IPMask(nil), address.Mask...)})
			case *net.IPAddr:
				if address == nil {
					return nil, ErrUnsupported
				}
				copy.AddAddress(&net.IPAddr{IP: append(net.IP(nil), address.IP...), Zone: address.Zone})
			default:
				return nil, ErrUnsupported
			}
		}
		result = append(result, copy)
	}
	return result, nil
}

// CaptureInterfaces freezes bridge-session input before any Tor SOCKS client
// can connect. Each individual Snowflake owner takes its own copy again.
func CaptureInterfaces(input []*transport.Interface) ([]*transport.Interface, error) {
	if input == nil {
		return nil, errors.New("captured Snowflake interface snapshot is missing")
	}
	return cloneInterfaces(input)
}
func (n *Network) Interfaces() ([]*transport.Interface, error) {
	if err := n.active(); err != nil {
		return nil, err
	}
	return cloneInterfaces(n.interfaces)
}
func (n *Network) InterfaceByIndex(index int) (*transport.Interface, error) {
	interfaces, err := n.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if iface.Index == index {
			return iface, nil
		}
	}
	return nil, transport.ErrInterfaceNotFound
}
func (n *Network) InterfaceByName(name string) (*transport.Interface, error) {
	interfaces, err := n.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return iface, nil
		}
	}
	return nil, transport.ErrInterfaceNotFound
}
