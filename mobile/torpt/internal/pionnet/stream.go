package pionnet

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/pion/transport/v4"
)

func (n *Network) Dial(network, address string) (net.Conn, error) {
	return n.dial(n.ctx, network, address)
}

// DialContext is also used by the broker, keeping its DNS and TCP socket in
// this same session owner instead of allowing an HTTP default dial path.
func (n *Network) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, ErrUnsupported
	}
	return n.dial(ctx, network, address)
}
func (n *Network) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "udp" || network == "udp4" || network == "udp6" {
		remote, err := n.ResolveUDPAddrContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		connection, err := n.dialUDP(ctx, network, nil, remote)
		if err != nil {
			return nil, err
		}
		return connection, nil
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrUnsupported
	}
	remote, err := n.resolveTCPAddrContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if remote.Port == 0 || remote.IP.IsUnspecified() || remote.IP.IsMulticast() {
		return nil, ErrUnsupported
	}
	return n.packets.DialContext(ctx, network, remote.String())
}
func (n *Network) DialTCP(network string, local, remote *net.TCPAddr) (transport.TCPConn, error) {
	if remote == nil || (local != nil && (local.Port != 0 || (len(local.IP) > 0 && !local.IP.IsUnspecified()))) {
		return nil, ErrUnsupported
	}
	conn, err := n.dial(n.ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	return &stream{Conn: conn}, nil
}
func (*Network) ListenTCP(string, *net.TCPAddr) (transport.TCPListener, error) {
	return nil, ErrUnsupported
}

type stream struct{ net.Conn }

func (*stream) CloseRead() error                           { return ErrUnsupported }
func (*stream) CloseWrite() error                          { return ErrUnsupported }
func (s *stream) ReadFrom(reader io.Reader) (int64, error) { return io.Copy(s.Conn, reader) }
func (*stream) SetLinger(int) error                        { return ErrUnsupported }
func (*stream) SetKeepAlive(bool) error                    { return ErrUnsupported }
func (*stream) SetKeepAlivePeriod(time.Duration) error     { return ErrUnsupported }
func (*stream) SetNoDelay(bool) error                      { return ErrUnsupported }
func (*stream) SetWriteBuffer(int) error                   { return ErrUnsupported }
func (*stream) SetReadBuffer(int) error                    { return ErrUnsupported }

type ownedDialer struct {
	owner    *Network
	timeout  time.Duration
	deadline time.Time
	invalid  bool
}

func (n *Network) CreateDialer(input *net.Dialer) transport.Dialer {
	d := &ownedDialer{owner: n}
	if input != nil {
		d.timeout = input.Timeout
		d.deadline = input.Deadline
		d.invalid = input.LocalAddr != nil || input.Resolver != nil || input.Control != nil || input.ControlContext != nil || input.Cancel != nil || input.DualStack || input.FallbackDelay != 0 || input.KeepAlive != 0 || input.KeepAliveConfig != (net.KeepAliveConfig{}) || input.MultipathTCP()
	}
	return d
}
func (d *ownedDialer) Dial(network, address string) (net.Conn, error) {
	if d.invalid {
		return nil, ErrUnsupported
	}
	ctx := d.owner.ctx
	deadline := d.deadline
	if d.timeout > 0 {
		timeout := time.Now().Add(d.timeout)
		if deadline.IsZero() || timeout.Before(deadline) {
			deadline = timeout
		}
	}
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	return d.owner.dial(ctx, network, address)
}

type ownedListenConfig struct {
	owner   *Network
	invalid bool
}

func (n *Network) CreateListenConfig(input *net.ListenConfig) transport.ListenConfig {
	invalid := input != nil && (input.Control != nil || input.KeepAlive != 0 || input.KeepAliveConfig != (net.KeepAliveConfig{}) || input.MultipathTCP())
	return &ownedListenConfig{owner: n, invalid: invalid}
}
func (*ownedListenConfig) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, ErrUnsupported
}
func (c *ownedListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if c.invalid || ctx == nil {
		return nil, ErrUnsupported
	}
	local, err := c.owner.ResolveUDPAddrContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return c.owner.listenUDP(ctx, network, local)
}
