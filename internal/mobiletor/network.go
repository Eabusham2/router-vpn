package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

type ListenPacket func(context.Context, string, string) (net.PacketConn, error)

// Network owns the captured lower transport of one VPN session. There is no
// default physical dialer or resolver fallback: callers must supply the actual
// VPN owner's protected TCP and (where supported) packet operations.
// Closing waits for pending operations and every adopted socket to finish; an
// expired wait leaves ownership intact and can be retried. A late dial cannot
// recreate a socket in a subsequent session.
type Network struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dial       DialContext
	listen     ListenPacket
	mu         sync.Mutex
	closing    bool
	count      int
	sockets    map[*socketOwner]struct{}
	failure    error
	pending    sync.WaitGroup
	done       chan struct{}
	parentStop func() bool
}

type socketOwner struct {
	network *Network
	socket  io.Closer
	once    sync.Once
	failure error
}

type ownedConn struct {
	net.Conn
	owner *socketOwner
}

func (c *ownedConn) Close() error { return c.owner.Close() }

type ownedPacket struct {
	net.PacketConn
	owner *socketOwner
}

func (c *ownedPacket) Close() error { return c.owner.Close() }

func NewNetwork(ctx context.Context, dial DialContext, listen ListenPacket) (*Network, error) {
	if ctx == nil || dial == nil {
		return nil, errors.New("native Tor requires the captured VPN network dialer")
	}
	lifetime, cancel := context.WithCancel(ctx)
	n := &Network{ctx: lifetime, cancel: cancel, dial: dial, listen: listen, sockets: make(map[*socketOwner]struct{}), done: make(chan struct{})}
	// Install before publishing the owner. The callback does not access the
	// returned stop function, so an already-canceled context is safe.
	n.parentStop = context.AfterFunc(ctx, n.beginClose)
	return n, nil
}

func (n *Network) HasPackets() bool { return n.listen != nil }

func (n *Network) begin() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing || n.ctx.Err() != nil {
		return net.ErrClosed
	}
	if n.count >= 512 {
		return errors.New("native Tor protected socket limit reached")
	}
	n.pending.Add(1)
	n.count++
	return nil
}

func (n *Network) adopt(socket io.Closer) (*socketOwner, error) {
	owner := &socketOwner{network: n, socket: socket}
	n.mu.Lock()
	closing := n.closing || n.ctx.Err() != nil
	if !closing {
		n.sockets[owner] = struct{}{}
	}
	n.mu.Unlock()
	if closing {
		_ = owner.Close()
		return nil, net.ErrClosed
	}
	return owner, nil
}

func (n *Network) operationContext(ctx context.Context) (context.Context, func()) {
	combined, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(n.ctx, cancel)
	return combined, func() { stop(); cancel() }
}

func (n *Network) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("native Tor dial context is missing")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" && network != "udp" && network != "udp4" && network != "udp6" {
		return nil, errors.New("native Tor network only carries TCP or UDP")
	}
	if err := n.begin(); err != nil {
		return nil, err
	}
	combined, cancel := n.operationContext(ctx)
	defer cancel()
	connection, err := n.dial(combined, network, address)
	if err != nil {
		n.discard(connection)
		return nil, err
	}
	if connection == nil {
		n.discard(nil)
		return nil, errors.New("captured Tor dialer returned no socket")
	}
	if err := combined.Err(); err != nil {
		n.discard(connection)
		if n.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		return nil, err
	}
	owner, err := n.adopt(connection)
	if err != nil {
		return nil, err
	}
	return &ownedConn{Conn: connection, owner: owner}, nil
}

func (n *Network) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if ctx == nil || n.listen == nil {
		return nil, errors.New("captured Tor network does not support packets")
	}
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, errors.New("native Tor packet network must be UDP")
	}
	if err := n.begin(); err != nil {
		return nil, err
	}
	combined, cancel := n.operationContext(ctx)
	defer cancel()
	connection, err := n.listen(combined, network, address)
	if err != nil {
		n.discard(connection)
		return nil, err
	}
	if connection == nil {
		n.discard(nil)
		return nil, errors.New("captured Tor packet listener returned no socket")
	}
	if err := combined.Err(); err != nil {
		n.discard(connection)
		if n.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		return nil, err
	}
	owner, err := n.adopt(connection)
	if err != nil {
		return nil, err
	}
	return &ownedPacket{PacketConn: connection, owner: owner}, nil
}

func (owner *socketOwner) Close() error {
	owner.once.Do(func() {
		owner.failure = owner.socket.Close()
		n := owner.network
		n.mu.Lock()
		delete(n.sockets, owner)
		n.count--
		if owner.failure != nil && !errors.Is(owner.failure, net.ErrClosed) && !errors.Is(owner.failure, io.ErrClosedPipe) {
			n.failure = errors.Join(n.failure, errors.New("native Tor protected socket close failed"))
		}
		n.mu.Unlock()
		n.pending.Done()
	})
	return owner.failure
}

func (n *Network) discard(socket io.Closer) {
	if socket != nil {
		_ = (&socketOwner{network: n, socket: socket}).Close()
		return
	}
	n.mu.Lock()
	n.count--
	n.mu.Unlock()
	n.pending.Done()
}

func (n *Network) beginClose() {
	n.mu.Lock()
	if n.closing {
		n.mu.Unlock()
		return
	}
	n.closing = true
	sockets := make([]*socketOwner, 0, len(n.sockets))
	for socket := range n.sockets {
		sockets = append(sockets, socket)
	}
	n.mu.Unlock()
	n.cancel()
	// A slow protocol close must not delay cancellation of another owned
	// socket. Each existing owner remains counted until its Close returns.
	for _, socket := range sockets {
		go func(s *socketOwner) { _ = s.Close() }(socket)
	}
	go func() { n.pending.Wait(); close(n.done) }()
}

func (n *Network) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("native Tor close context is missing")
	}
	n.beginClose()
	n.parentStop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.done:
		n.mu.Lock()
		defer n.mu.Unlock()
		return n.failure
	}
}
