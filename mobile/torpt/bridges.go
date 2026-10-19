// Package torpt embeds bridge transports in the existing mobile Go runtime.
// Its loopback SOCKS listeners accept only the frozen Tor bridge plan. All
// external sockets belong to the captured VPN network owner.
package torpt

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

// Bridges owns one session's PT listeners, accepted Tor connections, transport
// workers, pending protected dials, and TCP/UDP sockets. Close is retryable: a
// canceled wait never releases an unfinished worker into another session.
type Bridges struct {
	ctx        context.Context
	cancel     context.CancelFunc
	network    *mobiletor.Network
	plan       mobiletor.Plan
	transports map[string]clientTransport
	listeners  map[string]net.Listener
	mu         sync.Mutex
	closing    bool
	locals     map[*localConn]struct{}
	failure    error
	workers    sync.WaitGroup
	stopping   chan struct{}
	done       chan struct{}
	parentStop func() bool
}

type clientTransport interface {
	Dial(context.Context, mobiletor.Bridge, *mobiletor.Network) (net.Conn, error)
}

// Start never starts Tor, opens another VPN, downloads bridges, or resolves a
// destination on the default host network. The dial/listen callbacks must be
// captured from the current VPN owner or the final multihop predecessor.
func Start(ctx context.Context, plan mobiletor.Plan, dial mobiletor.DialContext, listen mobiletor.ListenPacket) (*Bridges, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("native Tor bridge session has no active context")
	}
	lines := make([]string, len(plan.Bridges))
	for i, bridge := range plan.Bridges {
		lines[i] = bridge.Line
	}
	verified, err := mobiletor.NewPlan(common.ExternalTorBridgeConfig{Transport: "custom", Bridges: lines})
	if err != nil {
		return nil, errors.New("native Tor bridge plan is invalid")
	}
	transports := make(map[string]clientTransport)
	for _, name := range verified.Transports() {
		transport, err := newClientTransport(name)
		if err != nil {
			return nil, err
		}
		transports[name] = transport
	}
	lifetime, cancel := context.WithCancel(ctx)
	network, err := mobiletor.NewNetwork(lifetime, dial, listen)
	if err != nil {
		cancel()
		return nil, err
	}
	b := &Bridges{ctx: lifetime, cancel: cancel, network: network, plan: verified,
		transports: transports, listeners: make(map[string]net.Listener), locals: make(map[*localConn]struct{}),
		stopping: make(chan struct{}), done: make(chan struct{})}
	for _, name := range verified.Transports() {
		// This is the private IPC endpoint Tor connects to. Only outgoing PT
		// operations use the protected/detoured VPN network.
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			for _, existing := range b.listeners {
				existing.Close()
			}
			cancel()
			network.Close(context.Background())
			return nil, errors.New("native Tor bridge listener could not open")
		}
		b.listeners[name] = listener
	}
	// Count every accept loop before any close callback can start waiting.
	b.workers.Add(len(b.listeners))
	for name, listener := range b.listeners {
		go b.accept(name, listener)
	}
	b.parentStop = context.AfterFunc(ctx, b.beginClose)
	return b, nil
}

// Listeners returns a copy suitable for mobiletor.Control.Configure. It never
// grants general proxy access: the incoming target and every argument must
// match a bridge in this session's validated snapshot.
func (b *Bridges) Listeners() map[string]string {
	result := make(map[string]string, len(b.listeners))
	for name, listener := range b.listeners {
		result[name] = listener.Addr().String()
	}
	return result
}

// Stopping closes as soon as cancellation or a fatal listener failure freezes
// the session. Done closes only after every transport worker and socket drains.
func (b *Bridges) Stopping() <-chan struct{} { return b.stopping }
func (b *Bridges) Done() <-chan struct{}     { return b.done }

func (b *Bridges) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failure
}

func (b *Bridges) fail(err error) {
	b.mu.Lock()
	b.failure = errors.Join(b.failure, err)
	b.mu.Unlock()
	b.beginClose()
}

func (b *Bridges) accept(name string, listener net.Listener) {
	defer b.workers.Done()
	socks := pt.NewSocksListener(&ownedListener{Listener: listener, bridges: b})
	for {
		connection, err := socks.AcceptSocks()
		if err != nil {
			b.mu.Lock()
			closing := b.closing
			b.mu.Unlock()
			if !closing {
				b.fail(errors.New("native Tor bridge listener stopped unexpectedly"))
			}
			return
		}
		b.workers.Add(1) // The counted accept loop prevents a zero-count race.
		go func() {
			defer b.workers.Done()
			b.serve(name, connection)
		}()
	}
}

func (b *Bridges) match(name string, request pt.SocksRequest) (mobiletor.Bridge, bool) {
	target, err := netip.ParseAddrPort(request.Target)
	if err != nil {
		return mobiletor.Bridge{}, false
	}
	for _, bridge := range b.plan.Bridges {
		address, _ := netip.ParseAddrPort(bridge.Target)
		if name != bridge.Transport || target.Addr().Unmap() != address.Addr().Unmap() || target.Port() != address.Port() || len(request.Args) != len(bridge.Arguments) {
			continue
		}
		equal := true
		for key, value := range bridge.Arguments {
			values := request.Args[key]
			if len(values) != 1 || values[0] != value {
				equal = false
				break
			}
		}
		if equal {
			return bridge, true
		}
	}
	return mobiletor.Bridge{}, false
}

func (b *Bridges) serve(name string, local *pt.SocksConn) {
	defer local.Close()
	bridge, ok := b.match(name, local.Req)
	if !ok {
		local.RejectReason(pt.SocksRepConnectionNotAllowed)
		return
	}
	ctx, cancel := context.WithCancel(b.ctx)
	defer cancel()
	var packets mobiletor.ListenPacket
	if b.network.HasPackets() {
		packets = b.network.ListenPacket
	}
	lower, err := mobiletor.NewNetwork(ctx, b.network.DialContext, packets)
	if err != nil {
		local.Reject()
		return
	}
	defer func() {
		cancel()
		// A transport that ignores cancellation remains owned here. A caller's
		// bounded Bridges.Close wait can expire, but cannot declare it drained.
		if err := lower.Close(context.Background()); err != nil {
			b.fail(errors.New("native Tor bridge transport did not close cleanly"))
		}
	}()
	// Factories without a context-taking handshake are interrupted by closing
	// their captured sockets. Stop the timer before admitting application data.
	handshake := time.AfterFunc(30*time.Second, cancel)
	remote, err := b.transports[name].Dial(ctx, bridge, lower)
	timely := handshake.Stop()
	if err != nil || remote == nil || !timely || ctx.Err() != nil {
		cancel()
		if remote != nil {
			remote.Close()
		}
		local.Reject()
		return
	}
	defer func() { cancel(); remote.Close() }()
	if err := local.Grant(nil); err != nil {
		return
	}
	finished := make(chan struct{}, 1)
	go func() {
		io.Copy(remote, local)
		cancel()
		local.Close()
		finished <- struct{}{}
	}()
	io.Copy(local, remote)
	cancel()
	local.Close()
	// Closing the protected sockets interrupts the opposite direction. Both
	// pumps finish before this worker can leave the session's close barrier.
	remote.Close()
	<-finished
}

func (b *Bridges) beginClose() {
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return
	}
	b.closing = true
	close(b.stopping)
	locals := make([]*localConn, 0, len(b.locals))
	for local := range b.locals {
		locals = append(locals, local)
	}
	b.mu.Unlock()
	b.cancel()
	for _, listener := range b.listeners {
		listener.Close()
	}
	for _, local := range locals {
		local.Close()
	}
	go func() {
		if err := b.network.Close(context.Background()); err != nil {
			b.mu.Lock()
			b.failure = errors.Join(b.failure, errors.New("native Tor bridge network close failed"))
			b.mu.Unlock()
		}
		b.workers.Wait()
		close(b.done)
	}()
}

func (b *Bridges) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("native Tor bridge close context is missing")
	}
	b.beginClose()
	b.parentStop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.done:
		return b.Err()
	}
}

type ownedListener struct {
	net.Listener
	bridges *Bridges
}

func (l *ownedListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		local := &localConn{Conn: connection, bridges: l.bridges}
		l.bridges.mu.Lock()
		closing := l.bridges.closing
		accepted := !closing && len(l.bridges.locals) < 64
		if accepted {
			l.bridges.locals[local] = struct{}{}
		}
		l.bridges.mu.Unlock()
		if accepted {
			return local, nil
		}
		connection.Close()
		if closing {
			return nil, net.ErrClosed
		}
	}
}

type localConn struct {
	net.Conn
	bridges *Bridges
	once    sync.Once
	err     error
}

func (c *localConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.bridges.mu.Lock()
		delete(c.bridges.locals, c)
		c.bridges.mu.Unlock()
	})
	return c.err
}
