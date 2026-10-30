package mobiletor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	DesktopSocketLimit       = 128
	DesktopSocketPeerLimit   = 32
	DesktopSocketGrantMaxAge = 10 * time.Second
	DesktopSocketReadbackAge = 5 * time.Second
	desktopSocketControlWait = 3 * time.Second
)

// DesktopSocketCapture identifies one immutable native source and one physical
// network generation. Reusing a node name, interface name or executable is not
// a replacement for this captured lifetime.
type DesktopSocketCapture struct {
	SessionID    string
	SourceSHA256 string
	NetworkID    string
}

// DesktopSocketKernelOwner is an independently provisioned OS socket owner.
// IdentitySHA256 covers the platform's retained identity receipt, not a caller
// supplied process path. A shared UID, executable path or tuple alone is not an
// implementation of this contract. The privileged OS adapter must establish
// exclusive ownership and prevent identity reuse until removal and process join.
type DesktopSocketKernelOwner struct {
	Kind           string
	IdentitySHA256 string
	Generation     uint64
	ProcessID      uint32
}

type DesktopSocketBinding struct {
	Owner          DesktopSocketKernelOwner
	InterfaceName  string
	InterfaceIndex uint32
	LocalAddress   netip.Addr
}

// DesktopSocketGrant contains only an actual exclusively bound kernel tuple.
// The remote address is numeric; this layer never performs host DNS. The same
// native selected-DNS transport must use this broker for its own socket too.
type DesktopSocketGrant struct {
	Capture  DesktopSocketCapture
	Binding  DesktopSocketBinding
	SocketID string
	Network  string
	Local    netip.AddrPort
	Remote   netip.AddrPort
	Sequence uint64
}

type DesktopSocketReceipt struct {
	Grant      DesktopSocketGrant
	ObservedAt int64
	ExpiresAt  int64
}

// DesktopSocketPolicy is the privileged, independently owned OS boundary.
// Current must be a bounded memory-only observation. Bind captures/verifies the
// actual raw descriptor and creator identity and applies/read-backs the physical
// interface. Grant must independently prove the actual bound socket's kernel
// owner before installing and reading back the exact owner AND full tuple;
// no Connect or data write is allowed before that acknowledgment. Revoke returns
// only after removal and an independent absent
// readback; an unknown/failed Grant remains revocable by its immutable identity.
// These methods may not resolve names, create a broader permit or release the
// socket. No production policy is manufactured from JSON or stdout receipts.
type DesktopSocketPolicy interface {
	Owner() (DesktopSocketKernelOwner, error)
	Current(DesktopSocketCapture, DesktopSocketKernelOwner) bool
	Select(context.Context, DesktopSocketCapture, string, netip.AddrPort) (DesktopSocketBinding, error)
	Bind(context.Context, DesktopSocketCapture, DesktopSocketBinding, string, syscall.RawConn) error
	Grant(context.Context, DesktopSocketGrant) (DesktopSocketReceipt, error)
	Revoke(context.Context, DesktopSocketGrant) error
}

// Only an in-package native adapter can move the internal control budget past
// its own serialized admission. The original caller still controls cancellation
// and any earlier deadline; waiting never creates or refreshes a receipt.
type desktopSocketAdmittedPolicy interface {
	grantSocketAdmitted(context.Context, DesktopSocketGrant) (DesktopSocketReceipt, error)
	revokeSocketAdmitted(context.Context, DesktopSocketGrant) error
}

// desktopSocketControlMutex preserves FIFO admission without leaving a cancelled
// waiter behind its current owner. Lock is used by memory-only native snapshots;
// request paths use lockContext so they cannot send after their caller retires.
type desktopSocketControlMutex struct {
	mu      sync.Mutex
	held    bool
	waiters []*desktopSocketControlWaiter
}

type desktopSocketControlWaiter struct {
	ready  chan struct{}
	queued bool
	caller context.Context
}

func (m *desktopSocketControlMutex) Lock() { _ = m.lockContext(context.Background()) }

func (m *desktopSocketControlMutex) lockContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("native control admission requires its caller")
	}
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}
	if !m.held {
		m.held = true
		m.mu.Unlock()
		return nil
	}
	waiter := &desktopSocketControlWaiter{ready: make(chan struct{}), queued: true, caller: ctx}
	m.waiters = append(m.waiters, waiter)
	m.mu.Unlock()
	select {
	case <-waiter.ready:
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		m.mu.Lock()
		if waiter.queued {
			for index, candidate := range m.waiters {
				if candidate == waiter {
					copy(m.waiters[index:], m.waiters[index+1:])
					m.waiters[len(m.waiters)-1] = nil
					m.waiters = m.waiters[:len(m.waiters)-1]
					break
				}
			}
			waiter.queued = false
		} else {
			// Handoff won the race with cancellation. Relinquish precisely the
			// admission it granted, rather than leaking or unlocking a successor.
			m.unlockLocked()
		}
		m.mu.Unlock()
		return ctx.Err()
	}
}

func (m *desktopSocketControlMutex) unlockLocked() {
	if !m.held {
		panic("unlock of unowned native control admission")
	}
	if len(m.waiters) == 0 {
		m.held = false
		return
	}
	next := m.waiters[0]
	copy(m.waiters, m.waiters[1:])
	m.waiters[len(m.waiters)-1] = nil
	m.waiters = m.waiters[:len(m.waiters)-1]
	next.queued = false
	close(next.ready)
}

func (m *desktopSocketControlMutex) Unlock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unlockLocked()
}

func desktopSocketGrantControlled(ctx context.Context, policy DesktopSocketPolicy, request DesktopSocketGrant) (DesktopSocketReceipt, error) {
	if admitted, ok := policy.(desktopSocketAdmittedPolicy); ok {
		return admitted.grantSocketAdmitted(ctx, request)
	}
	bounded, cancel := context.WithTimeout(ctx, desktopSocketControlWait)
	defer cancel()
	receipt, err := policy.Grant(bounded, request)
	return receipt, errors.Join(err, bounded.Err())
}

func desktopSocketRevokeControlled(ctx context.Context, policy DesktopSocketPolicy, request DesktopSocketGrant) error {
	if admitted, ok := policy.(desktopSocketAdmittedPolicy); ok {
		return admitted.revokeSocketAdmitted(ctx, request)
	}
	bounded, cancel := context.WithTimeout(ctx, desktopSocketControlWait)
	defer cancel()
	return errors.Join(policy.Revoke(bounded, request), bounded.Err())
}

// DesktopSocketBroker is the socket lifetime used by the native desktop Tor
// lower dialer. Its capability is supplied by a real privileged policy adapter;
// constructing a generic source/tuple record does not enable strict protection.
// Public Direct strict admission stays closed until those adapters are wired.
type DesktopSocketBroker struct {
	ctx        context.Context
	cancel     context.CancelFunc
	capture    DesktopSocketCapture
	owner      DesktopSocketKernelOwner
	policy     DesktopSocketPolicy
	source     DesktopSocketSource
	current    func() bool
	mu         sync.Mutex
	closing    bool
	sockets    map[*desktopSocket]struct{}
	workers    sync.WaitGroup
	joined     chan struct{}
	joinOnce   sync.Once
	monitor    chan struct{}
	parentStop func() bool
}

type desktopSocket struct {
	ctx          context.Context
	cancel       context.CancelFunc
	broker       *DesktopSocketBroker
	id           string
	network      string
	remote       netip.AddrPort
	binding      DesktopSocketBinding
	mu           sync.Mutex
	closing      bool
	conn         net.Conn
	packet       net.PacketConn
	keeper       *desktopSocketKeeper
	sourceFile   *os.File
	sourceNative DesktopSocketNative
	local        netip.AddrPort
	peers        map[netip.AddrPort]*desktopSocketPeer
	operation    chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
	io           sync.WaitGroup
	readUntil    time.Time
	writeUntil   time.Time
	lastFailure  error
}

type desktopSocketPeer struct {
	op       sync.Mutex
	mu       sync.Mutex
	request  DesktopSocketGrant
	receipt  DesktopSocketReceipt
	applying bool
	valid    bool
}

func desktopSocketHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func (c DesktopSocketCapture) valid() bool {
	return desktopSocketHex(c.SessionID, 32) && desktopSocketHex(c.SourceSHA256, 64) && desktopSocketHex(c.NetworkID, 32)
}

func (o DesktopSocketKernelOwner) valid() bool {
	switch o.Kind {
	case "linux-cgroup", "unix-isolated-uid", "windows-isolated-appid", "windows-isolated-token":
	default:
		return false
	}
	return desktopSocketHex(o.IdentitySHA256, 64) && o.Generation != 0 && o.ProcessID != 0
}

func NewDesktopSocketBroker(parent context.Context, capture DesktopSocketCapture, policy DesktopSocketPolicy, current func() bool) (*DesktopSocketBroker, error) {
	if parent == nil || parent.Err() != nil || !capture.valid() || policy == nil || current == nil || !current() {
		return nil, errors.New("desktop physical broker has no live captured native source")
	}
	owner, err := policy.Owner()
	if err != nil || !owner.valid() || !policy.Current(capture, owner) {
		return nil, errors.New("desktop physical broker has no independently captured kernel owner")
	}
	ctx, cancel := context.WithCancel(parent)
	b := &DesktopSocketBroker{ctx: ctx, cancel: cancel, capture: capture, owner: owner, policy: policy, current: current,
		sockets: make(map[*desktopSocket]struct{}), joined: make(chan struct{}), monitor: make(chan struct{})}
	b.source, _ = policy.(DesktopSocketSource)
	b.parentStop = context.AfterFunc(parent, b.Cancel)
	go b.monitorOwned()
	return b, nil
}

func (b *DesktopSocketBroker) Capture() DesktopSocketCapture {
	if b == nil {
		return DesktopSocketCapture{}
	}
	return b.capture
}

func (b *DesktopSocketBroker) Matches(capture DesktopSocketCapture) bool {
	return b != nil && capture == b.capture && b.Current()
}

func (b *DesktopSocketBroker) Current() bool {
	return b != nil && b.ctx.Err() == nil && b.current() && b.policy.Current(b.capture, b.owner)
}

func desktopSocketDestination(network, address string) (string, netip.AddrPort, error) {
	var base string
	switch network {
	case "tcp", "tcp4", "tcp6":
		base = "tcp"
	case "udp", "udp4", "udp6":
		base = "udp"
	default:
		return "", netip.AddrPort{}, errors.New("desktop physical sockets require TCP or UDP")
	}
	remote, err := netip.ParseAddrPort(address)
	if err != nil || !remote.IsValid() || remote.Port() == 0 || remote.Addr().Zone() != "" || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() || remote.Addr().Is4In6() {
		return "", netip.AddrPort{}, errors.New("desktop physical sockets require an exact numeric remote")
	}
	if (network == base+"4" && !remote.Addr().Is4()) || (network == base+"6" && remote.Addr().Is4()) {
		return "", netip.AddrPort{}, errors.New("desktop physical socket address family changed")
	}
	return base, remote, nil
}

func (b *DesktopSocketBroker) begin(ctx context.Context, network string, remote netip.AddrPort) (*desktopSocket, context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil || !b.Current() {
		return nil, nil, nil, net.ErrClosed
	}
	b.mu.Lock()
	if b.closing || b.ctx.Err() != nil || len(b.sockets) >= DesktopSocketLimit {
		b.mu.Unlock()
		return nil, nil, nil, errors.New("desktop physical socket owner is retired or full")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		b.mu.Unlock()
		return nil, nil, nil, err
	}
	socketCtx, socketCancel := context.WithCancel(b.ctx)
	s := &desktopSocket{ctx: socketCtx, cancel: socketCancel, broker: b, id: hex.EncodeToString(nonce[:]), network: network, remote: remote, peers: make(map[netip.AddrPort]*desktopSocketPeer), operation: make(chan struct{}), done: make(chan struct{})}
	b.sockets[s] = struct{}{}
	b.workers.Add(1)
	b.mu.Unlock()
	operation, cancel := context.WithCancel(socketCtx)
	stop := context.AfterFunc(ctx, cancel)
	release := func() { stop(); cancel() }
	return s, operation, release, nil
}

func (s *desktopSocket) prepare(ctx context.Context) error {
	b := s.broker
	binding, err := b.policy.Select(ctx, b.capture, s.network, s.remote)
	if err != nil {
		return err
	}
	if !b.Current() || ctx.Err() != nil || binding.Owner != b.owner || binding.InterfaceIndex == 0 || binding.InterfaceName == "" || len(binding.InterfaceName) > 64 || strings.ContainsAny(binding.InterfaceName, "\x00\r\n") || !binding.LocalAddress.IsValid() || binding.LocalAddress.IsUnspecified() || binding.LocalAddress.IsMulticast() || binding.LocalAddress.Is4In6() || binding.LocalAddress.Zone() != "" || binding.LocalAddress.Is4() != s.remote.Addr().Is4() {
		return errors.New("desktop physical binding lost its exact kernel/interface owner")
	}
	s.binding = binding
	return nil
}

// DialContext opens no host resolver and cannot transmit until its actual bound
// tuple has an acknowledged, matching permit. A duplicate kernel handle keeps
// the port reserved even if net.Dialer closes an unreturned/failed descriptor.
func (b *DesktopSocketBroker) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	base, remote, err := desktopSocketDestination(network, address)
	if err != nil {
		return nil, err
	}
	if base == "udp" {
		packet, err := b.openPacket(ctx, network, remote, true)
		if err != nil {
			return nil, err
		}
		return &desktopConnectedPacket{packet: packet, remote: net.UDPAddrFromAddrPort(remote)}, nil
	}
	s, operation, release, err := b.begin(ctx, base, remote)
	if err != nil {
		return nil, err
	}
	defer release()
	defer b.workers.Done()
	defer close(s.operation)
	failed := true
	defer func() {
		if failed {
			s.stop()
		}
	}()
	if err := s.prepare(operation); err != nil {
		return nil, err
	}
	if err := s.create(operation); err != nil {
		return nil, err
	}
	control := func(controlCtx context.Context, actualNetwork, actualAddress string, raw syscall.RawConn) error {
		if controlCtx.Err() != nil || !b.Current() || actualAddress != remote.String() {
			return net.ErrClosed
		}
		if err := b.policy.Bind(controlCtx, b.capture, s.binding, actualNetwork, raw); err != nil {
			return err
		}
		keeper, local, err := desktopSocketBindTCP(raw, s.binding.LocalAddress)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.keeper, s.local = keeper, local
		s.mu.Unlock()
		_, err = s.permit(controlCtx, remote)
		return err
	}
	var connection net.Conn
	if b.source == nil {
		connection, err = desktopSocketDialTCP(operation, network, remote, control)
	} else if s.sourceNative != nil {
		connection, err = desktopSocketImportNativeTCP(operation, network, remote, s.sourceNative, control)
	} else {
		connection, err = desktopSocketImportTCP(operation, network, remote, s.sourceFile, control)
	}
	s.mu.Lock()
	s.conn = connection
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if connection == nil || operation.Err() != nil || ctx.Err() != nil || !s.allowed(remote) || connection.LocalAddr().String() != s.local.String() || connection.RemoteAddr().String() != remote.String() {
		return nil, net.ErrClosed
	}
	s.updateDeadlines()
	failed = false
	return &desktopSocketConn{socket: s}, nil
}

func (b *DesktopSocketBroker) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	remote, err := netip.ParseAddrPort(address)
	if (network != "udp" && network != "udp4" && network != "udp6") || err != nil || !remote.IsValid() || remote.Addr().Zone() != "" || remote.Addr().IsMulticast() || remote.Addr().Is4In6() || (network == "udp4" && !remote.Addr().Is4()) || (network == "udp6" && remote.Addr().Is4()) || (remote.Addr().IsUnspecified() && remote.Port() != 0) {
		return nil, errors.New("desktop physical packets require a numeric UDP family hint")
	}
	return b.openPacket(ctx, network, remote, false)
}

func (b *DesktopSocketBroker) openPacket(ctx context.Context, network string, remote netip.AddrPort, connected bool) (*desktopSocketPacket, error) {
	s, operation, release, err := b.begin(ctx, "udp", remote)
	if err != nil {
		return nil, err
	}
	defer release()
	defer b.workers.Done()
	defer close(s.operation)
	failed := true
	defer func() {
		if failed {
			s.stop()
		}
	}()
	if err := s.prepare(operation); err != nil {
		return nil, err
	}
	if err := s.create(operation); err != nil {
		return nil, err
	}
	listener := net.ListenConfig{Control: func(actualNetwork, _ string, raw syscall.RawConn) error {
		if operation.Err() != nil || !b.Current() {
			return net.ErrClosed
		}
		if err := b.policy.Bind(operation, b.capture, s.binding, actualNetwork, raw); err != nil {
			return err
		}
		return desktopSocketExclusive(raw)
	}}
	var packet net.PacketConn
	if b.source == nil {
		packet, err = listener.ListenPacket(operation, network, netip.AddrPortFrom(s.binding.LocalAddress, 0).String())
	} else if s.sourceNative != nil {
		packet, err = desktopSocketImportNativePacket(operation, network, s.sourceNative, s.binding.LocalAddress, listener.Control)
	} else {
		packet, err = desktopSocketImportPacket(operation, network, s.sourceFile, s.binding.LocalAddress, listener.Control)
	}
	s.mu.Lock()
	s.packet = packet
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	raw, ok := packet.(syscall.Conn)
	if !ok {
		return nil, errors.New("desktop physical packet socket has no retained kernel handle")
	}
	control, err := raw.SyscallConn()
	if err != nil {
		return nil, err
	}
	keeper, local, err := desktopSocketRetain(control)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.keeper, s.local = keeper, local
	s.mu.Unlock()
	if connected {
		if _, err := s.permit(operation, remote); err != nil {
			return nil, err
		}
	}
	if operation.Err() != nil || ctx.Err() != nil || !s.live() || (connected && !s.allowed(remote)) || local.Addr() != s.binding.LocalAddress || packet.LocalAddr().String() != local.String() {
		return nil, net.ErrClosed
	}
	s.updateDeadlines()
	failed = false
	return &desktopSocketPacket{socket: s, connected: connected}, nil
}

func (s *desktopSocket) live() bool {
	if !s.broker.Current() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closing
}

func validDesktopSocketReceipt(receipt DesktopSocketReceipt, request DesktopSocketGrant, now time.Time) bool {
	return receipt.Grant == request && request.Sequence != 0 && receipt.ObservedAt > 0 && receipt.ObservedAt <= now.UnixMilli() &&
		now.UnixMilli()-receipt.ObservedAt <= DesktopSocketReadbackAge.Milliseconds() && receipt.ExpiresAt > now.UnixMilli() &&
		receipt.ExpiresAt-receipt.ObservedAt <= DesktopSocketGrantMaxAge.Milliseconds()
}

func (s *desktopSocket) permit(ctx context.Context, remote netip.AddrPort) (*desktopSocketPeer, error) {
	if ctx == nil || ctx.Err() != nil || !s.live() {
		return nil, net.ErrClosed
	}
	s.mu.Lock()
	peer := s.peers[remote]
	if peer == nil {
		if len(s.peers) >= DesktopSocketPeerLimit || !s.local.IsValid() || s.local.Port() == 0 || remote.Addr().Is4() != s.local.Addr().Is4() {
			s.mu.Unlock()
			return nil, errors.New("desktop physical UDP peer bound or family rejected")
		}
		peer = &desktopSocketPeer{request: DesktopSocketGrant{Capture: s.broker.capture, Binding: s.binding, SocketID: s.id, Network: s.network, Local: s.local, Remote: remote}}
		s.peers[remote] = peer
	}
	s.mu.Unlock()
	// A renewal owns control serialization, not data admission while the last
	// real readback is still valid. This matters for Snowflake's UDP socket.
	if peer.live(time.Now()) {
		return peer, nil
	}
	peer.op.Lock()
	defer peer.op.Unlock()
	if peer.live(time.Now()) {
		return peer, nil
	}
	if err := s.apply(ctx, peer); err != nil {
		return nil, err
	}
	return peer, nil
}

func (peer *desktopSocketPeer) snapshot() (DesktopSocketReceipt, bool) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	expected := peer.request
	expected.Sequence = peer.receipt.Grant.Sequence
	return peer.receipt, peer.valid && expected.Sequence > 0 && expected.Sequence <= peer.request.Sequence && peer.receipt.Grant == expected
}

func (peer *desktopSocketPeer) live(now time.Time) bool {
	receipt, valid := peer.snapshot()
	return valid && validDesktopSocketReceipt(receipt, receipt.Grant, now)
}

// apply is serialized with both refresh and removal. A late/unknown write is
// never followed by an absent readback until that exact write has completed.
func (s *desktopSocket) apply(ctx context.Context, peer *desktopSocketPeer) error {
	if ctx.Err() != nil || !s.live() {
		return net.ErrClosed
	}
	peer.mu.Lock()
	peer.request.Sequence++
	request := peer.request
	peer.applying = true
	peer.mu.Unlock()
	receipt, err := desktopSocketGrantControlled(ctx, s.broker.policy, request)
	if err != nil || ctx.Err() != nil || !s.live() || !validDesktopSocketReceipt(receipt, request, time.Now()) {
		peer.mu.Lock()
		peer.valid, peer.applying = false, false
		peer.mu.Unlock()
		s.stop()
		return errors.Join(err, errors.New("desktop physical permit has no current complete readback"))
	}
	peer.mu.Lock()
	peer.receipt, peer.valid = receipt, true
	peer.applying = false
	peer.mu.Unlock()
	s.updateDeadlines()
	return nil
}

func (b *DesktopSocketBroker) monitorOwned() {
	defer close(b.monitor)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-tick.C:
		}
		if !b.Current() {
			b.Cancel()
			return
		}
		b.mu.Lock()
		sockets := make([]*desktopSocket, 0, len(b.sockets))
		for s := range b.sockets {
			sockets = append(sockets, s)
		}
		b.mu.Unlock()
		for _, s := range sockets {
			s.refresh()
		}
	}
}

func (s *desktopSocket) refresh() {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	peers := make([]*desktopSocketPeer, 0, len(s.peers))
	for _, peer := range s.peers {
		peers = append(peers, peer)
	}
	s.mu.Unlock()
	for _, peer := range peers {
		// The monitor never waits for a possibly blocked Grant. It needs the
		// last acknowledged receipt independently to interrupt existing I/O.
		receipt, valid := peer.snapshot()
		if !valid {
			continue
		}
		if !validDesktopSocketReceipt(receipt, receipt.Grant, time.Now()) {
			s.stop()
			continue
		}
		peer.mu.Lock()
		freshUntil := min(peer.receipt.ExpiresAt, peer.receipt.ObservedAt+DesktopSocketReadbackAge.Milliseconds())
		if freshUntil-time.Now().UnixMilli() > desktopSocketControlWait.Milliseconds() || peer.applying {
			peer.mu.Unlock()
			continue
		}
		peer.applying = true
		peer.mu.Unlock()
		if err := s.beginIO(); err != nil {
			peer.mu.Lock()
			peer.applying = false
			peer.mu.Unlock()
			continue
		}
		go func(peer *desktopSocketPeer) {
			defer s.io.Done()
			peer.op.Lock()
			defer peer.op.Unlock()
			_ = s.apply(s.ctx, peer)
		}(peer)
	}
}

func (b *DesktopSocketBroker) Cancel() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return
	}
	b.closing = true
	sockets := make([]*desktopSocket, 0, len(b.sockets))
	for socket := range b.sockets {
		sockets = append(sockets, socket)
	}
	b.mu.Unlock()
	b.cancel()
	if b.source != nil {
		b.source.Cancel()
	}
	for _, socket := range sockets {
		socket.stop()
	}
	b.joinOnce.Do(func() {
		go func() {
			b.workers.Wait()
			for _, socket := range sockets {
				<-socket.done
			}
			if b.source != nil {
				for {
					ctx, cancel := context.WithTimeout(context.Background(), desktopSocketControlWait)
					err := b.source.Close(ctx)
					cancel()
					if err == nil {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			<-b.monitor
			close(b.joined)
		}()
	})
}

func (s *desktopSocket) stop() {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.closing = true
	s.cancel()
	if s.conn != nil {
		_ = s.conn.SetDeadline(time.Now())
	}
	if s.packet != nil {
		_ = s.packet.SetDeadline(time.Now())
	}
	s.mu.Unlock()
	s.closeOnce.Do(func() { go s.drain() })
}

func (s *desktopSocket) drain() {
	<-s.operation
	// A dial may publish its raw handle after cancellation. Interrupt it now
	// too, before waiting for I/O and before any possible descriptor release.
	s.mu.Lock()
	if s.conn != nil {
		_ = s.conn.SetDeadline(time.Now())
	}
	if s.packet != nil {
		_ = s.packet.SetDeadline(time.Now())
	}
	peers := make([]*desktopSocketPeer, 0, len(s.peers))
	for _, peer := range s.peers {
		peers = append(peers, peer)
	}
	s.mu.Unlock()
	s.io.Wait()
	for _, peer := range peers {
		peer.op.Lock()
		for peer.request.Sequence != 0 {
			err := desktopSocketRevokeControlled(context.Background(), s.broker.policy, peer.request)
			if err == nil {
				peer.mu.Lock()
				peer.valid = false
				peer.mu.Unlock()
				break
			}
			s.mu.Lock()
			s.lastFailure = err
			s.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
		peer.op.Unlock()
	}
	for {
		var err error
		if s.conn != nil {
			err = s.conn.Close()
		}
		if s.packet != nil {
			err = errors.Join(err, s.packet.Close())
		}
		if err == nil || errors.Is(err, net.ErrClosed) {
			break
		}
		s.mu.Lock()
		s.lastFailure = err
		s.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	if s.keeper != nil {
		for {
			if err := s.keeper.Close(); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if s.sourceFile != nil {
		for {
			err := s.sourceFile.Close()
			if err == nil || errors.Is(err, os.ErrClosed) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if s.sourceNative != nil {
		for {
			err := s.sourceNative.Close()
			if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				break
			}
			s.mu.Lock()
			s.lastFailure = err
			s.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}
	if source, ok := s.broker.source.(DesktopSocketSourceRelease); ok && (s.sourceFile != nil || s.sourceNative != nil) {
		request := DesktopSocketCreation{Capture: s.broker.capture, Binding: s.binding, SocketID: s.id, Network: s.network}
		for {
			err := desktopSocketReleaseControlled(context.Background(), source, request)
			if err == nil {
				break
			}
			s.mu.Lock()
			s.lastFailure = err
			s.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}
	s.broker.mu.Lock()
	delete(s.broker.sockets, s)
	s.broker.mu.Unlock()
	close(s.done)
}

func (b *DesktopSocketBroker) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("desktop physical close requires a bounded wait")
	}
	wait, cancel := context.WithTimeout(ctx, desktopSocketControlWait)
	defer cancel()
	b.Cancel()
	b.parentStop()
	select {
	case <-b.joined:
		return nil
	default:
	}
	select {
	case <-b.joined:
		return nil
	case <-wait.Done():
		return errors.Join(wait.Err(), errors.New("desktop physical kernel permits/sockets remain retained"))
	}
}
