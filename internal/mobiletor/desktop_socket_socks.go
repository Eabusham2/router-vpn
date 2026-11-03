package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// Only an in-package native source can derive this per-socket capability. It
// is never a profile field, context key, shared destination or caller policy.
type desktopSocketSOCKSOwner interface {
	privateSOCKSRelayPolicy(DesktopSocketGrant, netip.AddrPort, string) (DesktopSocketPolicy, error)
}

func (s *desktopSocket) policy() DesktopSocketPolicy {
	if s.scopedPolicy != nil {
		return s.scopedPolicy
	}
	return s.broker.policy
}

// A captured control may predate a genuine renewal, but cannot claim a
// sequence the native owner has not acknowledged. All other fields are fixed.
func desktopSocketSOCKSControlMatches(current, captured DesktopSocketGrant) bool {
	if captured.Sequence == 0 || captured.Sequence > current.Sequence {
		return false
	}
	current.Sequence = captured.Sequence
	return current == captured
}

func desktopSocketPrivateSOCKSRelay(control DesktopSocketGrant, remote netip.AddrPort) bool {
	return control.Capture.valid() && control.Binding.Owner.valid() && control.Network == "tcp" &&
		desktopSocketHex(control.SocketID, 32) && control.Sequence != 0 && control.Local.IsValid() && control.Local.Port() != 0 &&
		control.Local.Addr() == control.Binding.LocalAddress && control.Remote.IsValid() && control.Remote.Port() != 0 &&
		control.Remote.Addr().IsPrivate() && !control.Remote.Addr().Is4In6() && control.Remote.Addr().Zone() == "" &&
		remote.IsValid() && remote.Port() != 0 && remote.Addr() == control.Remote.Addr() &&
		control.Local.Addr().Is4() == remote.Addr().Is4()
}

// DialPrivateSOCKSRelay is called only by the pinned native SOCKS client's
// per-operation lower dialer after successful authentication and UDP ASSOCIATE.
// The actual retained TCP object is the authority: a tuple, wrapped connection,
// copied receipt, sibling source or imported graph cannot stand in for it.
// Public/different-host relays keep the normal numeric broker path.
func (b *DesktopSocketBroker) DialPrivateSOCKSRelay(ctx context.Context, control net.Conn, address string) (net.Conn, error) {
	_, remote, err := desktopSocketDestination("udp", address)
	owned, ok := control.(*desktopSocketConn)
	if err != nil || !ok || owned == nil || owned.socket == nil || owned.socket.broker != b || owned.socket.network != "tcp" ||
		ctx == nil || ctx.Err() != nil || !b.Current() || !owned.socket.allowed(owned.socket.remote) {
		return nil, errors.New("private SOCKS relay has no original live native TCP control")
	}
	parent := owned.socket
	parent.mu.Lock()
	peer := parent.peers[parent.remote]
	parent.mu.Unlock()
	if peer == nil {
		return nil, net.ErrClosed
	}
	receipt, valid := peer.snapshot()
	if !valid || !validDesktopSocketReceipt(receipt, receipt.Grant, time.Now()) || !desktopSocketPrivateSOCKSRelay(receipt.Grant, remote) {
		return nil, errors.New("private SOCKS relay differs from its captured control address")
	}
	parent.mu.Lock()
	if parent.closing || parent.socksClaimed || parent.ctx.Err() != nil {
		parent.mu.Unlock()
		return nil, net.ErrClosed
	}
	parent.socksClaimed = true
	parent.mu.Unlock()
	packet, err := b.openPacketOwned(ctx, "udp", remote, true, parent)
	if err != nil {
		return nil, err
	}
	return &desktopConnectedPacket{packet: packet, remote: net.UDPAddrFromAddrPort(remote)}, nil
}

func (s *desktopSocket) attachSOCKSParent(parent *desktopSocket, remote netip.AddrPort) error {
	if parent == nil || parent == s || parent.broker != s.broker || parent.network != "tcp" || s.network != "udp" ||
		remote != s.remote || !parent.allowed(parent.remote) {
		return net.ErrClosed
	}
	parent.mu.Lock()
	if parent.closing || !parent.socksClaimed || parent.ctx.Err() != nil || len(parent.children) != 0 {
		parent.mu.Unlock()
		return net.ErrClosed
	}
	peer := parent.peers[parent.remote]
	if peer == nil {
		parent.mu.Unlock()
		return net.ErrClosed
	}
	receipt, valid := peer.snapshot()
	if !valid || !validDesktopSocketReceipt(receipt, receipt.Grant, time.Now()) || !desktopSocketPrivateSOCKSRelay(receipt.Grant, remote) {
		parent.mu.Unlock()
		return net.ErrClosed
	}
	s.parent = parent
	if parent.children == nil {
		parent.children = make(map[*desktopSocket]struct{})
	}
	parent.children[s] = struct{}{}
	parent.mu.Unlock()
	if owner, ok := s.broker.policy.(desktopSocketSOCKSOwner); ok {
		policy, err := owner.privateSOCKSRelayPolicy(receipt.Grant, remote, s.id)
		if err != nil || policy == nil {
			return errors.Join(err, errors.New("private SOCKS source omitted its exact association capability"))
		}
		s.scopedPolicy = policy
	}
	return nil
}
