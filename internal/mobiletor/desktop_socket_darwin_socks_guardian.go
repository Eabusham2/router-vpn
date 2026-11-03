//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"time"
)

func (g *desktopDarwinGuardian) socksDestination(a desktopDarwinSOCKSAssociation) bool {
	c := a.Control
	if !desktopSocketSOCKSRelay(c, a.Remote) || c.Capture != g.capture || c.Binding.Owner != g.owner || a.Binding.Owner != g.owner ||
		!desktopSocketHex(a.SocketID, 32) || a.SocketID == c.SocketID || a.Remote.Addr().Is4() != a.Binding.LocalAddress.Is4() {
		return false
	}
	if c.Remote.Addr().IsPrivate() {
		selected := false
		for _, exact := range g.options.PrivateDestinations {
			selected = selected || exact.Network == "tcp" && exact.Address == c.Remote
		}
		if !selected {
			return false
		}
	} else if !g.options.permits("tcp", c.Remote) {
		return false
	}
	if a.Remote.Addr().IsPrivate() {
		return desktopSocketPrivateSOCKSRelay(c, a.Remote) || g.options.permits("udp", a.Remote)
	}
	// A different public relay keeps the unchanged ordinary numeric policy.
	// Neither loopback nor link-local metadata gains an association exception.
	return !a.Remote.Addr().IsLoopback() && !a.Remote.Addr().IsLinkLocalUnicast() && g.options.permits("udp", a.Remote)
}

func desktopDarwinSOCKSPeer(fd int) (netip.AddrPort, error) {
	peer, err := syscall.Getpeername(fd)
	if err != nil {
		return netip.AddrPort{}, err
	}
	switch value := peer.(type) {
	case *syscall.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(value.Addr), uint16(value.Port)), nil
	case *syscall.SockaddrInet6:
		if value.ZoneId == 0 {
			return netip.AddrPortFrom(netip.AddrFrom16(value.Addr), uint16(value.Port)), nil
		}
	}
	return netip.AddrPort{}, errors.New("Darwin SOCKS control has another native address family")
}

// The original descriptor, its native creator and established TCP endpoint
// are checked independently of the caller's receipt and association claim.
func (g *desktopDarwinGuardian) socksControlSocket(a desktopDarwinSOCKSAssociation) (*desktopDarwinOwnedSocket, DesktopSocketGrant, error) {
	if !g.socksDestination(a) {
		return nil, DesktopSocketGrant{}, errors.New("Darwin SOCKS relay is outside its captured control policy")
	}
	c := a.Control
	owned := g.sockets[c.SocketID]
	if owned == nil || !owned.bound || owned.creation.Capture != c.Capture || owned.creation.Binding != c.Binding ||
		owned.creation.Network != "tcp" || owned.creation.SocketID != c.SocketID || len(owned.grants) != 1 {
		return nil, DesktopSocketGrant{}, errors.New("Darwin SOCKS association has no original bound TCP owner")
	}
	current := owned.grants[c.Remote.String()]
	receipt := owned.receipts[c.Remote.String()]
	if !desktopSocketSOCKSControlMatches(current, c) || !validDesktopSocketReceipt(receipt, current, time.Now()) {
		return nil, DesktopSocketGrant{}, errors.New("Darwin SOCKS control has no matching acknowledged live permit")
	}
	identity, err := desktopDarwinSocketIdentity(owned.file)
	if err != nil || identity != owned.identity || identity.uid != g.uid || identity.network != "tcp" {
		return nil, DesktopSocketGrant{}, errors.New("Darwin SOCKS control lost its original kernel socket")
	}
	fd := int(owned.file.Fd())
	local, localErr := desktopSocketLocal(fd)
	remote, remoteErr := desktopDarwinSOCKSPeer(fd)
	bound, boundErr := desktopDarwinBoundInterface(fd, identity.family)
	infoErr := desktopDarwinSOCKSEstablished(fd)
	if localErr != nil || remoteErr != nil || boundErr != nil || infoErr != nil ||
		local != c.Local || remote != c.Remote || bound != c.Binding.InterfaceIndex {
		return nil, DesktopSocketGrant{}, errors.Join(localErr, remoteErr, boundErr, infoErr, errors.New("Darwin SOCKS control is not its original established physical TCP endpoint"))
	}
	if err := desktopDarwinCheckInterface(DesktopDarwinSocketInterface{Name: c.Binding.InterfaceName, Index: c.Binding.InterfaceIndex, Address: c.Binding.LocalAddress}); err != nil {
		return nil, DesktopSocketGrant{}, err
	}
	return owned, current, nil
}

func (g *desktopDarwinGuardian) checkSOCKSControl(ctx context.Context, a desktopDarwinSOCKSAssociation) (DesktopSocketGrant, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || g.pf == nil {
		return DesktopSocketGrant{}, time.Time{}, errors.New("Darwin SOCKS control has no current guardian readback")
	}
	want, err := g.options.binding(g.owner, a.Remote)
	if err != nil || want != a.Binding {
		return DesktopSocketGrant{}, time.Time{}, errors.Join(err, errors.New("Darwin SOCKS relay lost its separately captured UDP binding"))
	}
	_, current, err := g.socksControlSocket(a)
	if err != nil {
		return DesktopSocketGrant{}, time.Time{}, err
	}
	// This proves the complete captured PF rules, including the original TCP
	// permit. Grant itself shares its existing pre/post readbacks instead.
	if err := g.pf.verify(ctx, true); err != nil {
		return DesktopSocketGrant{}, time.Time{}, err
	}
	until, err := g.pf.socksControlExpiry(current)
	if err != nil {
		return DesktopSocketGrant{}, time.Time{}, err
	}
	_, confirmed, err := g.socksControlSocket(a)
	if err != nil || confirmed != current || ctx.Err() != nil {
		return DesktopSocketGrant{}, time.Time{}, errors.Join(err, ctx.Err(), errors.New("Darwin SOCKS control changed during native PF readback"))
	}
	return current, until, nil
}

func (g *desktopDarwinGuardian) associateSOCKS(ctx context.Context, a desktopDarwinSOCKSAssociation) error {
	if _, _, err := g.checkSOCKSControl(ctx, a); err != nil {
		return err
	}
	return g.claimSOCKSAssociation(a)
}

// This registry is changed only after complete original control proof. A
// pending child is claimed before its descriptor is created or transferred.
func (g *desktopDarwinGuardian) claimSOCKSAssociation(a desktopDarwinSOCKSAssociation) error {
	control := g.sockets[a.Control.SocketID]
	if control == nil {
		return errors.New("Darwin SOCKS association lost its original control")
	}
	if control.socksChild != "" {
		if control.socksChild == a.SocketID && g.socks[a.SocketID] == a {
			return nil
		}
		return errors.New("Darwin SOCKS control already claimed its one captured UDP association")
	}
	if g.sockets[a.SocketID] != nil || len(g.socks) >= DesktopSocketLimit {
		return errors.New("Darwin SOCKS association substituted an existing socket or exceeded its bound")
	}
	if _, exists := g.socks[a.SocketID]; exists {
		return errors.New("Darwin SOCKS association belongs to another control")
	}
	if g.socks == nil {
		g.socks = make(map[string]desktopDarwinSOCKSAssociation)
	}
	g.socks[a.SocketID] = a
	control.socksChild = a.SocketID
	return nil
}

func (g *desktopDarwinGuardian) retireSOCKSControl(socketID string) error {
	control := g.sockets[socketID]
	if control == nil || control.socksChild == "" {
		return nil
	}
	if g.sockets[control.socksChild] != nil {
		return errors.New("Darwin SOCKS control retirement precedes joined UDP descriptor retirement")
	}
	// A failed creation may leave only its immutable pending claim. It owns no
	// descriptor or permit, and cannot prevent retirement of the real control.
	delete(g.socks, control.socksChild)
	return nil
}
