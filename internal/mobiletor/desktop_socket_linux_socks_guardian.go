//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

func (g *desktopLinuxGuardian) socksDestination(a desktopLinuxSOCKSAssociation) bool {
	c := a.Control
	if !c.Capture.valid() || !g.owner.valid() || c.Capture != g.capture || c.Binding.Owner != g.owner || c.Network != "tcp" || c.Sequence == 0 || a.Binding.Owner != g.owner ||
		!desktopSocketHex(c.SocketID, 32) || !desktopSocketHex(a.SocketID, 32) || a.SocketID == c.SocketID ||
		!c.Local.IsValid() || c.Local.Port() == 0 || c.Local.Addr() != c.Binding.LocalAddress ||
		!c.Remote.IsValid() || c.Remote.Port() == 0 || c.Remote.Addr().Is4In6() || c.Remote.Addr().Zone() != "" || c.Remote.Addr().IsLoopback() || c.Remote.Addr().IsLinkLocalUnicast() ||
		!a.Remote.IsValid() || a.Remote.Port() == 0 || a.Remote.Addr().Is4In6() || a.Remote.Addr().Zone() != "" ||
		c.Local.Addr().Is4() != c.Remote.Addr().Is4() || a.Remote.Addr().Is4() != a.Binding.LocalAddress.Is4() {
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

func desktopLinuxSOCKSPeer(fd int) (netip.AddrPort, error) {
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
	return netip.AddrPort{}, errors.New("Linux SOCKS control has another native address family")
}

// Linux UAPI tcp_info starts with the one-byte tcpi_state. TCP_INFO accepts
// shorter output buffers (net/ipv4/tcp.c), so no architecture-specific suffix
// layout or newly added native package is needed to prove ESTABLISHED (1).
func desktopLinuxSOCKSEstablished(fd int) error {
	var state uint8
	length := uint32(1)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.IPPROTO_TCP, syscall.TCP_INFO,
		uintptr(unsafe.Pointer(&state)), uintptr(unsafe.Pointer(&length)), 0)
	if errno != 0 || length != 1 || state != 1 {
		return errors.New("Linux SOCKS original TCP control is no longer established")
	}
	return nil
}

// The original descriptor, its native creator and established TCP endpoint
// are checked independently of the caller's receipt and association claim.
func (g *desktopLinuxGuardian) socksControlSocket(a desktopLinuxSOCKSAssociation) (*desktopLinuxOwnedSocket, DesktopSocketGrant, error) {
	if !g.socksDestination(a) {
		return nil, DesktopSocketGrant{}, errors.New("Linux SOCKS relay is outside its captured control policy")
	}
	c := a.Control
	owned := g.sockets[c.SocketID]
	if owned == nil || !owned.bound || owned.creation.Capture != c.Capture || owned.creation.Binding != c.Binding ||
		owned.creation.Network != "tcp" || owned.creation.SocketID != c.SocketID || len(owned.grants) != 1 {
		return nil, DesktopSocketGrant{}, errors.New("Linux SOCKS association has no original bound TCP owner")
	}
	current := owned.grants[c.Remote.String()]
	receipt := owned.receipts[c.Remote.String()]
	if !desktopSocketSOCKSControlMatches(current, c) || !validDesktopSocketReceipt(receipt, current, time.Now()) {
		return nil, DesktopSocketGrant{}, errors.New("Linux SOCKS control has no matching acknowledged live permit")
	}
	identity, err := desktopLinuxSocketIdentity(owned.file)
	if err != nil || identity != owned.identity || identity.uid != g.uid || identity.network != "tcp" {
		return nil, DesktopSocketGrant{}, errors.New("Linux SOCKS control lost its original kernel socket")
	}
	fd := int(owned.file.Fd())
	local, localErr := desktopSocketLocal(fd)
	remote, remoteErr := desktopLinuxSOCKSPeer(fd)
	bound, boundErr := desktopLinuxBoundDevice(fd)
	infoErr := desktopLinuxSOCKSEstablished(fd)
	if localErr != nil || remoteErr != nil || boundErr != nil || infoErr != nil ||
		local != c.Local || remote != c.Remote || bound != c.Binding.InterfaceName {
		return nil, DesktopSocketGrant{}, errors.Join(localErr, remoteErr, boundErr, infoErr, errors.New("Linux SOCKS control is not its original established physical TCP endpoint"))
	}
	if err := desktopLinuxCheckInterface(DesktopLinuxSocketInterface{Name: c.Binding.InterfaceName, Index: c.Binding.InterfaceIndex, Address: c.Binding.LocalAddress}); err != nil {
		return nil, DesktopSocketGrant{}, err
	}
	return owned, current, nil
}

func (g *desktopLinuxGuardian) checkSOCKSControl(ctx context.Context, a desktopLinuxSOCKSAssociation) (DesktopSocketGrant, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || g.nft == nil {
		return DesktopSocketGrant{}, time.Time{}, errors.New("Linux SOCKS control has no current guardian readback")
	}
	want, err := g.options.binding(g.owner, a.Remote)
	if err != nil || want != a.Binding {
		return DesktopSocketGrant{}, time.Time{}, errors.Join(err, errors.New("Linux SOCKS relay lost its separately captured UDP binding"))
	}
	_, current, err := g.socksControlSocket(a)
	if err != nil {
		return DesktopSocketGrant{}, time.Time{}, err
	}
	started := time.Now()
	rows, err := desktopLinuxNFTReadTable(ctx, g.nft.table())
	if err != nil {
		return DesktopSocketGrant{}, time.Time{}, err
	}
	expires, err := g.nft.socksControlExpiry(rows, current, started)
	return current, expires, err
}

func (g *desktopLinuxGuardian) associateSOCKS(ctx context.Context, a desktopLinuxSOCKSAssociation) error {
	if _, _, err := g.checkSOCKSControl(ctx, a); err != nil {
		return err
	}
	control := g.sockets[a.Control.SocketID]
	if control.socksChild != "" {
		if control.socksChild == a.SocketID && g.socks[a.SocketID] == a {
			return nil
		}
		return errors.New("Linux SOCKS control already claimed its one captured UDP association")
	}
	if g.sockets[a.SocketID] != nil || len(g.socks) >= DesktopSocketLimit {
		return errors.New("Linux SOCKS association substituted an existing socket or exceeded its bound")
	}
	if _, exists := g.socks[a.SocketID]; exists {
		return errors.New("Linux SOCKS association belongs to another control")
	}
	if g.socks == nil {
		g.socks = make(map[string]desktopLinuxSOCKSAssociation)
	}
	g.socks[a.SocketID] = a
	control.socksChild = a.SocketID
	return nil
}

func (g *desktopLinuxGuardian) retireSOCKSControl(socketID string) error {
	control := g.sockets[socketID]
	if control == nil || control.socksChild == "" {
		return nil
	}
	if g.sockets[control.socksChild] != nil {
		return errors.New("Linux SOCKS control retirement precedes joined UDP descriptor retirement")
	}
	// A failed creation may leave only its immutable pending claim. It owns no
	// descriptor or permit, and cannot prevent retirement of the real control.
	delete(g.socks, control.socksChild)
	return nil
}
