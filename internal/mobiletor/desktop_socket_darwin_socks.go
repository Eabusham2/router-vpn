//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// This is one association on the original authenticated guardian channel.
// It never changes the source's static destinations or selected LAN policy.
type desktopDarwinSOCKSAssociation struct {
	Control  DesktopSocketGrant
	Binding  DesktopSocketBinding
	Remote   netip.AddrPort
	SocketID string
}

type desktopDarwinSOCKSRelayPolicy struct {
	owner       *DesktopDarwinSocketPolicy
	association desktopDarwinSOCKSAssociation
}

func (p *DesktopDarwinSocketPolicy) socksRelayPolicy(control DesktopSocketGrant, remote netip.AddrPort, socketID string) (DesktopSocketPolicy, error) {
	if p == nil || !desktopSocketHex(socketID, 32) ||
		socketID == control.SocketID || control.Capture != p.capture || !p.Current(control.Capture, control.Binding.Owner) {
		return nil, errors.New("Darwin SOCKS relay lost its original native TCP control")
	}
	binding, err := p.options.binding(p.owner, remote)
	association := desktopDarwinSOCKSAssociation{Control: control, Binding: binding, Remote: remote, SocketID: socketID}
	selected := desktopDarwinGuardian{capture: p.capture, owner: p.owner, options: p.options}
	if err != nil || !selected.socksDestination(association) {
		return nil, errors.Join(err, errors.New("Darwin SOCKS relay is outside its original selected destination policy"))
	}
	return &desktopDarwinSOCKSRelayPolicy{owner: p, association: association}, nil
}

func (a *desktopDarwinSOCKSRelayPolicy) Owner() (DesktopSocketKernelOwner, error) {
	return a.owner.Owner()
}

func (a *desktopDarwinSOCKSRelayPolicy) Current(c DesktopSocketCapture, o DesktopSocketKernelOwner) bool {
	return c == a.association.Control.Capture && o == a.association.Control.Binding.Owner && a.owner.Current(c, o)
}

func (a *desktopDarwinSOCKSRelayPolicy) Select(ctx context.Context, c DesktopSocketCapture, network string, remote netip.AddrPort) (DesktopSocketBinding, error) {
	control := a.association.Control
	if ctx == nil || ctx.Err() != nil || c != control.Capture || network != "udp" || remote != a.association.Remote || !a.Current(c, control.Binding.Owner) {
		return DesktopSocketBinding{}, net.ErrClosed
	}
	reply, file, err := a.owner.call(ctx, desktopDarwinRequest{Operation: "socks-associate", Capture: c, SOCKS: &a.association}, nil, true)
	if file != nil {
		file.Close()
		err = errors.Join(err, errors.New("Darwin SOCKS association unexpectedly transferred a descriptor"))
	}
	expected := DesktopSocketCreation{Capture: c, Binding: a.association.Binding, Network: "udp", SocketID: a.association.SocketID}
	if err != nil || reply.Creation != expected {
		return DesktopSocketBinding{}, errors.Join(err, errors.New("Darwin SOCKS association changed its captured UDP creation"))
	}
	return a.association.Binding, nil
}

func (a *desktopDarwinSOCKSRelayPolicy) Bind(ctx context.Context, c DesktopSocketCapture, b DesktopSocketBinding, network string, raw syscall.RawConn) error {
	if c != a.association.Control.Capture || b != a.association.Binding || network != "udp4" && network != "udp6" {
		return net.ErrClosed
	}
	return a.owner.bindSocket(ctx, c, b, network, raw, a.association.SocketID)
}

func (a *desktopDarwinSOCKSRelayPolicy) matches(g DesktopSocketGrant) bool {
	return g.Capture == a.association.Control.Capture && g.Binding == a.association.Binding &&
		g.Network == "udp" && g.Remote == a.association.Remote && g.SocketID == a.association.SocketID
}

func (a *desktopDarwinSOCKSRelayPolicy) Grant(ctx context.Context, g DesktopSocketGrant) (DesktopSocketReceipt, error) {
	return a.grantSocketAdmitted(ctx, g)
}

func (a *desktopDarwinSOCKSRelayPolicy) grantSocketAdmitted(ctx context.Context, g DesktopSocketGrant) (DesktopSocketReceipt, error) {
	ctx, release, err := a.owner.admitControl(ctx)
	if err != nil {
		return DesktopSocketReceipt{}, err
	}
	defer release()
	if ctx == nil || ctx.Err() != nil || !a.matches(g) || !a.Current(g.Capture, g.Binding.Owner) {
		return DesktopSocketReceipt{}, net.ErrClosed
	}
	reply, file, err := a.owner.callLocked(ctx, desktopDarwinRequest{Operation: "grant", Capture: g.Capture, Grant: g}, nil, true)
	if file != nil {
		file.Close()
		err = errors.Join(err, errors.New("Darwin SOCKS grant unexpectedly transferred a descriptor"))
	}
	return reply.Receipt, errors.Join(err, ctx.Err())
}

func (a *desktopDarwinSOCKSRelayPolicy) Revoke(ctx context.Context, g DesktopSocketGrant) error {
	return a.revokeSocketAdmitted(ctx, g)
}

func (a *desktopDarwinSOCKSRelayPolicy) revokeSocketAdmitted(ctx context.Context, g DesktopSocketGrant) error {
	if !a.matches(g) {
		return net.ErrClosed
	}
	// Retirement remains available after the TCP control or source is lost.
	return a.owner.Revoke(ctx, g)
}
