//go:build windows

package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// This adapter is owned by one broker UDP socket. It changes no captured
// option, shared destination, baseline rule or another socket's authority.
type desktopWindowsSOCKSRelayPolicy struct {
	owner    *DesktopWindowsSocketPolicy
	control  DesktopSocketGrant
	remote   netip.AddrPort
	socketID string
}

func (p *DesktopWindowsSocketPolicy) privateSOCKSRelayPolicy(control DesktopSocketGrant, remote netip.AddrPort, socketID string) (DesktopSocketPolicy, error) {
	if p == nil || !desktopSocketHex(socketID, 32) || socketID == control.SocketID || !desktopSocketPrivateSOCKSRelay(control, remote) || control.Capture != p.capture || !p.Current(control.Capture, control.Binding.Owner) {
		return nil, errors.New("Windows private SOCKS relay lost its exact native control")
	}
	return &desktopWindowsSOCKSRelayPolicy{owner: p, control: control, remote: remote, socketID: socketID}, nil
}

// Called only while the original Windows policy queue is owned. Every phase
// checks the still-present actual TCP grant and isolated kernel endpoint.
// The source must have captured this exact private control tuple beforehand.
func (p *DesktopWindowsSocketPolicy) checkPrivateSOCKSControl(ctx context.Context, control DesktopSocketGrant, remote netip.AddrPort) error {
	if ctx == nil || ctx.Err() != nil || !desktopSocketPrivateSOCKSRelay(control, remote) || !p.Current(control.Capture, control.Binding.Owner) {
		return net.ErrClosed
	}
	selected := false
	for _, destination := range p.options.PrivateDestinations {
		if destination.Network == "tcp" && destination.Address == control.Remote {
			selected = true
			break
		}
	}
	if !selected {
		return errors.New("private SOCKS relay has no originally selected control tuple")
	}
	permit := p.permits[desktopWindowsPermitKey(control)]
	if permit == nil || !time.Now().Before(permit.expires) {
		return errors.New("private SOCKS relay control grant retired or expired")
	}
	creation, exists := p.bindings[control.SocketID]
	if !desktopSocketSOCKSControlMatches(permit.request, control) || !exists || creation.Capture != control.Capture || creation.Binding != control.Binding || creation.Network != "tcp" || creation.SocketID != control.SocketID {
		return errors.New("private SOCKS relay changed its original socket binding")
	}
	actual, err := p.identity.InspectSocket(ctx, creation)
	if err != nil || actual.Protocol != syscall.IPPROTO_TCP || !actual.PeerConnected || actual.Local != control.Local || actual.Remote != control.Remote {
		return errors.Join(err, errors.New("private SOCKS relay control has no actual connected isolated endpoint"))
	}
	return nil
}

func (a *desktopWindowsSOCKSRelayPolicy) Owner() (DesktopSocketKernelOwner, error) {
	return a.owner.Owner()
}
func (a *desktopWindowsSOCKSRelayPolicy) Current(c DesktopSocketCapture, o DesktopSocketKernelOwner) bool {
	return c == a.control.Capture && o == a.control.Binding.Owner && a.owner.Current(c, o)
}
func (a *desktopWindowsSOCKSRelayPolicy) Select(ctx context.Context, c DesktopSocketCapture, network string, remote netip.AddrPort) (DesktopSocketBinding, error) {
	if c != a.control.Capture || network != "udp" || remote != a.remote {
		return DesktopSocketBinding{}, net.ErrClosed
	}
	return desktopWindowsPolicyCall(a.owner, ctx, false, func() (DesktopSocketBinding, error) {
		if err := a.owner.checkPrivateSOCKSControl(ctx, a.control, remote); err != nil {
			return DesktopSocketBinding{}, err
		}
		if _, err := a.owner.binding(a.control.Binding); err != nil {
			return DesktopSocketBinding{}, err
		}
		return a.control.Binding, nil
	})
}
func (a *desktopWindowsSOCKSRelayPolicy) Bind(ctx context.Context, c DesktopSocketCapture, b DesktopSocketBinding, network string, raw syscall.RawConn) error {
	if c != a.control.Capture || b != a.control.Binding || network != "udp" && network != "udp4" && network != "udp6" {
		return net.ErrClosed
	}
	_, err := desktopWindowsPolicyCall(a.owner, ctx, false, func() (struct{}, error) {
		return struct{}{}, a.owner.checkPrivateSOCKSControl(ctx, a.control, a.remote)
	})
	if err != nil {
		return err
	}
	creation, err := a.owner.identity.MatchSocket(ctx, c, b, network, raw)
	if err != nil || creation.SocketID != a.socketID {
		return errors.Join(err, errors.New("private SOCKS relay changed its exact created UDP socket"))
	}
	return a.owner.Bind(ctx, c, b, network, raw)
}
func (a *desktopWindowsSOCKSRelayPolicy) Grant(ctx context.Context, q DesktopSocketGrant) (DesktopSocketReceipt, error) {
	if q.Capture != a.control.Capture || q.Binding != a.control.Binding || q.Network != "udp" || q.Remote != a.remote || q.SocketID != a.socketID {
		return DesktopSocketReceipt{}, net.ErrClosed
	}
	return a.owner.grantSocket(ctx, q, &a.control)
}
func (a *desktopWindowsSOCKSRelayPolicy) Revoke(ctx context.Context, q DesktopSocketGrant) error {
	// Retirement must still work after the original control was cancelled.
	if q.Capture != a.control.Capture || q.Binding != a.control.Binding || q.Network != "udp" || q.Remote != a.remote || q.SocketID != a.socketID {
		return net.ErrClosed
	}
	return a.owner.Revoke(ctx, q)
}
