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

func (p *DesktopWindowsSocketPolicy) socksRelayPolicy(control DesktopSocketGrant, remote netip.AddrPort, socketID string) (DesktopSocketPolicy, error) {
	if p == nil || !desktopSocketHex(socketID, 32) || socketID == control.SocketID || !desktopSocketSOCKSRelay(control, remote) || control.Capture != p.capture || !p.Current(control.Capture, control.Binding.Owner) {
		return nil, errors.New("Windows SOCKS relay lost its exact native control")
	}
	return &desktopWindowsSOCKSRelayPolicy{owner: p, control: control, remote: remote, socketID: socketID}, nil
}

// Called only while the original Windows policy queue is owned. Every phase
// checks the still-present actual TCP grant and isolated kernel endpoint.
// The source must have captured this exact original control tuple beforehand.
func (p *DesktopWindowsSocketPolicy) checkSOCKSControl(ctx context.Context, control DesktopSocketGrant, remote netip.AddrPort) error {
	if ctx == nil || ctx.Err() != nil || !desktopSocketSOCKSRelay(control, remote) || !p.Current(control.Capture, control.Binding.Owner) {
		return net.ErrClosed
	}
	if err := p.destination("tcp", control.Remote, false); err != nil {
		return err
	}
	if control.Remote.Addr().IsPrivate() {
		selected := false
		for _, destination := range p.options.PrivateDestinations {
			if destination.Network == "tcp" && destination.Address == control.Remote {
				selected = true
				break
			}
		}
		if !selected {
			return errors.New("SOCKS relay has no originally selected private control tuple")
		}
	}
	if !desktopSocketPrivateSOCKSRelay(control, remote) {
		if err := p.destination("udp", remote, false); err != nil {
			return err
		}
	}
	permit := p.permits[desktopWindowsPermitKey(control)]
	if permit == nil || !time.Now().Before(permit.expires) {
		return errors.New("SOCKS relay control grant retired or expired")
	}
	creation, exists := p.bindings[control.SocketID]
	if !desktopSocketSOCKSControlMatches(permit.request, control) || !exists || creation.Capture != control.Capture || creation.Binding != control.Binding || creation.Network != "tcp" || creation.SocketID != control.SocketID {
		return errors.New("SOCKS relay changed its original socket binding")
	}
	actual, err := p.identity.InspectSocket(ctx, creation)
	if err != nil || actual.Protocol != syscall.IPPROTO_TCP || !actual.PeerConnected || actual.Local != control.Local || actual.Remote != control.Remote {
		return errors.Join(err, errors.New("SOCKS relay control has no actual connected isolated endpoint"))
	}
	return nil
}

func (a *desktopWindowsSOCKSRelayPolicy) Owner() (DesktopSocketKernelOwner, error) {
	return a.owner.Owner()
}
func (a *desktopWindowsSOCKSRelayPolicy) Current(c DesktopSocketCapture, o DesktopSocketKernelOwner) bool {
	return c == a.control.Capture && o == a.control.Binding.Owner && a.owner.Current(c, o)
}
func (a *desktopWindowsSOCKSRelayPolicy) binding(ctx context.Context) (DesktopSocketBinding, error) {
	if desktopSocketPrivateSOCKSRelay(a.control, a.remote) {
		return a.control.Binding, nil
	}
	return a.owner.Select(ctx, a.control.Capture, "udp", a.remote)
}

func (a *desktopWindowsSOCKSRelayPolicy) Select(ctx context.Context, c DesktopSocketCapture, network string, remote netip.AddrPort) (DesktopSocketBinding, error) {
	if c != a.control.Capture || network != "udp" || remote != a.remote {
		return DesktopSocketBinding{}, net.ErrClosed
	}
	return desktopWindowsPolicyCall(a.owner, ctx, false, func() (DesktopSocketBinding, error) {
		if err := a.owner.checkSOCKSControl(ctx, a.control, remote); err != nil {
			return DesktopSocketBinding{}, err
		}
		binding, err := a.binding(ctx)
		if err != nil {
			return DesktopSocketBinding{}, err
		}
		if _, err := a.owner.binding(binding); err != nil {
			return DesktopSocketBinding{}, err
		}
		return binding, nil
	})
}
func (a *desktopWindowsSOCKSRelayPolicy) Bind(ctx context.Context, c DesktopSocketCapture, b DesktopSocketBinding, network string, raw syscall.RawConn) error {
	binding, bindingErr := a.binding(ctx)
	if bindingErr != nil {
		return bindingErr
	}
	if c != a.control.Capture || b != binding || network != "udp" && network != "udp4" && network != "udp6" {
		return net.ErrClosed
	}
	_, err := desktopWindowsPolicyCall(a.owner, ctx, false, func() (struct{}, error) {
		return struct{}{}, a.owner.checkSOCKSControl(ctx, a.control, a.remote)
	})
	if err != nil {
		return err
	}
	creation, err := a.owner.identity.MatchSocket(ctx, c, b, network, raw)
	if err != nil || creation.SocketID != a.socketID {
		return errors.Join(err, errors.New("SOCKS relay changed its exact created UDP socket"))
	}
	return a.owner.Bind(ctx, c, b, network, raw)
}
func (a *desktopWindowsSOCKSRelayPolicy) Grant(ctx context.Context, q DesktopSocketGrant) (DesktopSocketReceipt, error) {
	binding, err := a.binding(ctx)
	if err != nil {
		return DesktopSocketReceipt{}, err
	}
	if q.Capture != a.control.Capture || q.Binding != binding || q.Network != "udp" || q.Remote != a.remote || q.SocketID != a.socketID {
		return DesktopSocketReceipt{}, net.ErrClosed
	}
	return a.owner.grantSocket(ctx, q, &a.control)
}
func (a *desktopWindowsSOCKSRelayPolicy) Revoke(ctx context.Context, q DesktopSocketGrant) error {
	// Retirement must still work after the original control was cancelled.
	if q.Capture != a.control.Capture || q.Binding.Owner != a.control.Binding.Owner || q.Network != "udp" || q.Remote != a.remote || q.SocketID != a.socketID {
		return net.ErrClosed
	}
	return a.owner.Revoke(ctx, q)
}
