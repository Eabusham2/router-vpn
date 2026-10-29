//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"net"
	"os"
)

var _ DesktopSocketTunnelFilePolicy = (*DesktopDarwinSocketPolicy)(nil)

func (p *DesktopDarwinSocketPolicy) BindTunnel(context.Context, DesktopSocketCapture, string, uint32) error {
	return errors.New("Darwin tunnel permission requires the actual owned control descriptor")
}

func (p *DesktopDarwinSocketPolicy) BindTunnelFile(ctx context.Context, capture DesktopSocketCapture, name string, index uint32, file *os.File) error {
	if p == nil || ctx == nil || ctx.Err() != nil || !p.Current(capture, p.owner) || name == "" || index == 0 || file == nil {
		return net.ErrClosed
	}
	actual, err := desktopDarwinReadTunnel(file)
	if err != nil || actual != name {
		return errors.Join(err, errors.New("Darwin native tunnel descriptor changed its actual interface"))
	}
	_, unexpected, err := p.call(ctx, desktopDarwinRequest{Operation: "tunnel", Capture: capture, Tunnel: name, Index: index}, file, true)
	if unexpected != nil {
		unexpected.Close()
		return errors.New("Darwin tunnel acknowledgment transferred another descriptor")
	}
	return err
}

func (p *DesktopDarwinSocketPolicy) RetireTunnel(ctx context.Context, capture DesktopSocketCapture, name string, index uint32) error {
	if p == nil || p.pf == nil || ctx == nil || ctx.Err() != nil || capture != p.capture || name == "" || index == 0 {
		return net.ErrClosed
	}
	_, unexpected, err := p.call(ctx, desktopDarwinRequest{Operation: "retire-tunnel", Capture: capture, Tunnel: name, Index: index}, nil, false)
	if unexpected != nil {
		unexpected.Close()
		return errors.New("Darwin tunnel retirement transferred another descriptor")
	}
	if err == nil {
		return nil
	}
	select {
	case <-p.joined:
		// Every guardian descriptor has actually closed. Remove only its
		// captured network leaf before native interface replacement proceeds.
		return p.pf.close(ctx)
	default:
		return err
	}
}
