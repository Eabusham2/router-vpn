//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"time"
)

// The caller must already have independently verified the complete PF anchor.
// Deadlines stay in the guardian and never come from an association request.
func (p *desktopDarwinPF) socksControlExpiry(control DesktopSocketGrant) (time.Time, error) {
	if p == nil || !p.valid() || control.Network != "tcp" || control.Sequence == 0 || control.Capture != p.Capture {
		return time.Time{}, errors.New("Darwin SOCKS control lost its original PF owner")
	}
	permit, exists := p.permits[p.key(control)]
	if !exists || permit.Grant != control || !time.Now().Before(permit.Expires) {
		return time.Time{}, errors.New("Darwin SOCKS control PF permit retired, changed or expired")
	}
	return permit.Expires, nil
}

func (p *desktopDarwinPF) socksGrantExpiry(started time.Time, control DesktopSocketGrant) (time.Time, error) {
	until, err := p.socksControlExpiry(control)
	if err != nil || started.IsZero() || started.After(time.Now()) {
		return time.Time{}, errors.Join(err, errors.New("Darwin SOCKS grant has no original start"))
	}
	expires := started.Add(7 * time.Second)
	if until.Before(expires) {
		expires = until
	}
	if !time.Now().Before(expires) {
		return time.Time{}, errors.New("Darwin SOCKS derived grant expired before admission")
	}
	return expires, nil
}

func (p *desktopDarwinPF) grantSOCKS(ctx context.Context, grant, control DesktopSocketGrant) (DesktopSocketReceipt, error) {
	if ctx == nil || ctx.Err() != nil || grant.Network != "udp" || grant.Capture != control.Capture ||
		grant.Binding.Owner != control.Binding.Owner || grant.SocketID == control.SocketID || !desktopSocketSOCKSRelay(control, grant.Remote) {
		return DesktopSocketReceipt{}, errors.New("Darwin SOCKS PF grant lost its original association")
	}
	// The unchanged two complete PF inspections prove the parent and derived
	// rules together. The derived deadline can never pass the retained parent.
	return p.grantBounded(ctx, grant, &control)
}
