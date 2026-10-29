package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// A nonblocking Connect that returned pending is not complete merely because
// Getpeername already exposes its target. First observe writable completion,
// then SO_ERROR, and only then inspect the exact live peer. The platform caller
// retains the entered socket operation and performs its independent identity
// proof after this function succeeds.
// https://learn.microsoft.com/windows/win32/api/winsock2/nf-winsock2-connect
func desktopSocketCompleteTCP(ctx context.Context, pending bool, remote netip.AddrPort,
	wait func(context.Context) error, status func() error, peer func() (netip.AddrPort, error),
) error {
	if ctx == nil || wait == nil || status == nil || peer == nil || !remote.IsValid() || remote.Port() == 0 {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if pending {
		if err := wait(ctx); err != nil {
			return fmt.Errorf("Winsock Connect polling: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := status(); err != nil {
		return fmt.Errorf("Winsock Connect completion status: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	actual, err := peer()
	if err != nil {
		return fmt.Errorf("Winsock completed connected peer: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actual != remote {
		return errors.New("desktop physical connected peer changed")
	}
	return nil
}
