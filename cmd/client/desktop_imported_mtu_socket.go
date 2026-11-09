package main

import (
	"context"
	"errors"
	"net"
	"syscall"

	"router-vpn/internal/desktopnetwork"
)

// Only the retained MTU adapter supplies current: it validates the captured
// native command, graph and exact active lease. The kernel interface check
// cannot stand in for that ownership, including during a reader handoff.
func bindDesktopImportedMTUSocket(ctx context.Context, network string, raw syscall.RawConn, live desktopNodeMTURecord, current func(context.Context) error) error {
	if ctx == nil || raw == nil || current == nil ||
		network != "tcp4" && network != "tcp6" && network != "udp4" && network != "udp6" {
		return errors.New("imported MTU socket has no original native path owner")
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := current(ctx); err != nil {
			return err
		}
		return desktopImportedMTUTUNCurrent(ctx, live)
	}
	if err := check(); err != nil {
		return err
	}
	var failure error
	entered := false
	err := raw.Control(func(fd uintptr) {
		if entered {
			failure = errors.New("imported MTU socket repeated its original descriptor binding")
			return
		}
		entered = true
		if failure = check(); failure != nil {
			return
		}
		failure = bindDesktopImportedMTUKernel(ctx, network, fd, live)
	})
	if !entered {
		return errors.Join(err, errors.New("imported MTU socket did not bind its original descriptor"))
	}
	if err != nil || failure != nil {
		return errors.Join(err, failure, ctx.Err())
	}
	return check()
}

// This is a readback of the exact TUN named by the retained native command.
// The adapter separately checks its graph, path, lease and reader; neither an
// interface name nor a matching numeric MTU can supply that authority.
func desktopImportedMTUTUNCurrent(ctx context.Context, live desktopNodeMTURecord) error {
	if ctx == nil || live.Index < 1 || live.Index > 0x7fffffff || live.Reader == 0 ||
		live.MTU < 1280 || live.MTU > 9000 || validateMTULiveInterface(live.Interface) != nil {
		return errors.New("imported MTU socket has no captured native TUN")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	actual, _, err := desktopnetwork.InterfaceContext(ctx, live.Index)
	if err != nil || actual == nil || actual.Index != live.Index || actual.Name != live.Interface || actual.MTU != live.MTU ||
		actual.Flags&net.FlagUp == 0 || actual.Flags&net.FlagLoopback != 0 {
		return errors.Join(err, errors.New("imported MTU socket lost its exact running native TUN"))
	}
	return ctx.Err()
}
