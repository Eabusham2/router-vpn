//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/desktopnetwork"
)

func desktopCohortLinuxOff(ctx context.Context, a *app) error {
	path, handled, err := captureDesktopLinuxNodePath(ctx, a, nil)
	if err != nil {
		return err
	}
	if path != nil {
		return errors.New("comparison off boundary retained an active Linux native path")
	}
	// A captured settled disconnected Always guard has no TUN. This check
	// does not adopt or change it; ordinary transition policy still owns it.
	_ = handled
	return nil
}

func desktopCohortLinuxReceipt(ctx context.Context, a *app, path *desktopLinuxNodePath) (*desktopnetwork.DesktopNetworkReceipt, error) {
	if path == nil || path.app != a || path.session == nil || path.host == nil {
		return nil, errors.New("comparison has no original retained Linux path")
	}
	if err := path.session.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { path.session.gate <- struct{}{} }()
	if err := path.host.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { path.host.gate <- struct{}{} }()
	_, live, err := path.currentLocked(ctx)
	if err != nil {
		return nil, err
	}
	return parseDesktopCohortReceipt(live.NetworkReceipt, live.Interface, live.Index, live.MTU)
}

func desktopCohortLinuxJoined(ctx context.Context, path *desktopLinuxNodePath) error {
	if path == nil || ctx == nil || ctx.Err() != nil || path.host == nil || path.process == nil || path.transaction == nil || path.processJoined == nil {
		return errors.New("retired Linux routing receipt lost its original owners")
	}
	select {
	case <-path.processJoined:
	default:
		return errors.New("retired Linux routing receipt still has a live original process")
	}
	h := path.host
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-h.gate:
	}
	defer func() { h.gate <- struct{}{} }()
	if h.process != path.process || h.transaction != path.transaction || h.launch != path.launch || !h.closed {
		return errors.New("Linux routing retirement has no closed original host")
	}
	t := path.transaction
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.gate:
	}
	defer func() { t.gate <- struct{}{} }()
	if !t.retired || !t.engineJoined || t.retirement == nil || t.pending != nil {
		return errors.New("Linux routing retirement lacks its original native source acknowledgement")
	}
	return nil
}
