//go:build linux

package main

import (
	"context"
	"errors"

	"router-vpn/internal/mobiletor"
)

// CheckLegacyTransition must run on the prepared original host before the
// caller records StopBegun or changes the old connection. An existing fixed
// guard is accepted only through the retained installed service reservation. Refuse
// every other transition while the old command and protection still belong to their
// actual owner; never remove either to authorize the new launch.
// The caller holds operationMu through this observation and subsequent Stop.
func (h *desktopLinuxNodeHost) CheckLegacyTransition(ctx context.Context) error {
	observe := mobiletor.ReadDesktopLinuxLegacyTransitionAbsence
	if h != nil && h.standardTransfer != nil {
		observe = func(ctx context.Context) error {
			if h.standardTransfer.host != h {
				return errors.New("transition replaced its actual standard reservation")
			}
			return h.standardTransfer.current(ctx, true)
		}
	}
	return h.checkLegacyTransition(ctx, observe)
}

func (h *desktopLinuxNodeHost) checkLegacyTransition(ctx context.Context, observe func(context.Context) error) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if observe == nil || h.stageEntered || h.staged || h.startEntered || h.process != nil || h.transaction != nil || h.activation != nil {
		return errors.New("Linux transition preflight requires its unused original prepared host")
	}
	if err := h.current(ctx); err != nil {
		return err
	}
	a := h.parent.app
	a.mu.Lock()
	command, presentation := a.cmd, a.state
	a.mu.Unlock()
	current := func() error {
		if err := h.current(ctx); err != nil {
			return err
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.cmd != command || a.state != presentation {
			return errors.New("Linux transition preflight belongs to a changed previous connection")
		}
		return nil
	}
	if err := current(); err != nil {
		return err
	}
	// Even a rejected native query cannot be interpreted as permission to
	// change a replacement command after the original capture was made.
	return errors.Join(observe(ctx), current())
}
