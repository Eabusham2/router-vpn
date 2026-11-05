//go:build windows

package main

import (
	"context"
	"errors"
	"path/filepath"
	"router-vpn/internal/mobilemtu"

	"router-vpn/internal/windowscontroller"
)

func captureDesktopOwnedNodePreparation(a *app) (desktopOwnedNodePreparation, error) {
	var empty desktopOwnedNodePreparation
	capture := windowsOwnedCapture.Load()
	if a == nil {
		return empty, errors.New("native Router preparation has no captured application")
	}
	if err := currentDesktopNodeController(capture); err != nil {
		return empty, err
	}
	if err := windowscontroller.OwnProcessLifetime(); err != nil {
		return empty, err
	}
	// Configuration was constrained during the authenticated bootstrap. Use its
	// retained Data root directly, never a later HOMEVPN_ROOT or package guess.
	a.mu.Lock()
	profiles := a.cfg.ProfilesFile
	a.mu.Unlock()
	if !windowsOwnedSamePath(profiles, filepath.Join(capture.dataRoot, "routers.json")) {
		return empty, errors.New("native Router preparation changed its captured private profile root")
	}
	return desktopOwnedNodePreparation{
		retainedController: capture,
		packageRoot:        capture.packageRoot, dataRoot: capture.dataRoot, lifetime: capture.ctx,
		protectionBackend: func() (desktopNodeProtectionBackend, error) {
			if err := currentDesktopNodeController(capture); err != nil {
				return desktopNodeProtectionBackend{}, err
			}
			return desktopOwnedNodeProtectionBackendFor(capture)
		},

		currentContext: func(ctx context.Context) error {
			if err := currentDesktopNodeControllerContext(ctx, capture); err != nil {
				return err
			}
			if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
				return err
			}
			current := a.cfg.ProfilesFile
			a.mu.Unlock()
			if current != profiles || !windowsOwnedSamePath(current, filepath.Join(capture.dataRoot, "routers.json")) {
				return errors.New("native Router preparation lost its original profile root")
			}
			return ctx.Err()
		},
		current: func() error {
			if err := currentDesktopNodeController(capture); err != nil {
				return err
			}
			a.mu.Lock()
			current := a.cfg.ProfilesFile
			a.mu.Unlock()
			if current != profiles || !windowsOwnedSamePath(current, filepath.Join(capture.dataRoot, "routers.json")) {
				return errors.New("native Router preparation lost its original profile root")
			}
			return nil
		},
	}, nil
}
