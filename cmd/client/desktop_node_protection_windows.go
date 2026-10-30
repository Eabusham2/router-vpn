//go:build windows

package main

import (
	"context"
	"errors"

	"router-vpn/internal/mobiletor"
)

func desktopOwnedNodeProtectionBackend() (desktopNodeProtectionBackend, error) {
	owner := windowsOwnedCapture.Load()
	if owner == nil || owner.Alive() != nil {
		return desktopNodeProtectionBackend{}, errors.New("native Router protection requires its authenticated Windows controller")
	}
	// The retained app slot authorizes only its exact target. Cleanup may run
	// after the original UI retires, so these checked native cleanup operations
	// deliberately do not depend on that UI remaining alive.
	return desktopNodeProtectionBackend{
		read: mobiletor.ReadDesktopWindowsProtectionExpectation,
		prepared: func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
			return mobiletor.ReadDesktopWindowsPreparedProtection(ctx, target.Capture, target.Policy, target.BaselineSHA256)
		},
		release: func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
			owner, err := mobiletor.NewDesktopWindowsProtectionReleaseTarget(ctx, target)
			if owner == nil {
				return nil, err
			}
			return owner, err
		},
		recover: func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
			owner, err := mobiletor.NewDesktopWindowsProtectionRecoveryTarget(ctx, target)
			if owner == nil {
				return nil, err
			}
			return owner, err
		},
	}, nil
}
