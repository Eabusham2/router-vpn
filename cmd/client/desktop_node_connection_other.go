//go:build !linux

package main

import (
	"context"
	"errors"

	"router-vpn/internal/common"
)

func (*app) startDesktopLinuxNodeConnection(context.Context, common.RouterProfile, common.Mode, [3]bool, bool, ...*modeAttemptTransition) (bool, error) {
	return false, nil
}

func (*app) guardDesktopLinuxNodeLegacyTransition() error { return nil }

func (*app) guardDesktopLinuxNodeLegacyTransitionContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("native transition requires its original caller")
	}
	return ctx.Err()
}
