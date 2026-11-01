//go:build !linux

package main

import (
	"context"

	"router-vpn/internal/common"
)

func (*app) startDesktopLinuxNodeConnection(context.Context, common.RouterProfile, common.Mode, [3]bool, bool, ...*modeAttemptTransition) (bool, error) {
	return false, nil
}

func (*app) guardDesktopLinuxNodeLegacyTransition() error { return nil }
