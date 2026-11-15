//go:build !darwin

package main

import (
	"context"
	"router-vpn/internal/common"
)

func (*app) startDesktopMacOSPairedNodeConnection(context.Context, common.RouterProfile, common.Mode, [3]bool, bool, ...*modeAttemptTransition) (bool, error) {
	return false, nil
}
