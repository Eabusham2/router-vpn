//go:build !linux

package main

import (
	"context"

	"router-vpn/internal/common"
)

func (*app) captureSmartLegacyPredecessor(context.Context, common.RouterProfile, string) (*desktopSmartLegacyCapture, error) {
	return nil, nil
}
