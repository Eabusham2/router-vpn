//go:build !linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/desktopnetwork"
)

func desktopCohortLinuxOff(context.Context, *app) error { return nil }
func desktopCohortLinuxReceipt(context.Context, *app, *desktopLinuxNodePath) (*desktopnetwork.DesktopNetworkReceipt, error) {
	return nil, errors.New("Linux receipt belongs to another target")
}
func desktopCohortLinuxJoined(context.Context, *desktopLinuxNodePath) error {
	return errors.New("Linux retirement belongs to another target")
}
