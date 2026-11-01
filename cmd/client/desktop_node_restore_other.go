//go:build !linux

package main

import (
	"context"
	"errors"

	"router-vpn/internal/common"
)

type desktopLinuxNodeRestore struct{}

func captureDesktopLinuxNodeRestore(context.Context, *app, *desktopLinuxNodePath, common.RouterProfile) (*desktopLinuxNodeRestore, error) {
	return nil, errors.New("Linux restore requires its original native platform")
}
func clearDesktopLinuxNodeRestore(*desktopLinuxNodeRestore) {}
func (*app) restartCapturedDesktopLinuxNode(speedLabRestorePlan, string) error {
	return errors.New("Linux restore requires its original native platform")
}
func currentRestoredDesktopLinuxNode(context.Context, *app, *desktopLinuxNodeRestore) error {
	return errors.New("Linux restore requires its original native platform")
}
func (*app) captureSmartDesktopLinuxNode(context.Context, common.RouterProfile) (*desktopSmartNodeCapture, bool, error) {
	return nil, false, nil
}
func (*app) retainSmartDesktopLinuxNode(*desktopSmartNodeCapture) error {
	return errors.New("SMART Linux restore requires its original native platform")
}
