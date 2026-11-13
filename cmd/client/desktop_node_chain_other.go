//go:build !linux && !darwin

package main

import (
	"context"
	"errors"
)

// Windows uses its existing concrete captured owner. Other platforms cannot
// manufacture a Linux session or borrow the legacy pair's process launcher.
type desktopNodeChainPlatformCapture struct{}
type desktopNodeChainPlatformRuntime struct{}

func captureDesktopNodeChainPlatform(context.Context, *app, multihopSelection) (*desktopNodeChainPlatformCapture, error) {
	return nil, errors.New("ordered native host is not implemented for this platform")
}
func (*desktopNodeChainPlatformCapture) current(context.Context) error {
	return errors.New("ordered native platform capture unavailable")
}
func (*desktopNodeChainPlatformCapture) prepare(context.Context, *desktopNodeChainHostCapture, multihopSelection) (*desktopNodeLaunch, string, error) {
	return nil, "", errors.New("ordered native platform preparation unavailable")
}
func (*desktopNodeChainPlatformCapture) prepareForPurpose(context.Context, *desktopNodeChainHostCapture, multihopSelection, *orderedCandidatePreparation) (*desktopNodeLaunch, string, error) {
	return nil, "", errors.New("ordered native platform preparation unavailable")
}
func (*desktopNodeChainPlatformRuntime) guard(context.Context, *app, *desktopNodeLaunch) error {
	return errors.New("ordered native platform transition unavailable")
}
func (*desktopNodeChainPlatformRuntime) stage(context.Context) error {
	return errors.New("ordered native platform staging unavailable")
}
func (*desktopNodeChainPlatformRuntime) start(context.Context) error {
	return errors.New("ordered native platform startup unavailable")
}
func (*desktopNodeChainPlatformRuntime) current(context.Context) error {
	return errors.New("ordered native platform observation unavailable")
}
func (*desktopNodeChainPlatformRuntime) prove(context.Context) error {
	return errors.New("ordered native platform proof unavailable")
}
func (*desktopNodeChainPlatformRuntime) activate(context.Context) error {
	return errors.New("ordered native platform activation unavailable")
}
func (*desktopNodeChainPlatformRuntime) close(context.Context) error {
	return errors.New("ordered native platform retirement unavailable")
}
func (*desktopNodeChainPlatformRuntime) processDone() <-chan struct{} { return nil }
