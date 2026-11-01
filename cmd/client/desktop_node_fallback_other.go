//go:build !linux

package main

import "context"

func (*app) releaseDesktopLinuxNodeFallbackProtection() (bool, error) { return false, nil }

func (*app) stopDesktopLinuxNodeForOperation(context.Context, bool) (bool, error) {
	return false, nil
}
