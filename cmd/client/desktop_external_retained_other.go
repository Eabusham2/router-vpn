//go:build !linux

package main

func prepareDesktopRetainedExternal(*app, *desktopNodeLaunch) (desktopExternalRetainedRuntime, error) {
	return nil, nil
}
