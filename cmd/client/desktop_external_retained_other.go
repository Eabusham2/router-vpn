//go:build !linux && !darwin

package main

func prepareDesktopRetainedExternal(*app, *desktopNodeLaunch) (desktopExternalRetainedRuntime, error) {
	return nil, nil
}
