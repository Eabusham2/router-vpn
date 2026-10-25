package main

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

func (a *app) holdMTUForStop() (func(), *exec.Cmd, error) {
	return a.holdMTUForStopWith(a.holdCapturedMTU)
}

// Only explicit runtime teardown may retire the native engine to discharge an
// unresolved MTU lease. Speed Lab's measurement hold never takes this fallback.
func (a *app) holdMTUForStopWith(hold func(context.Context) (func(), error)) (func(), *exec.Cmd, error) {
	a.mu.Lock()
	command := a.cmd
	a.mu.Unlock()
	current := func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.cmd == command
	}
	tryHold := func() (func(), error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		release, err := hold(ctx)
		if err == nil && !current() {
			release()
			return nil, errors.New("connection owner changed while its MTU teardown was draining")
		}
		return release, err
	}
	release, holdErr := tryHold()
	if holdErr == nil {
		return release, command, nil
	}
	if command == nil || !current() {
		return nil, command, holdErr
	}
	raw, exists := desktopNodeOwners.Load(a)
	launch, native := raw.(*desktopNodeLaunch)
	if !exists || !native || launch == nil || launch.command != command || launch.command.Process == nil || launch.external == nil && launch.mtuSession == "" {
		return nil, command, holdErr
	}
	// An unconfirmed commit can outlive its revert deadline. Stop this exact
	// child, with protection retained, so its checked TUN retirement can close
	// the MTU owner. Process death alone cannot satisfy either stop helper.
	var retireErr error
	if launch.external != nil {
		retireErr = prepareDesktopExternalStop(a, command)
	} else {
		retireErr = prepareDesktopNodeStop(a, command)
	}
	if retireErr != nil || !current() {
		return nil, command, errors.Join(holdErr, retireErr, errors.New("captured native MTU teardown has not completed"))
	}
	if active, found := desktopNodeOwners.Load(a); !found || active != launch {
		return nil, command, errors.Join(holdErr, errors.New("native MTU teardown owner was replaced"))
	}
	release, err := tryHold()
	if err != nil {
		return nil, command, errors.Join(holdErr, err)
	}
	return release, command, nil
}
