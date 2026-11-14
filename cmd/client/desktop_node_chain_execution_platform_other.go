//go:build !linux && !darwin

package main

import (
	"context"
	"errors"
)

func prepareDesktopNodeChainExecutionPlatform(context.Context, *desktopNodeChainHostCapture, multihopSelection, *desktopNodeChainExecutionRequest) (*desktopNodeLaunch, string, error) {
	return nil, "", errors.New("ordered execution has no installed retained platform owner")
}
