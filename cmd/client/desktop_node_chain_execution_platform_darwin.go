//go:build darwin

package main

import (
	"context"
	"errors"
)

func prepareDesktopNodeChainExecutionPlatform(ctx context.Context, capture *desktopNodeChainHostCapture,
	selection multihopSelection, request *desktopNodeChainExecutionRequest) (*desktopNodeLaunch, string, error) {
	if capture == nil || capture.platform == nil || request == nil {
		return nil, "", errors.New("macOS execution preparation lost its captured original host")
	}
	return capture.platform.prepareForPurposeAndExecution(ctx, capture, selection, nil, request)
}
