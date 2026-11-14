//go:build linux

package main

import "context"

func prepareDesktopNodeChainExecutionPlatform(ctx context.Context, capture *desktopNodeChainHostCapture, selection multihopSelection, request *desktopNodeChainExecutionRequest) (*desktopNodeLaunch, string, error) {
	return capture.platform.prepareForPurposeAndExecution(ctx, capture, selection, nil, request)
}
