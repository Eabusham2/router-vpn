package main

import (
	"context"
	"errors"
	"router-vpn/internal/desktopnetwork"
)

// Internal-only request retained from the same full source and concrete native
// host capture. Public mode admission remains separate from this constructor.
type desktopNodeChainExecutionRequest struct {
	capture   *desktopNodeChainHostCapture
	native    *nativeMultihopCapture
	requested string
	restore   *desktopNodeChainExecutionRestore
}

func prepareDesktopNodeChainExecutionHost(ctx context.Context, a *app, selection multihopSelection, requested string) (*desktopNodeLaunch, string, error) {
	if requested != "server" && requested != "auto" {
		return nil, "", errors.New("ordered execution requires captured Server or Compare setting")
	}
	capture, err := captureDesktopNodeChainHostContext(ctx, a, selection)
	if err != nil {
		return nil, "", err
	}
	request := &desktopNodeChainExecutionRequest{capture: capture, native: selection.Native, requested: requested}
	return prepareDesktopNodeChainCapturedHost(ctx, capture, selection, nil, request)
}

func (r *desktopNodeChainExecutionRequest) newLaunch(ctx context.Context, capture *desktopNodeChainHostCapture, selection multihopSelection, session, target string) (*desktopNodeLaunch, error) {
	bad := errors.New("execution startup changed its original complete source or native host")
	if r == nil || ctx == nil || ctx.Err() != nil || capture == nil || r.capture != capture || r.native == nil ||
		r.native != selection.Native || capture.sources == nil || capture.sources.selection.Native != r.native ||
		r.native.chain == nil || r.native.chain.host != capture || r.native.validate(selection) != nil {
		return nil, bad
	}
	if err := capture.current(ctx); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &capture.app.mu); err != nil {
		return nil, err
	}
	operation := capture.app.connectionContext
	operationErr := capture.app.checkCapturedConnectionOperationLocked(operation)
	capture.app.mu.Unlock()
	if operationErr != nil {
		return nil, operationErr
	}
	var launch *desktopNodeLaunch
	var execution *desktopNodeChainExecutionLaunch
	var err error
	if r.restore != nil {
		if r.restore.execution == nil || r.restore.execution.original.capture != capture ||
			r.restore.execution.original.selection.Native != r.native || r.requested != r.restore.execution.preparation.Execution() {
			return nil, bad
		}
		launch, execution, err = r.restore.newLaunchContext(ctx, session, target)
	} else {
		launch, err = newDesktopNodeChainLaunch(selection, session, target)
		if err == nil {
			execution, err = newDesktopNodeChainExecutionSource(launch.chain, r.requested)
		}
	}
	if err != nil {
		return nil, err
	}
	if launch.chain.selection.Native != r.native {
		return nil, bad
	}
	execution.operation = operation
	if err := execution.attach(launch); err != nil {
		return nil, err
	}
	return launch, capture.current(ctx)
}

func newDesktopNodeChainLaunchForExecution(ctx context.Context, capture *desktopNodeChainHostCapture, selection multihopSelection, session, target string, purpose *orderedCandidatePreparation, execution *desktopNodeChainExecutionRequest) (*desktopNodeLaunch, error) {
	if execution == nil {
		return newDesktopNodeChainLaunchForPurpose(ctx, selection, session, target, purpose)
	}
	if purpose != nil {
		return nil, errors.New("execution startup cannot borrow candidate preparation authority")
	}
	return execution.newLaunch(ctx, capture, selection, session, target)
}

func (r *desktopNodeChainExecutionRestore) prepareHostContext(ctx context.Context) (*desktopNodeLaunch, string, error) {
	if r == nil || r.execution == nil || r.execution.original.capture == nil {
		return nil, "", errors.New("execution restore lost its original platform capture")
	}
	original := r.execution.original
	request := &desktopNodeChainExecutionRequest{capture: original.capture, native: original.selection.Native,
		requested: r.execution.preparation.Execution(), restore: r}
	return prepareDesktopNodeChainCapturedHost(ctx, original.capture, original.selection, nil, request)
}
