package main

import (
	"context"
	"errors"
	"sync"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// The capsule belongs to one proved parent/child. A saved Last record alone
// cannot replace its joined native retirement or actual pre-stop MTU readback.
type desktopNodeChainExecutionRestore struct {
	mu        sync.Mutex
	app       *app
	launch    *desktopNodeLaunch
	execution *desktopNodeChainExecutionLaunch
	last      mobilemultihop.NodeChainExecutionLast
	identity  mobilemultihop.NodeChainIdentity
	mtu       desktopNodeMTURecord
	retired   bool
}

func (e *desktopNodeChainExecutionLaunch) captureRestoreContext(ctx context.Context, a *app, launch *desktopNodeLaunch) (*desktopNodeChainExecutionRestore, error) {
	if ctx == nil || ctx.Err() != nil || e.bound(launch) != nil || a == nil || e.original.capture == nil || e.original.capture.app != a {
		return nil, errors.New("execution restore has no original captured parent")
	}
	if err := desktopNodeChainCurrent(ctx, a, launch); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &e.mu); err != nil {
		return nil, err
	}
	if e.ready == nil || e.projection == nil || e.started.IsZero() {
		e.mu.Unlock()
		return nil, errors.New("execution restore preceded original proved adoption")
	}
	transfer, started := e.ready.TransferSHA256, e.started
	e.mu.Unlock()
	live, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil || live.Active || live.Failure != "" {
		return nil, errors.Join(err, errors.New("execution restore requires its idle original MTU reader"))
	}
	ready, err := e.readReadyContext(ctx, launch, transfer, started, false, live)
	if err != nil {
		return nil, err
	}
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "node-chain-execution-last.json", 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	last, err := mobilemultihop.ParseNodeChainExecutionLast(string(raw), e.preparation)
	if err != nil || last.Execution() != ready.Progress.Execution || last.Target() != ready.Progress.Comparison.Target {
		return nil, errors.Join(err, errors.New("execution restore changed its proved winner or common target"))
	}
	if err := desktopnetwork.LockContext(ctx, &e.mu); err != nil {
		return nil, err
	}
	matched := e.ready != nil && e.identity == ready.Identity && e.ready.SelectionEpoch == ready.SelectionEpoch && last.ValidateDesktopProjection(e.projection) == nil
	e.mu.Unlock()
	if !matched {
		return nil, errors.New("execution restore replaced its pinned adoption or selected epoch")
	}
	after, err := readDesktopNodeMTUContext(ctx, launch)
	compared, originalReadback := after, live
	compared.Heartbeat, originalReadback.Heartbeat = 0, 0
	if err != nil || compared != originalReadback {
		return nil, errors.Join(err, errors.New("execution restore crossed a native MTU change"))
	}
	if err := desktopNodeChainCurrent(ctx, a, launch); err != nil {
		return nil, err
	}
	return &desktopNodeChainExecutionRestore{app: a, launch: launch, execution: e, last: last, identity: ready.Identity, mtu: live}, nil
}

func (capture *desktopNodeChainExecutionRestore) retireContext(ctx context.Context) error {
	if ctx == nil || capture == nil || capture.app == nil || capture.launch == nil || capture.execution == nil {
		return errors.New("execution restore lost original native retirement")
	}
	if err := desktopnetwork.LockContext(ctx, &capture.mu); err != nil {
		return err
	}
	defer capture.mu.Unlock()
	if capture.retired {
		return ctx.Err()
	}
	if capture.execution.bound(capture.launch) != nil {
		return errors.New("execution restore replaced the original launch before retirement")
	}
	// The existing concrete owner joins only this captured child, remote cleanup,
	// TUN and protection transaction. A replacement app runtime is never stopped.
	var retained desktopNodeChainExecutionRestoreCloser
	if platform := capture.launch.chain.platform; platform != nil {
		retained, _ = any(platform).(desktopNodeChainExecutionRestoreCloser)
	}
	if err := closeDesktopNodeChainExecutionRestoreCapability(ctx, capture.launch, capture.execution, retained,
		func(call context.Context) error {
			return closeDesktopNodeChainLaunch(call, capture.app, capture.launch)
		}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	capture.retired = true
	return nil
}

// Shared platform hooks stage the returned execution source on this fresh
// launch; neither this constructor nor the saved choice grants native Ready.
func (capture *desktopNodeChainExecutionRestore) newLaunchContext(ctx context.Context, session, target string) (*desktopNodeLaunch, *desktopNodeChainExecutionLaunch, error) {
	bad := errors.New("execution restore has not joined its original captured native owner")
	if ctx == nil || capture == nil {
		return nil, nil, bad
	}
	if err := desktopnetwork.LockContext(ctx, &capture.mu); err != nil {
		return nil, nil, err
	}
	defer capture.mu.Unlock()
	if !capture.retired || capture.execution == nil || capture.execution.validateSource() != nil {
		return nil, nil, bad
	}
	if err := desktopnetwork.LockContext(ctx, &capture.execution.mu); err != nil {
		return nil, nil, err
	}
	matched := capture.execution.identity == capture.identity && capture.last.ValidateDesktopProjection(capture.execution.projection) == nil
	capture.execution.mu.Unlock()
	if !matched {
		return nil, nil, bad
	}
	original := capture.execution.original
	if original.capture == nil || original.capture.app != capture.app {
		return nil, nil, bad
	}
	if err := original.capture.current(ctx); err != nil {
		return nil, nil, err
	}
	meta := original.policy.Metadata()
	if target != meta.TargetOS || session == meta.SessionID {
		return nil, nil, bad
	}
	selection := original.selection
	selection.restoreMTU = capture.mtu.MTU
	launch, err := newDesktopNodeChainLaunch(selection, session, target)
	if err != nil {
		return nil, nil, err
	}
	execution, err := newDesktopNodeChainExecutionSource(launch.chain, capture.execution.preparation.Execution())
	if err != nil {
		return nil, nil, err
	}
	prep, err := mobilemultihop.NewDesktopNodeChainExecutionLastPreparation(launch.chain.policy, execution.preparation.Execution(), capture.last.JSON())
	if err != nil {
		return nil, nil, err
	}
	physical, err := prep.DesktopPhysicalPolicy()
	if err != nil {
		return nil, nil, err
	}
	execution.preparation, execution.physical = prep, physical
	if err := errors.Join(execution.validateSource(), original.capture.current(ctx)); err != nil {
		return nil, nil, err
	}
	return launch, execution, nil
}

// Darwin's inherited native host must retain its deny baseline across restore.
// Ordinary Disconnect deliberately remains a different close intent.
type desktopNodeChainExecutionRestoreCloser interface {
	closeForExecutionRestore(context.Context, *desktopNodeChainExecutionLaunch) error
}

// The caller obtains retained only from the captured concrete platform. This
// small dispatch seam also keeps source substitution and missing Darwin support
// testable without inventing a native process or a PF retirement receipt.
func closeDesktopNodeChainExecutionRestoreCapability(ctx context.Context, launch *desktopNodeLaunch, captured *desktopNodeChainExecutionLaunch,
	retained desktopNodeChainExecutionRestoreCloser, closeOriginal func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || captured == nil || captured.bound(launch) != nil {
		return errors.New("execution restore close lost its exact captured source or caller")
	}
	if retained != nil {
		return errors.Join(retained.closeForExecutionRestore(ctx, captured), ctx.Err())
	}
	if captured.original.policy.Metadata().TargetOS == "darwin" {
		return errors.New("Darwin execution restore requires its retained deny-baseline close owner")
	}
	if closeOriginal == nil {
		return errors.New("execution restore has no original captured close")
	}
	return errors.Join(closeOriginal(ctx), ctx.Err())
}
