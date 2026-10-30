package main

import (
	"context"
	"errors"

	"router-vpn/internal/common"
)

// StopBegun records the actual transition boundary, rather than inferring a
// disconnect from an error returned by preparation. It is request-local and
// never supplies process, graph, or protection authority.
type modeAttemptTransition struct{ StopBegun bool }

var errDesktopNodeOperationReplaced = errors.New("native fallback cannot mutate another operation's runtime")

// Defaults execute the shipping operations. Tests replace only their native
// execution boundary while exercising the same outer SMART selection loop.
type smartStrategyRuntime struct {
	first   func(*app, common.RouterProfile, *strategyResult) (common.Mode, error)
	check   func(*app, common.Mode) (bool, string)
	start   func(*app, string, bool, *modeAttemptTransition) error
	restore func(*app, speedLabRestorePlan) error
}

func (r smartStrategyRuntime) firstWorking(a *app, profile common.RouterProfile, result *strategyResult) (common.Mode, error) {
	if r.first != nil {
		return r.first(a, profile, result)
	}
	return a.firstWorkingAuto("smart-auto", profile, result)
}

func (r smartStrategyRuntime) checkMode(a *app, mode common.Mode) (bool, string) {
	if r.check != nil {
		return r.check(a, mode)
	}
	return a.checkMode(mode)
}

func (r smartStrategyRuntime) startMode(a *app, id string, hold bool, outcome *modeAttemptTransition) error {
	if r.start != nil {
		return r.start(a, id, hold, outcome)
	}
	return a.startModeAttempt(id, hold, outcome)
}

func (r smartStrategyRuntime) restoreNode(a *app, plan speedLabRestorePlan) error {
	if r.restore != nil {
		return r.restore(a, plan)
	}
	return a.restartCapturedDesktopNode(plan, "smart:restore")
}

func (a *app) sameConnectionOperation(ctx context.Context) bool {
	if a == nil || ctx == nil {
		return false
	}
	a.mu.Lock()
	current := a.connectionContext
	a.mu.Unlock()
	return current == ctx || current == nil && ctx == context.Background()
}

func (a *app) checkCapturedConnectionOperation(ctx context.Context) error {
	if !a.sameConnectionOperation(ctx) || ctx.Err() != nil || a.controllerClosing() {
		return errConnectionOperationCancelled
	}
	return nil
}

func desktopOwnedNodeOperation(launch *desktopNodeLaunch) context.Context {
	if launch == nil || launch.ownedNode == nil {
		return nil
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	return launch.ownedNode.operation
}

type desktopSmartNodeCapture struct {
	operation context.Context
	launch    *desktopNodeLaunch
	plan      speedLabRestorePlan
	state     state
}

func (a *app) captureSmartDesktopNode(ctx context.Context, profile common.RouterProfile) (*desktopSmartNodeCapture, error) {
	raw, exists := desktopNodeOwners.Load(a)
	launch, _ := raw.(*desktopNodeLaunch)
	if !exists || launch == nil || launch.ownedNode == nil {
		return nil, nil
	}
	if err := a.checkCapturedConnectionOperation(ctx); err != nil || desktopOwnedNodeOperation(launch) != ctx {
		return nil, errors.Join(err, errors.New("SMART native predecessor belongs to another operation"))
	}
	a.mu.Lock()
	previous := a.state
	current := a.cmd == launch.command && previous.Connected
	a.mu.Unlock()
	if !current {
		return nil, errors.New("SMART native predecessor is not a proved connection")
	}
	restore, err := a.captureDesktopOwnedNodeRestore(launch, profile)
	if err != nil {
		return nil, err
	}
	return &desktopSmartNodeCapture{operation: ctx, launch: launch, state: previous,
		plan: speedLabRestorePlan{profile: cloneRouterProfile(profile), request: speedLabRequest{Base: previous.Base}, native: restore}}, nil
}

// The preflight failure did not reach Stop. Keep the already proved native
// process and its exact source/MTU instead of reopening current saved inputs.
// This is not a new path measurement or a claim that a trial was restored.
func (a *app) retainSmartDesktopNode(saved *desktopSmartNodeCapture) error {
	if saved == nil || saved.launch == nil || a.checkCapturedConnectionOperation(saved.operation) != nil ||
		desktopOwnedNodeOperation(saved.launch) != saved.operation {
		return errors.New("SMART predecessor changed before it could be retained")
	}
	if _, err := a.readDesktopOwnedNodeReady(saved.launch, false); err != nil {
		return err
	}
	owned := saved.launch.ownedNode
	owned.slot.mu.Lock()
	exact := owned.slot.active == owned.attempt && owned.attempt != nil && owned.attempt.prepared != nil && owned.slot.retirement == nil
	owned.slot.mu.Unlock()
	if !exact {
		return errors.New("SMART predecessor changed its protection attempt")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.connectionContext != saved.operation || a.cmd != saved.launch.command || a.nodeProtection != owned.slot || a.closing {
		return errors.New("SMART predecessor was replaced before retaining presentation")
	}
	a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""
	a.state.Mode, a.state.RuntimeMode, a.state.LogicalMode = saved.state.Mode, saved.state.RuntimeMode, saved.state.LogicalMode
	a.state.RouterID, a.state.Base = saved.state.RouterID, saved.state.Base
	return nil
}

// Cancellation and failed SMART trials may join only a runtime created by the
// captured request. A successful connection outlives that request context;
// this identity is consulted only while the same fallback transaction owns it.
func (a *app) stopDesktopNodeForOperation(ctx context.Context) (bool, error) {
	if !a.sameConnectionOperation(ctx) {
		return true, errors.Join(errConnectionOperationCancelled, errDesktopNodeOperationReplaced)
	}
	raw, exists := desktopNodeOwners.Load(a)
	launch, _ := raw.(*desktopNodeLaunch)
	if !exists || launch == nil || launch.ownedNode == nil {
		return false, nil
	}
	a.mu.Lock()
	current := (a.cmd == nil || a.cmd == launch.command) && launch.ownedNode.slot != nil && a.nodeProtection == launch.ownedNode.slot
	a.mu.Unlock()
	if !current || desktopOwnedNodeOperation(launch) != ctx {
		return true, errors.Join(errConnectionOperationCancelled, errDesktopNodeOperationReplaced)
	}
	return true, a.stopModeWithIntent(true)
}

func (a *app) restoreSmartDesktopNode(saved *desktopSmartNodeCapture, runtime smartStrategyRuntime) error {
	if saved == nil || a.checkCapturedConnectionOperation(saved.operation) != nil {
		return errConnectionOperationCancelled
	}
	if _, err := a.stopDesktopNodeForOperation(saved.operation); err != nil {
		return err
	}
	if err := a.checkCapturedConnectionOperation(saved.operation); err != nil {
		return err
	}
	if err := runtime.restoreNode(a, saved.plan); err != nil {
		_, stopErr := a.stopDesktopNodeForOperation(saved.operation)
		return errors.Join(err, stopErr)
	}
	if err := a.checkCapturedConnectionOperation(saved.operation); err != nil {
		return err
	}
	if _, err := a.readDesktopOwnedNodeReady(saved.plan.native, false); err != nil {
		_, stopErr := a.stopDesktopNodeForOperation(saved.operation)
		return errors.Join(err, stopErr)
	}
	return nil
}
