package main

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// A stale graph cannot erase the need to validate an actual retained ordered
// owner. This only selects the strict status check; it grants no authority.
func nativeOrderedRuntimeRetained(a *app) bool {
	raw, found := nativeMultihopOwners.Load(a)
	owner, ok := raw.(*nativeMultihopRuntime)
	return found && ok && owner != nil && (owner.execution != nil || owner.launch != nil && owner.launch.chain != nil)
}

// An adopted execution retains basic status through its actual child authority.
// A Compare winner called Local is still an execution owner; neither winner
// acquires generic ordered Performance rows from this status observation.
func nativeOrderedExecutionStatusContext(ctx context.Context, a *app, command *exec.Cmd, graph activeMultihopGraph, stateToken string) (bool, error) {
	if ctx == nil || ctx.Err() != nil || a == nil {
		return false, errors.New("ordered status has no original live caller")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	raw, found := nativeMultihopOwners.Load(a)
	owner, ok := raw.(*nativeMultihopRuntime)
	if !found || !ok || owner == nil || owner.launch == nil || owner.launch.chain == nil ||
		owner.launch.command != command || owner.graph != graph {
		return false, errors.New("ordered status lost its original native owner")
	}
	launch, proof, execution := owner.launch, owner.execution, owner.launch.chain.execution
	if proof == nil && execution == nil {
		return false, nil
	}
	if proof == nil || execution == nil || proof.execution != execution {
		return false, errors.New("ordered status replaced its original execution authority")
	}
	// Native/source/physical Current may call the retained platform; it must
	// finish under the original caller outside app.mu before publication checks.
	current, err := capturedNativeMultihopRuntimeContext(ctx, a, command, graph)
	if err != nil || current != owner {
		return false, errors.Join(err, errors.New("ordered execution status lost its current native authority"))
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return false, err
	}
	defer a.mu.Unlock()
	active, graphOK := getActiveMultihopGraph(a)
	registered, registeredOK := nativeMultihopOwners.Load(a)
	if !graphOK || active != graph || !registeredOK || registered != owner || a.cmd != command ||
		!a.state.Connected || a.state.Phase != "connected" || a.state.Mode != "multihop" || mtuStateSnapshotToken(a.state) != stateToken ||
		owner.launch != launch || owner.execution != proof || launch.chain == nil || launch.chain.execution != execution || proof.execution != execution {
		return false, errors.New("ordered execution status changed during original observation")
	}
	// These existing locked guards never invoke a native observer. The proof
	// uses TryLock, so a concurrent observation cannot block while app.mu is held.
	if err := execution.retainedCurrentLocked(ctx, a, owner, graph); err != nil {
		return false, err
	}
	return true, ctx.Err()
}
