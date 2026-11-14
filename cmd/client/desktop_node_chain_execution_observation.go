package main

import (
	"context"
	"errors"
)

// Caller holds app.mu and has already observed the original native process,
// physical network and private workspace with this caller. A completed HTTP
// connection operation is not the retained child's lifetime. Observation still
// requires the exact published owner and proof; it cannot admit or publish one.
func (e *desktopNodeChainExecutionLaunch) retainedCurrentLocked(ctx context.Context, a *app, owner *nativeMultihopRuntime, graph activeMultihopGraph) error {
	if ctx == nil || a == nil || e == nil || owner == nil || owner.launch == nil || owner.execution == nil {
		return errors.New("ordered execution observation lost its original caller or retained owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	launch, selection := owner.launch, owner.selection
	registered, registeredOK := nativeMultihopOwners.Load(a)
	active, graphOK := getActiveMultihopGraph(a)
	if e.operation == nil || e.bound(launch) != nil || owner.execution.execution != e ||
		e.original.capture == nil || e.original.capture.app != a || e.original.capture.sources == nil ||
		e.original.selection.Native != selection.Native || e.original.capture.sources.selection.Native != selection.Native ||
		!registeredOK || registered != owner || !graphOK || active != graph || owner.graph != graph ||
		launch.command == nil || a.cmd != launch.command || a.controllerClosingLocked() ||
		!a.state.Connected || a.state.Phase != "connected" || a.state.Mode != "multihop" ||
		a.connectionCancelIntent != nil || e.original.capture.sources.currentLocked(a) != nil {
		return errors.New("ordered execution observation changed its retained source, command or graph")
	}
	// An operation that is still running must be this child's original one.
	// After its real finish clears the slot, the retained native/proof registry
	// above supplies observation authority, never permission for new publication.
	if a.connectionContext != nil && a.checkCapturedConnectionOperationLocked(e.operation) != nil {
		return errors.New("ordered execution observation belongs to another connection operation")
	}
	if err := owner.execution.currentLocked(launch, graph); err != nil {
		return err
	}
	return ctx.Err()
}
