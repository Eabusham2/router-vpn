package main

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/routechoice"
)

// This is the selected child's retained authority, not an independently
// reconstructed Server lease or a Local graph with its label rewritten.
type desktopNodeChainExecutionProof struct {
	execution  *desktopNodeChainExecutionLaunch
	physical   *mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy
	projection *mobilemultihop.NodeChainExecutionProjection
	identity   mobilemultihop.NodeChainIdentity
	winner     routechoice.Candidate
	target     string
	epoch      uint64
}

func captureDesktopNodeChainExecutionProofContext(ctx context.Context, launch *desktopNodeLaunch) (*desktopNodeChainExecutionProof, error) {
	if ctx == nil {
		return nil, errors.New("execution proof capture has no caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	e := desktopNodeChainLaunchExecution(launch)
	if e == nil {
		return nil, nil
	}
	if err := e.bound(launch); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &e.mu); err != nil {
		return nil, err
	}
	defer e.mu.Unlock()
	if e.projection == nil || e.ready == nil || e.ready.Identity != e.identity || e.ready.Progress.Comparison.Winner == nil ||
		!e.ready.Progress.Complete || !e.ready.Progress.Ready || !e.ready.Progress.DNSProven || !e.ready.Progress.PublicProven || e.ready.SelectionEpoch == 0 {
		return nil, errors.New("ordered execution graph preceded its selected native proof")
	}
	return &desktopNodeChainExecutionProof{execution: e, physical: e.physical, projection: e.projection, identity: e.identity,
		winner: *e.ready.Progress.Comparison.Winner, target: e.ready.Progress.Comparison.Target, epoch: e.ready.SelectionEpoch}, nil
}

func (proof *desktopNodeChainExecutionProof) currentContext(ctx context.Context, launch *desktopNodeLaunch, graph activeMultihopGraph) error {
	if ctx == nil {
		return errors.New("execution observation has no caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	e, err := proof.original(launch, graph)
	if err != nil || e == nil {
		return errors.Join(err, ctx.Err())
	}
	if err := desktopnetwork.LockContext(ctx, &e.mu); err != nil {
		return err
	}
	defer e.mu.Unlock()
	return errors.Join(proof.currentState(e, graph), ctx.Err())
}

// Caller may hold app.mu. Never wait for an observer that may own a native
// workspace/host lock; an in-flight receipt is a retryable failed observation.
func (proof *desktopNodeChainExecutionProof) currentLocked(launch *desktopNodeLaunch, graph activeMultihopGraph) error {
	e, err := proof.original(launch, graph)
	if err != nil || e == nil {
		return err
	}
	if !e.mu.TryLock() {
		return errors.New("ordered execution receipt is already being observed")
	}
	defer e.mu.Unlock()
	return proof.currentState(e, graph)
}

func (proof *desktopNodeChainExecutionProof) original(launch *desktopNodeLaunch, graph activeMultihopGraph) (*desktopNodeChainExecutionLaunch, error) {
	e := desktopNodeChainLaunchExecution(launch)
	if proof == nil {
		if e != nil || launch != nil && launch.chain != nil && graph.Execution != "local" {
			return nil, errors.New("ordered graph omitted its execution authority")
		}
		return nil, nil
	}
	if e == nil || e != proof.execution || e.bound(launch) != nil || e.physical != proof.physical || graph.Execution != string(proof.winner.Execution) {
		return nil, errors.New("ordered execution graph replaced its original preparation")
	}
	return e, nil
}

func (proof *desktopNodeChainExecutionProof) currentState(e *desktopNodeChainExecutionLaunch, graph activeMultihopGraph) error {
	if e.projection != proof.projection || e.identity != proof.identity || e.ready == nil || e.ready.Identity != proof.identity ||
		e.ready.SelectionEpoch < proof.epoch || e.ready.Progress.Comparison.Target != proof.target || e.ready.Progress.Comparison.Winner == nil ||
		*e.ready.Progress.Comparison.Winner != proof.winner || e.ready.Progress.Execution != graph.Execution {
		return errors.New("ordered execution graph replaced its proved winner, target or identity")
	}
	return nil
}

// Call before taking app.mu. Pure construction lets every native platform publish the chosen graph once,
// inside its original session/command guard, without a transient Local graph.
func desktopNodeChainExecutionGraph(ctx context.Context, launch *desktopNodeLaunch, selection multihopSelection) (activeMultihopGraph, error) {
	proof, err := captureDesktopNodeChainExecutionProofContext(ctx, launch)
	if err != nil || proof == nil || selection.Native == nil || selection.Native != launch.chain.selection.Native || selection.Native.validate(selection) != nil {
		return activeMultihopGraph{}, errors.Join(err, errors.New("ordered execution publication lost its original selected source"))
	}
	graph := activeMultihopGraph{Execution: string(proof.winner.Execution), EntryID: selection.Entry.ID, ExitID: selection.Exit.ID,
		Base: selection.Base, EntryMode: selection.Native.entryMode, SourceSHA: selection.Native.source, ChainNodes: len(selection.Nodes), ExitMode: selection.ExitMode, Started: time.Now().UTC()}
	if err := proof.currentContext(ctx, launch, graph); err != nil {
		return activeMultihopGraph{}, err
	}
	return graph, nil
}

// Caller holds app.mu. Only the original captured operation may publish this
// child's chosen graph or retained native owner; a late callback cannot replace
// a newer operation even if profile IDs and inert graph bytes are identical.
func (e *desktopNodeChainExecutionLaunch) publicationCurrentLocked(ctx context.Context, a *app, launch *desktopNodeLaunch, selection multihopSelection) error {
	if ctx == nil || ctx.Err() != nil || a == nil || e == nil || e.operation == nil || e.bound(launch) != nil ||
		e.original.capture == nil || e.original.capture.app != a || e.original.capture.sources == nil ||
		e.original.selection.Native != selection.Native || launch.command == nil || a.cmd != launch.command || a.closing ||
		a.connectionContext != e.operation || a.checkCapturedConnectionOperationLocked(e.operation) != nil ||
		e.original.capture.sources.currentLocked(a) != nil {
		return errors.New("ordered execution publication lost its captured operation, source or command")
	}
	return ctx.Err()
}
