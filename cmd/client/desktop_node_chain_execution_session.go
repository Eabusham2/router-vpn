package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/routechoice"
)

// This session consumes the comparison performed by the typed native child.
// It deliberately has no Probe methods: putting it through routechoice.Compare
// would repeat selection and could restore a different winner.
type desktopNodeChainExecutionSession struct {
	mu               sync.Mutex
	app              *app
	launch           *desktopNodeLaunch
	execution        *desktopNodeChainExecutionLaunch
	selection        multihopSelection
	graph            *activeMultihopGraph
	native           *nativeMultihopRuntime
	dns              *activeDNSRuntimeIdentity
	closed           bool
	workspaceRemoved bool
	restoreNext      *desktopNodeChainExecutionSession
}

// A partial session is returned with every post-construction error so the
// caller can join its exact child and retry retained cleanup.
func openDesktopNodeChainExecutionSession(ctx context.Context, a *app, selection multihopSelection, requested string) (*desktopNodeChainExecutionSession, error) {
	launch, binary, err := prepareDesktopNodeChainExecutionHost(ctx, a, selection, requested)
	if launch == nil {
		return nil, err
	}
	session := &desktopNodeChainExecutionSession{app: a, launch: launch, execution: desktopNodeChainLaunchExecution(launch), selection: selection}
	if err != nil {
		return session, err
	}
	if err := preflightRetainedNativeMultihop(ctx, binary, launch, runDesktopExternalPreflightCommand); err != nil {
		return session, err
	}
	return session, session.startContext(ctx)
}

func (s *desktopNodeChainExecutionSession) startContext(ctx context.Context) error {
	if ctx == nil || s == nil || s.app == nil || s.execution == nil || s.execution.bound(s.launch) != nil {
		return errors.New("execution session lost its original launch")
	}
	if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if s.closed || s.graph != nil || s.native != nil || s.launch.command != nil {
		return errors.New("execution session cannot repeat startup")
	}
	if err := stageOwnedNativeMultihopInputsContext(ctx, s.app, s.selection, s.launch); err != nil {
		return err
	}
	if desktopMultihopPlatformLaunch(s.launch) {
		budget, err := desktopNodeReadyBudget(s.launch)
		if err != nil {
			return err
		}
		startup, cancel := context.WithTimeout(ctx, budget)
		err = s.launch.chain.platform.start(startup)
		cancel()
		if err != nil {
			return err
		}
		if s.launch.command == nil {
			return errors.New("execution platform returned no captured command")
		}
		if err := s.launch.chain.platform.current(ctx); err != nil {
			return err
		}
		if err := desktopnetwork.LockContext(ctx, &s.app.mu); err != nil {
			return err
		}
		err = s.execution.publicationCurrentLocked(ctx, s.app, s.launch, s.selection)
		if err == nil {
			err = registerActiveDNSRuntimeConfigKind(s.app, s.selection.Exit.ID, s.selection.ExitMode, filepath.Join(s.launch.directory, "sing-box.json"), true)
		}
		s.app.mu.Unlock()
		if err != nil {
			return err
		}
	} else {
		if err := desktopnetwork.LockContext(ctx, &s.app.mu); err != nil {
			return err
		}
		err := s.app.publishDesktopNodeChainStartLocked(s.execution.operation, s.launch, s.selection)
		if err == nil {
			err = registerNativeMultihopDNSRuntime(s.app, s.selection, s.launch.command)
		}
		s.app.mu.Unlock()
		if err != nil {
			return err
		}
		if err := startDesktopOwnedNodeChainLaunch(ctx, s.execution.operation, s.app, s.launch); err != nil {
			return err
		}
	}
	// The child has now authenticated, selected, re-proved, and published its
	// canonical adoption. Never publish a temporary Local graph before this.
	graph, err := desktopNodeChainExecutionGraph(ctx, s.launch, s.selection)
	if err != nil {
		return err
	}
	graph, err = publishDesktopMultihopPlatformGraph(ctx, s.app, s.launch, s.selection, graph.Execution)
	if err != nil {
		return err
	}
	s.graph = &graph
	if err := bindNativeMultihopRuntimeContext(ctx, s.app, s.launch, s.selection, s.execution.original.capture.network); err != nil {
		return err
	}
	raw, ok := nativeMultihopOwners.Load(s.app)
	owner, typed := raw.(*nativeMultihopRuntime)
	if !ok || !typed || owner == nil || owner.launch != s.launch || owner.execution == nil || owner.execution.execution != s.execution {
		return errors.New("execution session lost its just-published native owner")
	}
	s.native = owner
	return s.currentLocked(ctx)
}

func (s *desktopNodeChainExecutionSession) currentLocked(ctx context.Context) error {
	if s.closed || s.graph == nil || s.native == nil || s.execution == nil || s.execution.bound(s.launch) != nil {
		return errors.New("execution session has no retained proved owner")
	}
	owner, err := capturedNativeMultihopRuntimeContext(ctx, s.app, s.launch.command, *s.graph)
	if err != nil {
		return err
	}
	if owner != s.native || owner.execution == nil || owner.execution.execution != s.execution {
		return errors.New("execution session was replaced")
	}
	return ctx.Err()
}

func (s *desktopNodeChainExecutionSession) Current(ctx context.Context) error {
	if ctx == nil || s == nil {
		return errors.New("execution observation has no original caller")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	return s.currentLocked(ctx)
}

func (s *desktopNodeChainExecutionSession) Verify(ctx context.Context) error {
	if ctx == nil || s == nil {
		return errors.New("execution proof has no original caller")
	}
	if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if err := proveDesktopNodeChainContext(ctx, s.app, s.selection, s.launch.command); err != nil {
		return err
	}
	if desktopMultihopPlatformLaunch(s.launch) {
		if err := activateDesktopMultihopPlatform(ctx, s.launch); err != nil {
			return err
		}
	}
	return s.currentLocked(ctx)
}

func (s *desktopNodeChainExecutionSession) Result(ctx context.Context) (routechoice.Result, error) {
	var empty routechoice.Result
	if ctx == nil || s == nil {
		return empty, errors.New("execution result has no original caller")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
		return empty, err
	}
	defer s.mu.Unlock()
	if err := s.currentLocked(ctx); err != nil {
		return empty, err
	}
	if err := desktopnetwork.LockContext(ctx, &s.execution.mu); err != nil {
		return empty, err
	}
	if s.execution.ready == nil || s.native.execution.currentState(s.execution, *s.graph) != nil {
		s.execution.mu.Unlock()
		return empty, errors.New("execution result lost its original selected proof")
	}
	encoded, err := json.Marshal(s.execution.ready.Progress.Comparison)
	s.execution.mu.Unlock()
	if err != nil {
		return empty, err
	}
	var result routechoice.Result
	if err := json.Unmarshal(encoded, &result); err != nil {
		return empty, err
	}
	if err := s.currentLocked(ctx); err != nil {
		return empty, err
	}
	return result, nil
}

// Retirement never rediscovers a session or calls the global Stop path. Native
// Close must positively join before a private file or publication is removed.
func (s *desktopNodeChainExecutionSession) Close(ctx context.Context) error {
	if ctx == nil || s == nil || s.app == nil || s.launch == nil || s.execution == nil {
		return errors.New("execution retirement lost its original owner")
	}
	if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if s.closed {
		return ctx.Err()
	}
	// Source replacement revokes observation and restoration, but it must not
	// prevent joining the already captured process. Native Close retains the
	// original protection receipt checks before granting terminal retirement.
	if s.launch.chain == nil || s.launch.chain.execution != s.execution || s.execution.original != s.launch.chain ||
		s.launch.chain.capture == nil || s.launch.chain.capture.app != s.app || s.launch.chain.selection.Native != s.selection.Native {
		return errors.New("execution retirement changed its captured launch")
	}
	s.captureDNSPublication()
	if err := closeDesktopNodeChainLaunch(ctx, s.app, s.launch); err != nil {
		return err
	}
	return s.finishRetirementLocked(ctx)
}

func (s *desktopNodeChainExecutionSession) captureDNSPublication() {
	// Compare-and-delete retains the exact registration, including its directory.
	// An unrelated registration is never adopted merely because it is current.
	if s.dns != nil {
		return
	}
	expected := activeDNSRuntimeIdentity{ProfileID: s.selection.Exit.ID, RuntimeID: s.selection.ExitMode, Config: filepath.Join(s.launch.directory, "sing-box.json"), ImportedEntry: true}
	if raw, ok := activeDNSRuntimeIdentities.Load(s.app); ok && raw == expected {
		s.dns = &expected
	}
}

func (s *desktopNodeChainExecutionSession) finishRetirementLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Platform Close owns its own workspace/controller retirement. Windows
	// retains its descriptor until the exact child and protection receipt join.
	if s.launch.chain.platform == nil && !s.workspaceRemoved {
		if s.launch.ownedNode == nil {
			return errors.New("execution retirement lost its concrete native owner")
		}
		if err := cleanupDesktopNodeLaunch(s.launch); err != nil {
			return err
		}
		s.workspaceRemoved = true
	}
	if err := desktopnetwork.LockContext(ctx, &s.app.mu); err != nil {
		return err
	}
	defer s.app.mu.Unlock()
	clearCommand := s.app.cmd == s.launch.command && s.launch.command != nil
	if raw, found := nativeMultihopOwners.Load(s.app); found && raw != s.native {
		clearCommand = false
	}
	if raw, found := desktopNodeOwners.Load(s.app); found && raw != s.launch {
		clearCommand = false
	}
	if graph, found := getActiveMultihopGraph(s.app); found && (s.graph == nil || graph != *s.graph) {
		clearCommand = false
	}
	if s.native != nil {
		nativeMultihopOwners.CompareAndDelete(s.app, s.native)
	}
	if s.graph != nil {
		activeMultihopGraphs.CompareAndDelete(s.app, *s.graph)
	}
	desktopNodeOwners.CompareAndDelete(s.app, s.launch)
	if s.dns != nil {
		activeDNSRuntimeIdentities.CompareAndDelete(s.app, *s.dns)
	}
	if clearCommand {
		s.app.cmd = nil
		s.app.state.Connected = false
		s.app.state.Mode, s.app.state.LogicalMode, s.app.state.RuntimeMode, s.app.state.Base = "off", "", "", ""
		s.app.state.Phase, s.app.state.LastError = "off", ""
	}
	clear(s.launch.config)
	clear(s.launch.metadata)
	if s.launch.ownedNode != nil {
		clear(s.launch.ownedNode.source)
	}
	s.closed = true
	return ctx.Err()
}

// CaptureRestore retains the already selected child result and live MTU. Pass
// this capsule directly to Restore, which owns the retained-intent native join.
// Calling ordinary Close first invalidates restorability; it cannot grant the
// retained deny-baseline authority required by this capsule.
func (s *desktopNodeChainExecutionSession) CaptureRestore(ctx context.Context) (*desktopNodeChainExecutionRestore, error) {
	if ctx == nil || s == nil {
		return nil, errors.New("execution restore has no original session")
	}
	if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := s.currentLocked(ctx); err != nil {
		return nil, err
	}
	return s.execution.captureRestoreContext(ctx, s.app, s.launch)
}

func (s *desktopNodeChainExecutionSession) prepareRestoreContext(ctx context.Context, capture *desktopNodeChainExecutionRestore) (*desktopNodeChainExecutionSession, string, error) {
	if ctx == nil || s == nil || capture == nil {
		return nil, "", errors.New("execution restore lost its captured session")
	}
	if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
		return nil, "", err
	}
	defer s.mu.Unlock()
	if capture.app != s.app || capture.launch != s.launch || capture.execution != s.execution {
		return nil, "", errors.New("execution restore belongs to another session")
	}
	if s.restoreNext != nil {
		return s.restoreNext, "", errors.New("execution restore already owns a constructed successor")
	}
	if !s.closed {
		s.captureDNSPublication()
		if err := capture.retireContext(ctx); err != nil {
			return nil, "", err
		}
		if err := s.finishRetirementLocked(ctx); err != nil {
			return nil, "", err
		}
	}
	launch, binary, err := capture.prepareHostContext(ctx)
	if launch == nil {
		return nil, "", err
	}
	next := &desktopNodeChainExecutionSession{app: s.app, launch: launch, execution: desktopNodeChainLaunchExecution(launch), selection: launch.chain.selection}
	s.restoreNext = next
	return next, binary, err
}

func (s *desktopNodeChainExecutionSession) Restore(ctx context.Context, capture *desktopNodeChainExecutionRestore) (*desktopNodeChainExecutionSession, error) {
	next, binary, err := s.prepareRestoreContext(ctx, capture)
	if err != nil {
		return next, err
	}
	if err := preflightRetainedNativeMultihop(ctx, binary, next.launch, runDesktopExternalPreflightCommand); err != nil {
		return next, err
	}
	return next, next.startContext(ctx)
}
