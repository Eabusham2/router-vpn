//go:build darwin

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// The portable graph is captured before this installed parent. Neither a
// readiness file nor a saved profile can construct a replacement session.
type desktopNodeChainPlatformCapture struct {
	parent *desktopMacOSSessionCapture
	verify func(context.Context, string) (string, error)
}

type desktopNodeChainPlatformRuntime struct {
	capture    *desktopNodeChainHostCapture
	host       *desktopMacOSNodeChainHost
	registered bool
}

// A public MTU wrapper retains the original native lease. Its methods follow
// host.gate -> raw owner mutex; native retirement is joined before cleanup.
type desktopMacOSNodeChainMTUBridge interface {
	nativeOwner() *desktopNodeMTUOwner
	closeRetiredLocked(context.Context) error
}

type desktopMacOSNodeChainHost struct {
	parent                                                             *desktopMacOSSessionCapture
	runtime                                                            *desktopNodeChainPlatformRuntime
	launch                                                             *desktopNodeLaunch
	policy                                                             *mobilemultihop.DesktopNodeChainPolicy
	socksPolicy                                                        *mobilemultihop.DesktopNodeChainSOCKSPolicy
	connectPolicy                                                      *mobilemultihop.DesktopNodeChainCONNECTPolicy
	execution                                                          *desktopNodeChainExecutionLaunch
	executionPreparation                                               *mobilemultihop.NodeChainExecutionPreparation
	executionPhysical                                                  *mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy
	executionProof                                                     *desktopNodeChainExecutionProof
	selection                                                          desktopMacOSNodeChainSelection
	operation                                                          context.Context
	gate                                                               chan struct{}
	process                                                            *desktopMacOSProcess
	mtu                                                                desktopMacOSNodeChainMTUBridge
	mtuObservation                                                     desktopMacOSMTUObservationSlot
	baseline                                                           *desktopMacOSNodeChainReceipt
	baselineRun                                                        desktopMacOSNodeChainBaselineRunner
	started                                                            time.Time
	transfer                                                           string
	bound                                                              *nativeMultihopRuntime
	graph                                                              *activeMultihopGraph // Exact value published before native bind.
	entered, staged, published, proved, activated, baselineEntered     bool
	retiring, nativeRetired, baselineRetired, workspaceRetired, closed bool
	stageDirectory                                                     string
	stageInfo                                                          os.FileInfo // Original creation witness survives a failed workspace open.
	monitorCancel                                                      context.CancelFunc
	monitorDone                                                        chan struct{}
}

func captureDesktopNodeChainPlatform(ctx context.Context, a *app, selection multihopSelection) (*desktopNodeChainPlatformCapture, error) {
	if selection.Native == nil || selection.Native.root != macOSOwnedControllerRoot {
		return nil, errors.New("macOS ordered source is outside its installed controller")
	}
	parent, err := captureDesktopMacOSSession(ctx, a)
	if err != nil {
		return nil, err
	}
	return &desktopNodeChainPlatformCapture{parent: parent, verify: verifyBundledNativeContext}, nil
}

func (capture *desktopNodeChainPlatformCapture) current(ctx context.Context) error {
	if capture == nil || capture.parent == nil || capture.verify == nil {
		return errors.New("macOS ordered capture lost its original installed parent")
	}
	return capture.parent.Current(ctx)
}

func (capture *desktopNodeChainPlatformCapture) prepare(ctx context.Context, owner *desktopNodeChainHostCapture,
	selection multihopSelection) (launch *desktopNodeLaunch, image string, failure error) {
	return capture.prepareForPurpose(ctx, owner, selection, nil)
}

func (capture *desktopNodeChainPlatformCapture) prepareForPurpose(ctx context.Context, owner *desktopNodeChainHostCapture,
	selection multihopSelection, purpose *orderedCandidatePreparation) (launch *desktopNodeLaunch, image string, failure error) {
	return capture.prepareForPurposeAndExecution(ctx, owner, selection, purpose, nil)
}

func (capture *desktopNodeChainPlatformCapture) prepareForPurposeAndExecution(ctx context.Context, owner *desktopNodeChainHostCapture,
	selection multihopSelection, purpose *orderedCandidatePreparation, execution *desktopNodeChainExecutionRequest) (launch *desktopNodeLaunch, image string, failure error) {
	if capture == nil || capture.parent == nil || owner == nil || owner.platform != capture || owner.windows != nil ||
		owner.sources == nil || owner.app != capture.parent.app || selection.Native == nil || selection.Native.chain == nil ||
		selection.Native.chain.host != owner || owner.sources.selection.Native != selection.Native {
		return nil, "", errors.New("macOS ordered preparation changed its original full source and parent")
	}
	if err := owner.current(ctx); err != nil {
		return nil, "", err
	}
	image, err := capture.verify(ctx, macOSOwnedControllerRoot)
	if err != nil || image != macosprocess.EnginePath {
		return nil, "", errors.Join(err, errors.New("macOS ordered preparation verified another installed image"))
	}
	a := owner.app
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return nil, "", err
	}
	operation := a.connectionContext
	err = a.checkCapturedConnectionOperationLocked(operation)
	a.mu.Unlock()
	if err != nil {
		return nil, "", err
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, "", err
	}
	launch, err = newDesktopNodeChainLaunchForExecution(ctx, owner, selection, session, "darwin", purpose, execution)
	if err != nil {
		return nil, "", err
	}
	launch.chain.capture = owner
	meta := launch.chain.policyMetadata()
	runtime := &desktopNodeChainPlatformRuntime{capture: owner}
	h := &desktopMacOSNodeChainHost{parent: capture.parent, runtime: runtime, launch: launch, policy: launch.chain.policy, socksPolicy: launch.chain.socksPolicy, connectPolicy: launch.chain.connectPolicy,
		operation: operation, gate: make(chan struct{}, 1), baselineRun: runDesktopMacOSNodeChainBaseline,
		selection: desktopMacOSNodeChainSelection{Schema: 2, Family: launch.chain.macOSFamily(), ProfileID: meta.ProfileID,
			Session: meta.SessionID, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy}}
	if launch.chain.execution != nil {
		h.execution = launch.chain.execution
		h.executionPreparation, h.executionPhysical = h.execution.preparation, h.execution.physical
	}
	runtime.host, launch.chain.platform = h, runtime
	// Publish a complete dependent before any private stage or PF mutation.
	// Parent Close can wait for this construction gate and retain failed cleanup.
	defer func() { h.gate <- struct{}{} }()
	if err := h.currentLocked(ctx, false); err != nil {
		return launch, "", err
	}
	if err := h.parent.session.Retain(ctx, h); err != nil {
		return launch, "", err
	}
	runtime.registered = true
	return launch, image, h.currentLocked(ctx, false)
}

func (h *desktopMacOSNodeChainHost) enter(ctx context.Context) error {
	if h == nil || ctx == nil || h.gate == nil {
		return errors.New("macOS ordered host has no bounded original owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-h.gate:
	}
	if err := ctx.Err(); err != nil {
		h.gate <- struct{}{}
		return err
	}
	return nil
}

// Called under the host gate (or its unshared construction gate). Full source,
// original process and PF checks remain separate authorities.
func (h *desktopMacOSNodeChainHost) currentLocked(ctx context.Context, running bool) error {
	if h == nil || h.parent == nil || h.parent.session == nil || h.runtime == nil || h.runtime.host != h ||
		h.runtime.capture == nil || h.runtime.capture.platform == nil || h.runtime.capture.platform.parent != h.parent ||
		h.launch == nil || h.launch.chain == nil || h.launch.chain.platform != h.runtime ||
		h.launch.chain.capture != h.runtime.capture || !h.launch.chain.hasPolicy() || h.launch.chain.policy != h.policy || h.launch.chain.socksPolicy != h.socksPolicy || h.launch.chain.connectPolicy != h.connectPolicy ||
		h.launch.chain.execution != h.execution ||
		h.launch.ownedNode != nil || h.operation == nil || h.baselineRun == nil || h.retiring || h.closed ||
		h.launch.root != macOSOwnedControllerRoot {
		return errors.New("macOS ordered host lost its unique original policy and parent")
	}
	if h.execution != nil {
		if h.execution.preparation != h.executionPreparation || h.execution.physical != h.executionPhysical ||
			h.execution.operation != h.operation || h.execution.bound(h.launch) != nil {
			return errors.New("macOS execution host replaced its original preparation or physical owner")
		}
	} else if h.executionPreparation != nil || h.executionPhysical != nil {
		return errors.New("macOS ordered host acquired an unrelated execution preparation")
	}
	if err := h.runtime.capture.current(ctx); err != nil {
		return err
	}
	if err := validateDesktopNodeChainLaunch(ctx, h.launch); err != nil {
		return err
	}
	meta := h.launch.chain.policyMetadata()
	expected := desktopMacOSNodeChainSelection{Schema: 2, Family: h.launch.chain.macOSFamily(), ProfileID: meta.ProfileID,
		Session: meta.SessionID, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy}
	if meta.TargetOS != "darwin" || h.selection != expected || !h.selection.valid() {
		return errors.New("macOS ordered host changed its typed protection selection")
	}
	a := h.parent.app
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	valid := !a.closing && a.localController == h.parent.controller
	if !h.activated {
		valid = valid && h.operation.Err() == nil && a.checkCapturedConnectionOperationLocked(h.operation) == nil &&
			a.connectionCancelIntent != h.operation
	}
	if h.published {
		valid = valid && a.cmd == h.launch.command && a.state.RouterID == meta.ProfileID &&
			a.state.Mode == "multihop" && a.state.LogicalMode == "multihop" && a.state.RuntimeMode == meta.Mode
	}
	a.mu.Unlock()
	if !valid {
		return errors.New("macOS ordered request or published command was replaced")
	}
	if h.published {
		p := h.parent.parent
		if err := p.enter(ctx); err != nil {
			return err
		}
		_, retained := h.parent.session.dependents[h]
		selected := p.originalSession == h.parent.session && h.parent.session.nodeChain == h.runtime &&
			h.parent.session.external == nil && h.parent.session.candidatePrefix == nil && retained
		p.gate <- struct{}{}
		if !selected {
			return errors.New("macOS ordered runtime belongs to a replaced retained session")
		}
	}
	if h.published {
		// Start's first current read precedes the outer graph bind. It may accept
		// an absent registry then, but never a foreign owner or a lost bound owner.
		raw, exists := nativeMultihopOwners.Load(a)
		if exists {
			bound, ok := raw.(*nativeMultihopRuntime)
			if !ok || bound == nil || bound.launch != h.launch || bound.selection.Native != h.launch.chain.selection.Native ||
				h.bound != nil && bound != h.bound || !sameDesktopMacOSExecutionProof(bound.execution, h.executionProof) ||
				h.bound != nil && bound.execution != h.executionProof {
				return errors.New("macOS ordered runtime has another graph owner")
			}
		} else if h.bound != nil {
			return errors.New("macOS ordered runtime lost its bound graph")
		}
		if h.graph != nil {
			graph, found := getActiveMultihopGraph(a)
			if !found || graph != *h.graph || h.bound != nil && h.bound.graph != *h.graph {
				return errors.New("macOS ordered runtime changed its complete captured graph")
			}
			if err := h.executionProof.currentContext(ctx, h.launch, graph); err != nil {
				return err
			}
		} else if h.bound != nil || h.executionProof != nil {
			return errors.New("macOS ordered runtime lost its original pre-bind graph receipt")
		}
	}
	if running {
		expectedScope := macosprocess.Scope{Family: h.selection.Family, Session: h.selection.Session,
			Source: h.selection.Source, Config: h.selection.Config, Workspace: h.launch.directory}
		if !h.published || h.process == nil || h.process.parent != h.parent || h.process.capture == nil ||
			h.process.scope != expectedScope || h.process.command != h.launch.command || h.baseline == nil ||
			h.process.execution != h.executionPreparation || h.process.executionPhysical != h.executionPhysical ||
			h.baseline.Phase != "active" || h.started.IsZero() {
			return errors.New("macOS ordered runtime has no admitted original child and PF receipt")
		}
		if err := h.process.Current(ctx); err != nil {
			return err
		}
		if _, err := h.baselineRun(ctx, h.parent, h.selection, "current", h.baseline, nil); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (owner *desktopNodeChainPlatformRuntime) guard(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if owner == nil || !owner.registered || owner.host == nil || owner.capture == nil || owner.capture.app != a ||
		owner.host.launch != launch || launch == nil || launch.chain == nil || launch.chain.platform != owner {
		return errors.New("macOS ordered transition lost its retained original host")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.currentLocked(ctx, false); err != nil {
		return err
	}
	p := h.parent.parent
	if err := p.enter(ctx); err != nil {
		return err
	}
	_, retained := h.parent.session.dependents[h]
	p.gate <- struct{}{}
	if !retained {
		return errors.New("macOS ordered transition lost its cleanup registration")
	}
	return nil
}

func (owner *desktopNodeChainPlatformRuntime) PublishGraph(ctx context.Context, a *app, launch *desktopNodeLaunch,
	selection multihopSelection, execution string) (activeMultihopGraph, error) {
	var empty activeMultihopGraph
	if owner == nil || !owner.registered || owner.host == nil || owner.host.launch != launch || launch == nil ||
		launch.chain == nil || launch.chain.platform != owner || owner.host.parent == nil || owner.host.parent.app != a {
		return empty, errors.New("macOS ordered graph publication lost its original host")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return empty, err
	}
	defer func() { h.gate <- struct{}{} }()
	original := launch.chain.selection
	if !h.published || h.retiring || h.closed || h.graph != nil || h.bound != nil || h.executionProof != nil || launch.command == nil ||
		selection.Native == nil || selection.Native != original.Native || selection.Native.chain == nil ||
		h.execution == nil && execution != "local" ||
		selection.Control.ID != original.Control.ID || selection.Entry.ID != original.Entry.ID || selection.Exit.ID != original.Exit.ID ||
		selection.Base != original.Base || selection.ExitMode != original.ExitMode || len(selection.Nodes) != len(original.Nodes) ||
		selection.Native.validate(selection) != nil {
		return empty, errors.New("macOS ordered graph changed its complete original publication")
	}
	var chosen activeMultihopGraph
	var chosenProof *desktopNodeChainExecutionProof
	if h.execution != nil {
		if err := h.readReadyLocked(ctx, false); err != nil {
			return empty, err
		}
		var err error
		chosen, err = desktopNodeChainExecutionGraph(ctx, launch, original)
		if err != nil || execution != chosen.Execution {
			return empty, errors.Join(err, errors.New("macOS execution publication changed its actual chosen graph"))
		}
		chosenProof, err = captureDesktopNodeChainExecutionProofContext(ctx, launch)
		if err != nil || chosenProof == nil {
			return empty, errors.Join(err, errors.New("macOS execution publication lost its adopted proof"))
		}
	}
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return empty, err
	}
	defer a.mu.Unlock()
	if a.localController != h.parent.controller || a.cmd != launch.command || a.checkCapturedConnectionOperationLocked(h.operation) != nil {
		return empty, errors.New("macOS ordered graph publication lost its original command or operation")
	}
	if h.execution != nil {
		if err := h.execution.publicationCurrentLocked(ctx, a, launch, original); err != nil {
			return empty, err
		}
		if err := chosenProof.currentLocked(launch, chosen); err != nil {
			return empty, err
		}
	}
	if _, found := nativeMultihopOwners.Load(a); found {
		return empty, errors.New("macOS ordered graph already has another bound owner")
	}
	if _, found := getActiveMultihopGraph(a); found {
		return empty, errors.New("macOS ordered graph cannot replace another publication")
	}
	p := h.parent.parent
	if err := p.enter(ctx); err != nil {
		return empty, err
	}
	defer func() { p.gate <- struct{}{} }()
	_, retained := h.parent.session.dependents[h]
	if p.originalSession != h.parent.session || h.parent.session.nodeChain != owner || h.parent.session.external != nil || h.parent.session.candidatePrefix != nil || !retained {
		return empty, errors.New("macOS ordered graph publication lost its exact retained session")
	}
	if err := p.currentLocked(ctx, true); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	// There is no fallible observation between publication and retaining its
	// exact receipt. Cancellation after the store revokes later activation,
	// never this original owner's ability to retire its own unbound graph.
	graph := chosen
	if h.execution == nil {
		graph = setActiveMultihopGraph(a, original)
	} else {
		activeMultihopGraphs.Store(a, graph)
		homeExitProofs.Delete(a)
	}
	copy := graph
	h.graph, h.executionProof = &copy, chosenProof
	return graph, nil
}

// Publication precedes native bind, which captures its own immutable proof
// object. Both must name the identical original adoption. After prove binds
// the native owner, the host retains that exact proof pointer as well.
func sameDesktopMacOSExecutionProof(a, b *desktopNodeChainExecutionProof) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (owner *desktopNodeChainPlatformRuntime) stage(ctx context.Context) error {
	if owner == nil || !owner.registered || owner.host == nil {
		return errors.New("macOS ordered staging lost its retained original host")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.currentLocked(ctx, false); err != nil {
		return err
	}
	if h.staged || h.entered || h.launch.directory != "" {
		return errors.New("macOS ordered stage has already been consumed")
	}
	directory, err := newPrivateRuntimeDir(macOSOwnedControllerRoot, "native-node")
	if err != nil {
		return err
	}
	h.stageDirectory = directory
	h.stageInfo, err = os.Lstat(directory)
	if err != nil {
		return err
	}
	if err := h.captureWorkspace(); err != nil {
		return err
	}
	for _, input := range []struct {
		name string
		body []byte
	}{
		{h.launch.chain.sourceName(), []byte(h.launch.chain.input)},
		{"sing-box.json", h.launch.config},
	} {
		if err := writeDesktopRuntimeFile(h.launch, input.name, input.body, false); err != nil {
			return err
		}
	}
	h.staged = true
	return h.currentLocked(ctx, false)
}

// A failed second open keeps the original creation witness. Cleanup may
// reopen only that same private directory; absence or a replacement pathname
// never supplies a terminal receipt or authority to remove somebody's files.
func (h *desktopMacOSNodeChainHost) captureWorkspace() error {
	if h == nil || h.launch == nil || h.stageDirectory == "" || h.stageInfo == nil || !h.stageInfo.IsDir() ||
		h.stageInfo.Mode()&os.ModeSymlink != 0 || h.stageInfo.Mode().Perm()&0077 != 0 {
		return errors.New("macOS ordered staging has no original private directory witness")
	}
	current, err := os.Lstat(h.stageDirectory)
	if err != nil || !os.SameFile(current, h.stageInfo) || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		current.Mode().Perm()&0077 != 0 {
		return errors.Join(err, errors.New("macOS ordered staging cannot recapture a missing or replacement directory"))
	}
	if h.launch.directory != "" && h.launch.directory != h.stageDirectory ||
		h.launch.directoryInfo != nil && !os.SameFile(h.launch.directoryInfo, h.stageInfo) {
		return errors.New("macOS ordered staging changed its original workspace witness")
	}
	if h.launch.directoryRoot != nil && desktopExternalDirectoryCurrent(h.launch) == nil {
		return nil
	}
	pending := &desktopNodeLaunch{}
	if err := captureDesktopRuntimeDirectory(pending, h.stageDirectory); err != nil {
		if pending.directoryRoot != nil {
			_ = pending.directoryRoot.Close()
		}
		return err
	}
	if !os.SameFile(pending.directoryInfo, h.stageInfo) {
		_ = pending.directoryRoot.Close()
		return errors.New("macOS ordered staging opened a replacement directory")
	}
	if h.launch.directoryRoot != nil {
		if err := h.launch.directoryRoot.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			_ = pending.directoryRoot.Close()
			return err
		}
	}
	h.launch.directory, h.launch.directoryInfo, h.launch.directoryRoot = pending.directory, h.stageInfo, pending.directoryRoot
	return desktopExternalDirectoryCurrent(h.launch)
}

func (owner *desktopNodeChainPlatformRuntime) start(ctx context.Context) error {
	if owner == nil || !owner.registered || owner.host == nil || owner.capture == nil || owner.capture.platform == nil {
		return errors.New("macOS ordered startup lost its original session")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.currentLocked(ctx, false); err != nil {
		return err
	}
	if !h.staged || h.entered || h.process != nil {
		return errors.New("macOS ordered startup requires its unused exact private stage")
	}
	a, p := h.parent.app, h.parent.parent
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	if err := p.enter(ctx); err != nil {
		a.mu.Unlock()
		return err
	}
	_, legacy := desktopNodeOwners.Load(a)
	_, external := desktopExternalRetainedLaunches.Load(a)
	_, graph := nativeMultihopOwners.Load(a)
	if err := p.currentLocked(ctx, true); err != nil {
		p.gate <- struct{}{}
		a.mu.Unlock()
		return err
	}
	if p.originalSession != h.parent.session || h.parent.session.external != nil || h.parent.session.candidatePrefix != nil ||
		h.parent.session.nodeChain != nil || a.cmd != nil || a.state.Connected || legacy || external || graph ||
		a.checkCapturedConnectionOperationLocked(h.operation) != nil || h.runtime.capture.sources.currentLocked(a) != nil {
		p.gate <- struct{}{}
		a.mu.Unlock()
		return errors.New("macOS ordered startup cannot replace an unjoined predecessor")
	}
	h.entered, h.published = true, true
	h.parent.session.nodeChain = owner
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode = "multihop", "multihop", h.launch.mode
	a.state.RouterID, a.state.Base = h.launch.policyProfileID, h.launch.chain.selection.Base
	a.state.Connected, a.state.Phase, a.state.LastError = false, "starting", ""
	p.gate <- struct{}{}
	a.mu.Unlock()
	var err error
	h.baseline, err = h.baselineRun(ctx, h.parent, h.selection, "apply", nil, func() { h.baselineEntered = true })
	if err != nil {
		return err
	}
	if err := h.currentLocked(ctx, false); err != nil {
		return err
	}
	scope := macosprocess.Scope{Family: h.selection.Family, Session: h.selection.Session,
		Source: h.selection.Source, Config: h.selection.Config, Workspace: h.launch.directory}
	h.started = time.Now()
	if h.execution != nil {
		h.process, err = startDesktopMacOSExecutionProcessWithVerifier(ctx, h.parent, scope,
			h.executionPreparation, h.executionPhysical, owner.capture.platform.verify)
	} else {
		h.process, err = startDesktopMacOSProcessWithVerifier(ctx, h.parent, scope, owner.capture.platform.verify)
	}
	if err != nil {
		return err
	}
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	if a.cmd != nil || a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.localController != h.parent.controller {
		a.mu.Unlock()
		return errors.New("macOS ordered created child lost its original application")
	}
	h.launch.command, a.cmd = h.process.command, h.process.command
	a.mu.Unlock()
	if err := h.currentLocked(ctx, true); err != nil {
		return err
	}
	if h.execution != nil {
		// The chosen graph cannot be published until this exact child has
		// adopted and proved its winner. This pins typed readiness without
		// claiming the later graph bind, activation or MTU ownership.
		return h.awaitReadyLocked(ctx, true)
	}
	return nil
}

func validateDesktopMacOSNodeChainInterface(record desktopNodeMTURecord, link *net.Interface) error {
	if link == nil || !strings.HasPrefix(record.Interface, "utun") || len(record.Interface) == len("utun") ||
		link.Index != record.Index || link.Name != record.Interface || link.MTU != record.MTU ||
		link.Flags&net.FlagUp == 0 || record.MTU < 1280 || record.MTU > 9000 {
		return errors.New("macOS ordered proof changed its actual native utun reader")
	}
	for _, digit := range strings.TrimPrefix(record.Interface, "utun") {
		if digit < '0' || digit > '9' {
			return errors.New("macOS ordered proof has an invalid native utun name")
		}
	}
	return nil
}

// A fresh child proof may name a new utun only after the native reader
// advanced. Observe both the new interface and absence of the old exact one;
// a decoded generation counter alone is never a retirement receipt.
func validateDesktopMacOSNodeChainReaderRetirement(previous *mobilemultihop.DesktopNodeChainReadyRecord,
	live desktopNodeMTURecord, inventory []net.Interface) error {
	if previous == nil {
		return errors.New("macOS ordered replacement lacks its original reader")
	}
	return validateDesktopMacOSReaderRetirement(previous.InterfaceName, int(previous.InterfaceIndex), previous.Reader, live, inventory)
}

func validateDesktopMacOSReaderRetirement(name string, index int, reader uint64,
	live desktopNodeMTURecord, inventory []net.Interface) error {
	if name == "" || index < 1 || reader == 0 || name == live.Interface || live.Reader <= reader {
		return errors.New("macOS ordered replacement lacks an advanced original reader")
	}
	found := false
	for i := range inventory {
		link := &inventory[i]
		if link.Index == index && link.Name == name {
			return errors.New("macOS ordered replacement retained its original utun reader")
		}
		if link.Index == live.Index {
			if err := validateDesktopMacOSNodeChainInterface(live, link); err != nil {
				return err
			}
			found = true
		}
	}
	if !found {
		return errors.New("macOS ordered replacement lost its actual new utun reader")
	}
	return nil
}

func (h *desktopMacOSNodeChainHost) readReadyLocked(ctx context.Context, fresh bool) error {
	if err := h.currentLocked(ctx, true); err != nil {
		return err
	}
	// The full inherited selection binds the exact installed images, input
	// descriptors, original workspace and ordered family on both sides.
	transfer, err := h.launch.chain.macOSTransfer(h.process.capture.Selection())
	if err != nil || h.transfer != "" && h.transfer != transfer {
		return errors.Join(err, errors.New("macOS ordered readiness changed its original transfer"))
	}
	previousName, previousIndex, previousReader, err := h.capturedReaderLocked(ctx)
	if err != nil {
		return err
	}
	live, err := readDesktopNodeMTUContext(ctx, h.launch)
	if err != nil {
		return err
	}
	link, _, err := desktopnetwork.InterfaceContext(ctx, live.Index)
	if err != nil {
		return err
	}
	if err := validateDesktopMacOSNodeChainInterface(live, link); err != nil {
		return err
	}
	if previousName != "" && previousName != live.Interface {
		inventory, err := desktopnetwork.InterfacesContext(ctx)
		if err != nil {
			return err
		}
		if err := validateDesktopMacOSReaderRetirement(previousName, previousIndex, previousReader, live, inventory); err != nil {
			return err
		}
	}
	if err := readDesktopNodeChainNativeReadyContext(ctx, h.launch, transfer, h.started, fresh, live); err != nil {
		return err
	}
	if err := h.currentLocked(ctx, true); err != nil {
		return err
	}
	if next, err := h.launch.chain.macOSTransfer(h.process.capture.Selection()); err != nil || next != transfer {
		return errors.Join(err, errors.New("macOS ordered receipt lost its original inherited transfer"))
	}
	h.transfer = transfer
	return nil
}

// Only the original typed observer can publish a prior reader. Retain just its
// physical identity for the OS retirement observation; do not relabel an
// execution heartbeat as an ordinary Local policy or receipt.
func (h *desktopMacOSNodeChainHost) capturedReaderLocked(ctx context.Context) (string, int, uint64, error) {
	if h.execution != nil {
		if err := mobilemtu.LockContext(ctx, &h.execution.mu); err != nil {
			return "", 0, 0, err
		}
		defer h.execution.mu.Unlock()
		if ready := h.execution.ready; ready != nil {
			return ready.InterfaceName, int(ready.InterfaceIndex), ready.Reader, nil
		}
		return "", 0, 0, nil
	}
	if err := mobilemtu.LockContext(ctx, &h.launch.chain.mu); err != nil {
		return "", 0, 0, err
	}
	defer h.launch.chain.mu.Unlock()
	if ready := h.launch.chain.ready; ready != nil {
		return ready.InterfaceName, int(ready.InterfaceIndex), ready.Reader, nil
	}
	return "", 0, 0, nil
}

func (owner *desktopNodeChainPlatformRuntime) current(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return errors.New("macOS ordered observation has no original host")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.proved {
		return h.readReadyLocked(ctx, false)
	}
	return h.currentLocked(ctx, true)
}

func (owner *desktopNodeChainPlatformRuntime) prove(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return errors.New("macOS ordered proof has no original host")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.currentLocked(ctx, true); err != nil {
		return err
	}
	raw, found := nativeMultihopOwners.Load(h.parent.app)
	bound, ok := raw.(*nativeMultihopRuntime)
	graph, graphFound := getActiveMultihopGraph(h.parent.app)
	if !found || !ok || bound == nil || bound.launch != h.launch || bound.selection.Native != h.launch.chain.selection.Native ||
		!graphFound || h.graph == nil || graph != *h.graph || graph != bound.graph ||
		h.execution == nil && graph.Execution != "local" || graph.ChainNodes != len(h.launch.chain.selection.Nodes) ||
		!sameDesktopMacOSExecutionProof(bound.execution, h.executionProof) ||
		h.bound != nil && h.bound != bound {
		return errors.New("macOS ordered proof lost its original complete bound graph")
	}
	if err := bound.execution.currentContext(ctx, h.launch, graph); err != nil {
		return err
	}
	h.bound, h.executionProof = bound, bound.execution
	if h.proved {
		return h.readReadyLocked(ctx, false)
	}
	if err := h.awaitReadyLocked(ctx, true); err != nil {
		return err
	}
	h.proved = true
	return nil
}

func (h *desktopMacOSNodeChainHost) awaitReadyLocked(ctx context.Context, fresh bool) error {
	budget, err := desktopNodeReadyBudget(h.launch)
	if err != nil {
		return err
	}
	proof, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := h.readReadyLocked(proof, fresh); err == nil {
			return nil
		}
		if err := h.currentLocked(proof, true); err != nil {
			return err
		}
		select {
		case <-proof.Done():
			return proof.Err()
		case <-h.process.joined:
			return errors.New("macOS ordered child exited before its fresh complete proof")
		case <-ticker.C:
		}
	}
}

func (owner *desktopNodeChainPlatformRuntime) activate(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return errors.New("macOS ordered activation has no original host")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	if !h.proved || h.activated || h.bound == nil {
		h.gate <- struct{}{}
		return errors.New("macOS ordered activation requires its unused complete native proof")
	}
	if err := h.readReadyLocked(ctx, false); err != nil {
		h.gate <- struct{}{}
		return err
	}
	a := h.parent.app
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		h.gate <- struct{}{}
		return err
	}
	if ctx.Err() != nil || h.operation.Err() != nil || a.checkCapturedConnectionOperationLocked(h.operation) != nil ||
		a.cmd != h.launch.command || a.closing || a.localController != h.parent.controller ||
		h.runtime.capture.sources.currentLocked(a) != nil {
		a.mu.Unlock()
		h.gate <- struct{}{}
		return errors.New("macOS ordered activation lost its original captured request")
	}
	h.activated = true
	a.mu.Unlock()
	h.gate <- struct{}{}
	return h.monitor(ctx)
}

func (h *desktopMacOSNodeChainHost) monitor(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.currentLocked(ctx, true); err != nil {
		return err
	}
	if !h.activated || h.monitorDone != nil {
		return errors.New("macOS ordered monitor requires its unused proved activation")
	}
	watch, cancel := context.WithCancel(h.parent.parent.ctx)
	done := make(chan struct{})
	h.monitorCancel, h.monitorDone = cancel, done
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		var once sync.Once
		end := func() { once.Do(func() { ticker.Stop(); cancel(); close(done) }) }
		defer end()
		a, launch := h.parent.app, h.launch
		observe := func() (error, bool) {
			before := h.mtuObservation.value.Load()
			call, stop := context.WithTimeout(watch, 2*time.Second)
			defer stop()
			err := h.runtime.current(call)
			return err, err != nil && h.mtuObservation.deferFailure(h, launch, before)
		}
		for {
			select {
			case <-watch.Done():
				return
			case <-ticker.C:
			}
			if !a.ownsConnectionRuntime(launch.command) {
				return
			}
			if err, cleanup := observe(); err == nil || cleanup {
				continue
			}
			release, current := a.claimRuntimeMonitorOperation(launch.command)
			if !current {
				return
			}
			if release == nil {
				continue
			}
			if !a.ownsConnectionRuntime(launch.command) {
				release()
				return
			}
			if err, cleanup := observe(); err == nil || cleanup {
				release()
				continue
			}
			end()
			invalidateDesktopMacOSNodeChainMeasurements(a, launch)
			err := a.stopModeWithIntent(true)
			message := "captured macOS ordered path retired; original protection is held"
			if err != nil {
				message += "; " + err.Error()
			}
			a.mu.Lock()
			if a.cmd == launch.command || a.cmd == nil && a.state.RouterID == launch.policyProfileID {
				a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", message
			}
			a.mu.Unlock()
			sessionTrackerFor(a).markRequestFailure(message)
			release()
			return
		}
	}()
	return nil
}

func (h *desktopMacOSNodeChainHost) stopMonitor(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	cancel, done := h.monitorCancel, h.monitorDone
	h.gate <- struct{}{}
	if done == nil {
		return nil
	}
	if cancel == nil {
		return errors.New("macOS ordered monitor lost its exact cancellation")
	}
	cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (h *desktopMacOSNodeChainHost) retireNative(ctx context.Context) error {
	if h.nativeRetired {
		return nil
	}
	h.retiring = true
	if h.process != nil && h.process.started.Load() {
		if h.process.NativeCleanup(ctx) != nil {
			if err := h.process.StopAndJoin(ctx); err != nil {
				return err
			}
		}
		if err := h.process.NativeCleanup(ctx); err != nil {
			return err
		}
	}
	h.nativeRetired = true
	return nil
}

func (h *desktopMacOSNodeChainHost) closeWithIntent(ctx context.Context, hold bool) error {
	return h.closeCaptured(ctx, hold, nil)
}

func (h *desktopMacOSNodeChainHost) closeCaptured(ctx context.Context, hold bool, captured *desktopMacOSNodeChainStopCapture) error {
	if h == nil {
		return nil
	}
	if err := h.stopMonitor(ctx); err != nil {
		return err
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.closed {
		return nil
	}
	if h.parent == nil || h.parent.session == nil || h.runtime == nil || h.runtime.host != h || h.launch == nil ||
		h.launch.chain == nil || h.launch.chain.platform != h.runtime || !h.launch.chain.hasPolicy() || h.launch.chain.policy != h.policy || h.launch.chain.socksPolicy != h.socksPolicy || h.launch.chain.connectPolicy != h.connectPolicy ||
		h.launch.chain.execution != h.execution ||
		h.baselineRun == nil {
		return errors.New("macOS ordered retirement lost its original typed host")
	}
	if h.execution != nil {
		if h.execution.original != h.launch.chain || h.execution.preparation != h.executionPreparation ||
			h.execution.physical != h.executionPhysical || h.executionPreparation == nil || h.executionPhysical == nil {
			return errors.New("macOS execution retirement lost its original preparation and physical owner")
		}
	} else if h.executionPreparation != nil || h.executionPhysical != nil {
		return errors.New("macOS ordered retirement acquired an unrelated execution owner")
	}
	if h.process != nil && (h.process.execution != h.executionPreparation || h.process.executionPhysical != h.executionPhysical) {
		return errors.New("macOS execution retirement changed its originally created child preparation")
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return err
	}
	if captured != nil {
		if captured.host != h {
			return errors.New("macOS ordered cleanup changed its pre-held Stop owner")
		}
		if err := captured.current(ctx); err != nil {
			return err
		}
	}
	if err := h.retireNative(ctx); err != nil {
		return err
	}
	if bridge := h.mtu; bridge != nil {
		native := bridge.nativeOwner()
		if native == nil || native.launch != h.launch {
			return errors.New("macOS ordered cleanup lost its retained original MTU lease")
		}
		if err := bridge.closeRetiredLocked(ctx); err != nil {
			return err
		}
		if h.mtu != nil && h.mtu != bridge {
			return errors.New("macOS ordered cleanup cannot clear a replacement MTU bridge")
		}
	}
	if h.baselineEntered && (!h.baselineRetired || !hold && h.baseline != nil && h.baseline.Phase == "held") {
		action := "release"
		if hold {
			action = "retire"
		}
		value, err := h.baselineRun(ctx, h.parent, h.selection, action, h.baseline, nil)
		if err != nil {
			return err
		}
		h.baseline, h.baselineRetired = value, true
	}
	if h.process != nil {
		if err := h.process.Close(ctx); err != nil {
			return err
		}
	}
	if !h.workspaceRetired {
		if h.stageDirectory != "" {
			if err := h.captureWorkspace(); err != nil {
				return err
			}
		}
		if err := cleanupDesktopNodeLaunch(h.launch); err != nil {
			return err
		}
		h.workspaceRetired = true
	}
	a, p := h.parent.app, h.parent.parent
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	if h.published && (a.localController != h.parent.controller || a.cmd != nil && a.cmd != h.launch.command ||
		captured != nil && (a.cmd != captured.command || a.connectionContext != captured.operation)) {
		a.mu.Unlock()
		return errors.New("macOS ordered retirement cannot clear a replacement controller or command")
	}
	if err := p.enter(ctx); err != nil {
		a.mu.Unlock()
		return err
	}
	if p.originalSession != h.parent.session || h.published && (h.parent.session.nodeChain != h.runtime || h.parent.session.external != nil || h.parent.session.candidatePrefix != nil) {
		p.gate <- struct{}{}
		a.mu.Unlock()
		return errors.New("macOS ordered retirement belongs to another retained session")
	}
	var bound *nativeMultihopRuntime
	if h.published {
		if raw, found := nativeMultihopOwners.Load(a); found {
			var ok bool
			bound, ok = raw.(*nativeMultihopRuntime)
			if !ok || bound == nil || bound.launch != h.launch || h.bound != nil && h.bound != bound ||
				!sameDesktopMacOSExecutionProof(bound.execution, h.executionProof) ||
				h.bound != nil && bound.execution != h.executionProof {
				p.gate <- struct{}{}
				a.mu.Unlock()
				return errors.New("macOS ordered retirement cannot erase a replacement graph owner")
			}
		} else if h.bound != nil {
			p.gate <- struct{}{}
			a.mu.Unlock()
			return errors.New("macOS ordered retirement lost its original bound registry")
		}
		graph, graphFound := getActiveMultihopGraph(a)
		if h.graph == nil && (graphFound || bound != nil) ||
			h.graph != nil && (!graphFound || graph != *h.graph || bound != nil && bound.graph != *h.graph) {
			p.gate <- struct{}{}
			a.mu.Unlock()
			return errors.New("macOS ordered retirement changed its original pre-bind graph receipt")
		}
		if bound != nil && !nativeMultihopOwners.CompareAndDelete(a, bound) {
			p.gate <- struct{}{}
			a.mu.Unlock()
			return errors.New("macOS ordered retirement changed its original bound owner")
		}
		if h.graph != nil && !activeMultihopGraphs.CompareAndDelete(a, *h.graph) {
			p.gate <- struct{}{}
			a.mu.Unlock()
			return errors.New("macOS ordered retirement cannot erase a replacement graph")
		}
		h.parent.session.nodeChain = nil
		a.cmd = nil
		a.state.Connected, a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode, a.state.Base = false, "off", "", "", ""
		a.state.Phase, a.state.LastError = "off", ""
	}
	delete(h.parent.session.dependents, h)
	if h.process != nil {
		delete(h.parent.session.dependents, h.process)
	}
	p.gate <- struct{}{}
	cover := a.daitaCancel
	if h.published {
		a.daitaCancel = nil
	}
	a.mu.Unlock()
	if h.published {
		if cover != nil {
			cover()
		}
		activeDNSRuntimeIdentities.CompareAndDelete(a, activeDNSRuntimeIdentity{ProfileID: h.launch.policyProfileID,
			RuntimeID: h.launch.mode, Config: filepath.Join(h.launch.directory, "sing-box.json")})
	}
	clear(h.launch.config)
	clear(h.launch.metadata)
	h.closed = true
	return nil
}

func (h *desktopMacOSNodeChainHost) Close(ctx context.Context) error {
	return h.closeWithIntent(ctx, false)
}

func (owner *desktopNodeChainPlatformRuntime) close(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return nil
	}
	return owner.host.Close(ctx)
}

// Replacement retirement keeps the existing empty deny baseline across the
// fresh saved-choice session. Ordinary Disconnect continues to use Close.
// The common restore owner must pass its exact captured execution adjunct.
func (owner *desktopNodeChainPlatformRuntime) closeForExecutionRestore(ctx context.Context,
	execution *desktopNodeChainExecutionLaunch) error {
	if owner == nil || !owner.registered || owner.host == nil || execution == nil ||
		owner.host.runtime != owner || owner.host.execution != execution || owner.host.launch == nil ||
		owner.host.launch.chain == nil || owner.host.launch.chain.execution != execution {
		return errors.New("macOS execution replacement retirement lost its original retained host")
	}
	return owner.host.closeWithIntent(ctx, true)
}

func (owner *desktopNodeChainPlatformRuntime) closePreparation(ctx context.Context, p *orderedCandidatePreparation) error {
	if owner == nil || owner.host == nil || p == nil || p.launch == nil || p.launch.chain == nil ||
		owner.host.launch != p.launch || p.launch.chain.platform != owner || p.launch.chain.preparation != p {
		return errors.New("macOS candidate disconnect lost its captured original host")
	}
	return owner.host.Close(ctx) // Existing disconnect preserves Always and releases on-connect.
}

func (owner *desktopNodeChainPlatformRuntime) processDone() <-chan struct{} {
	if owner == nil || owner.host == nil || owner.host.process == nil {
		return nil
	}
	return owner.host.process.joined
}

func invalidateDesktopMacOSNodeChainMeasurements(a *app, launch *desktopNodeLaunch) {
	a.mu.Lock()
	dns, latency := a.dnsMeasurements, a.latencyMeasurements
	a.mu.Unlock()
	if dns != nil {
		dns.mu.Lock()
		operation := dns.current
		if operation != nil && operation.snapshot.launch != launch {
			operation = nil
		}
		if dns.session == launch.mtuSession {
			dns.used = map[string]bool{}
			dns.cancelled = map[string]desktopDNSView{}
		}
		dns.mu.Unlock()
		if operation != nil {
			operation.invalidate()
		}
	}
	if latency != nil {
		latency.mu.Lock()
		operation := latency.current
		if operation != nil && operation.snapshot.launch != launch {
			operation = nil
		}
		if latency.session == launch.mtuSession {
			latency.used = map[string]bool{}
			latency.cancelled = map[string]desktopLatencyView{}
		}
		latency.mu.Unlock()
		if operation != nil {
			operation.invalidate()
		}
	}
}

type desktopMacOSNodeChainStopCapture struct {
	host      *desktopMacOSNodeChainHost
	command   *exec.Cmd
	operation context.Context
}

// The shared Stop path calls this before trying to hold the MTU lease. A
// partially entered PF/child attempt remains handled even before graph bind.
func (p *desktopMacOSParent) CaptureNodeChainStop(a *app) (desktopRetainedStopCapture, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if p == nil || a == nil {
		return nil, errors.New("macOS ordered Stop lost its original parent")
	}
	if err := p.enter(ctx); err != nil {
		return nil, err
	}
	s := p.originalSession
	if s == nil || s.parent != p {
		p.gate <- struct{}{}
		return nil, errors.New("macOS ordered Stop lost its original session")
	}
	owner, prefix := s.nodeChain, s.candidatePrefix
	p.gate <- struct{}{}
	if owner != nil && prefix != nil {
		return nil, errors.New("macOS Stop found conflicting retained native purposes")
	}
	if prefix != nil {
		return prefix.captureStop(ctx, a, p, s)
	}
	if owner == nil {
		return nil, nil
	}
	if owner.host == nil || owner.host.parent == nil || owner.host.parent.parent != p || owner.host.parent.session != s ||
		owner.host.parent.app != a || owner.host.runtime != owner {
		return nil, errors.New("macOS ordered Stop cannot replace its malformed retained owner")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	captured := &desktopMacOSNodeChainStopCapture{host: h, command: a.cmd, operation: a.connectionContext}
	a.mu.Unlock()
	return captured, captured.current(ctx)
}

func (captured *desktopMacOSNodeChainStopCapture) current(ctx context.Context) error {
	if captured == nil || captured.host == nil || captured.host.parent == nil || captured.host.runtime == nil {
		return errors.New("macOS ordered Stop has no captured original host")
	}
	h := captured.host
	if !h.published || h.closed || h.launch == nil || h.launch.chain == nil || h.launch.chain.platform != h.runtime {
		return errors.New("macOS ordered Stop lost its retained original launch")
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return err
	}
	a, p := h.parent.app, h.parent.parent
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if a.localController != h.parent.controller || a.connectionContext != captured.operation || a.cmd != captured.command ||
		captured.command != h.launch.command {
		return errors.New("macOS ordered Stop belongs to a replacement command or operation")
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if p.originalSession != h.parent.session || h.parent.session.nodeChain != h.runtime || h.parent.session.external != nil || h.parent.session.candidatePrefix != nil {
		return errors.New("macOS ordered Stop belongs to another retained session")
	}
	return ctx.Err()
}

func (captured *desktopMacOSNodeChainStopCapture) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	if captured == nil || command != captured.command {
		return errors.New("macOS ordered Stop changed its MTU-held original command")
	}
	return captured.host.closeCaptured(ctx, !disconnect, captured)
}

// Only explicit teardown may use this after a failed MTU hold. The outer lease
// and command were captured before that hold; never select a new lease here.
func prepareDesktopMacOSNodeChainMTUStop(ctx context.Context, a *app, command *exec.Cmd, operation context.Context,
	outer *mtuLiveOwner, terminal bool, failedHold error) (bool, error) {
	if outer == nil {
		return false, nil
	}
	native, raw := outer.kernel.(*desktopNodeMTUOwner)
	var bridge desktopMacOSNodeChainMTUBridge
	if !raw {
		var ok bool
		bridge, ok = outer.kernel.(desktopMacOSNodeChainMTUBridge)
		if !ok {
			return false, nil
		}
		native = bridge.nativeOwner()
	}
	if native == nil || native.launch == nil || native.launch.chain == nil || native.launch.chain.platform == nil {
		if bridge != nil {
			return true, errors.New("macOS ordered MTU bridge lost its original native owner")
		}
		return false, nil
	}
	owner := native.launch.chain.platform
	if owner.host == nil || owner.host.runtime != owner || owner.host.launch != native.launch {
		return true, errors.New("macOS ordered MTU teardown lost its exact retained native owner")
	}
	h := owner.host
	if ctx == nil || ctx.Err() != nil || a == nil || command == nil || failedHold == nil ||
		errors.Is(failedHold, context.Canceled) || errors.Is(failedHold, context.DeadlineExceeded) || h.parent == nil || h.parent.app != a ||
		h.process == nil || !h.process.started.Load() || h.process.command != command {
		return true, errors.New("macOS ordered MTU teardown lost its bounded original capture")
	}
	lock := mtuRetestLockFor(a)
	if !lock.TryLock() {
		return true, errors.New("macOS ordered MTU teardown still waits for its original Retest")
	}
	defer lock.Unlock()
	outer.mu.Lock()
	defer outer.mu.Unlock()
	current := func() error {
		if !outer.stopped || outer.closed || outer.a != a || outer.command != command ||
			bridge == nil && outer.kernel != native || bridge != nil && (any(outer.kernel) != any(bridge) || h.mtu != bridge || bridge.nativeOwner() != native) ||
			h.mtu != nil && h.mtu.nativeOwner() != native || h.launch.command != command || h.launch.chain.platform != owner {
			return errors.New("macOS ordered MTU teardown changed its drained original lease")
		}
		if err := h.parent.cleanupCurrent(ctx); err != nil {
			return err
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		raw, found := mtuLiveOwners.Load(a)
		if !found || raw != outer || a.cmd != command || a.connectionContext != operation || a.closing != terminal ||
			a.localController != h.parent.controller || a.state.RouterID != h.launch.policyProfileID || a.state.RuntimeMode != h.launch.mode {
			return errors.New("macOS ordered MTU teardown belongs to a replacement application")
		}
		p := h.parent.parent
		if err := p.enter(ctx); err != nil {
			return err
		}
		defer func() { p.gate <- struct{}{} }()
		if p.originalSession != h.parent.session || h.parent.session.nodeChain != owner || h.parent.session.external != nil || h.parent.session.candidatePrefix != nil {
			return errors.New("macOS ordered MTU teardown belongs to a replacement session")
		}
		return nil
	}
	if err := h.enter(ctx); err != nil {
		return true, err
	}
	initial := current()
	h.gate <- struct{}{}
	if initial != nil {
		return true, initial
	}
	if err := h.stopMonitor(ctx); err != nil {
		return true, err
	}
	if err := h.enter(ctx); err != nil {
		return true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := current(); err != nil {
		return true, err
	}
	if err := h.retireNative(ctx); err != nil {
		return true, err
	}
	// Keep PF, workspace and original publication for the pre-held Stop capture.
	// The ordinary MTU owner still requires the child's exact stopped receipt.
	if stopped, err := readDesktopNodeStoppedContext(ctx, h.launch); err != nil || !stopped {
		return true, errors.Join(err, errors.New("macOS ordered MTU teardown lacks its exact native stopped receipt"))
	}
	if err := current(); err != nil {
		return true, err
	}
	a.mu.Lock()
	if a.cmd == command && a.connectionContext == operation {
		a.state.Connected, a.state.Phase = false, "stopping"
	}
	a.mu.Unlock()
	return true, nil
}
