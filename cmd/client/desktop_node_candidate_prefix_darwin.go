//go:build darwin

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// This retained host never publishes an active graph or ordinary Ready. Its
// process and PF selection belong to the closed selected-prefix family, while
// full saved source authority stays with the original preparation.
type desktopNodeCandidatePrefixPlatformRuntime struct {
	capture    *desktopNodeChainHostCapture
	host       *desktopMacOSCandidatePrefixHost
	registered bool
}

type desktopMacOSCandidatePrefixHost struct {
	parent                                                             *desktopMacOSSessionCapture
	runtime                                                            *desktopNodeCandidatePrefixPlatformRuntime
	launch                                                             *desktopNodeLaunch
	policy                                                             *mobilemultihop.DesktopNodeCandidatePreparationPolicy
	selection                                                          desktopMacOSCandidatePrefixSelection
	operation                                                          context.Context
	gate                                                               chan struct{}
	process                                                            *desktopMacOSProcess
	baseline                                                           *desktopMacOSCandidatePrefixReceipt
	baselineRun                                                        desktopMacOSCandidatePrefixBaselineRunner
	started                                                            time.Time
	transfer                                                           string
	entered, staged, published, prepared, baselineEntered              bool
	retiring, nativeRetired, baselineRetired, workspaceRetired, closed bool
	stageDirectory                                                     string
	stageInfo                                                          os.FileInfo
}

func (capture *desktopNodeChainPlatformCapture) prepareCandidatePrefixForPurpose(ctx context.Context, owner *desktopNodeChainHostCapture,
	selection multihopSelection, purpose *orderedCandidatePreparation) (launch *desktopNodeLaunch, image string, failure error) {
	if capture == nil || capture.parent == nil || owner == nil || owner.platform != capture || owner.windows != nil ||
		owner.sources == nil || owner.app != capture.parent.app || selection.Native == nil || selection.Native.chain == nil ||
		selection.Native.chain.host != owner || owner.sources.selection.Native != selection.Native {
		return nil, "", errors.New("macOS candidate prefix preparation changed its original full source and parent")
	}
	if err := owner.current(ctx); err != nil {
		return nil, "", err
	}
	image, err := capture.verify(ctx, macOSOwnedControllerRoot)
	if err != nil || image != macosprocess.EnginePath {
		return nil, "", errors.Join(err, errors.New("macOS candidate prefix preparation verified another installed image"))
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
	launch, err = newDesktopNodeCandidatePrefixLaunchForPurpose(ctx, selection, session, "darwin", purpose)
	if err != nil {
		return nil, "", err
	}
	launch.candidatePrefix.capture = owner
	meta := launch.candidatePrefix.policy.Metadata()
	runtime := &desktopNodeCandidatePrefixPlatformRuntime{capture: owner}
	h := &desktopMacOSCandidatePrefixHost{parent: capture.parent, runtime: runtime, launch: launch, policy: launch.candidatePrefix.policy,
		operation: operation, gate: make(chan struct{}, 1), baselineRun: runDesktopMacOSCandidatePrefixBaseline,
		selection: desktopMacOSCandidatePrefixSelection{Schema: 2, Family: macosprocess.CandidatePrefixFamily, ProfileID: meta.PolicyProfileID,
			Session: meta.SessionID, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy}}
	runtime.host, launch.candidatePrefix.platform = h, runtime
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

func (h *desktopMacOSCandidatePrefixHost) enter(ctx context.Context) error {
	if h == nil || ctx == nil || h.gate == nil {
		return errors.New("macOS candidate prefix host has no bounded original owner")
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

func (owner *desktopNodeCandidatePrefixPlatformRuntime) guard(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if owner == nil || !owner.registered || owner.host == nil || owner.capture == nil || owner.capture.app != a ||
		owner.host.launch != launch || launch == nil || launch.candidatePrefix == nil || launch.candidatePrefix.platform != owner {
		return errors.New("macOS candidate prefix transition lost its retained original host")
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
		return errors.New("macOS candidate prefix transition lost its cleanup registration")
	}
	return nil
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) stage(ctx context.Context) error {
	if owner == nil || !owner.registered || owner.host == nil {
		return errors.New("macOS candidate prefix staging lost its retained original host")
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
		return errors.New("macOS candidate prefix stage has already been consumed")
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
		{"node-candidate-prefix-source.json", []byte(h.launch.candidatePrefix.input)},
		{"sing-box.json", h.launch.config},
	} {
		if err := writeDesktopRuntimeFile(h.launch, input.name, input.body, false); err != nil {
			return err
		}
	}
	h.staged = true
	return h.currentLocked(ctx, false)
}

func (h *desktopMacOSCandidatePrefixHost) captureWorkspace() error {
	if h == nil || h.launch == nil || h.stageDirectory == "" || h.stageInfo == nil || !h.stageInfo.IsDir() ||
		h.stageInfo.Mode()&os.ModeSymlink != 0 || h.stageInfo.Mode().Perm()&0077 != 0 {
		return errors.New("macOS candidate prefix staging has no original private directory witness")
	}
	current, err := os.Lstat(h.stageDirectory)
	if err != nil || !os.SameFile(current, h.stageInfo) || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		current.Mode().Perm()&0077 != 0 {
		return errors.Join(err, errors.New("macOS candidate prefix staging cannot recapture a missing or replacement directory"))
	}
	if h.launch.directory != "" && h.launch.directory != h.stageDirectory ||
		h.launch.directoryInfo != nil && !os.SameFile(h.launch.directoryInfo, h.stageInfo) {
		return errors.New("macOS candidate prefix staging changed its original workspace witness")
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
		return errors.New("macOS candidate prefix staging opened a replacement directory")
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

func (owner *desktopNodeCandidatePrefixPlatformRuntime) start(ctx context.Context) error {
	if owner == nil || !owner.registered || owner.host == nil || owner.capture == nil || owner.capture.platform == nil {
		return errors.New("macOS candidate prefix startup lost its original session")
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
		return errors.New("macOS candidate prefix startup requires its unused exact private stage")
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
	if p.originalSession != h.parent.session || h.parent.session.external != nil ||
		h.parent.session.candidatePrefix != nil || h.parent.session.nodeChain != nil || a.cmd != nil || a.state.Connected || legacy || external || graph ||
		a.checkCapturedConnectionOperationLocked(h.operation) != nil || h.runtime.capture.sources.currentLocked(a) != nil {
		p.gate <- struct{}{}
		a.mu.Unlock()
		return errors.New("macOS candidate prefix startup cannot replace an unjoined predecessor")
	}
	h.entered, h.published = true, true
	h.parent.session.candidatePrefix = owner
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode = "multihop", "multihop", h.launch.mode
	a.state.RouterID, a.state.Base = h.launch.policyProfileID, h.launch.candidatePrefix.selection.Base
	a.state.Connected, a.state.Phase, a.state.LastError = false, "candidate:testing", ""
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
	scope := macosprocess.Scope{Family: macosprocess.CandidatePrefixFamily, Session: h.selection.Session,
		Source: h.selection.Source, Config: h.selection.Config, Workspace: h.launch.directory}
	h.started = time.Now()
	h.process, err = startDesktopMacOSProcessWithVerifier(ctx, h.parent, scope, owner.capture.platform.verify)
	if err != nil {
		return err
	}
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	if a.cmd != nil || a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.localController != h.parent.controller {
		a.mu.Unlock()
		return errors.New("macOS candidate prefix created child lost its original application")
	}
	h.launch.command, a.cmd = h.process.command, h.process.command
	a.mu.Unlock()
	return h.currentLocked(ctx, true)
}

func (h *desktopMacOSCandidatePrefixHost) retireNative(ctx context.Context) error {
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

func (h *desktopMacOSCandidatePrefixHost) Close(ctx context.Context) error {
	return h.closeWithIntent(ctx, false)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) close(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return nil
	}
	return owner.host.Close(ctx)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) closePreparation(ctx context.Context, p *orderedCandidatePreparation) error {
	if owner == nil || owner.host == nil || p == nil || p.launch == nil || p.launch.candidatePrefix == nil ||
		owner.host.launch != p.launch || p.launch.candidatePrefix.platform != owner || p.launch.candidatePrefix.preparation != p {
		return errors.New("macOS candidate disconnect lost its captured original host")
	}
	return owner.host.Close(ctx) // Existing disconnect preserves Always and releases on-connect.
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) processDone() <-chan struct{} {
	if owner == nil || owner.host == nil || owner.host.process == nil {
		return nil
	}
	return owner.host.process.joined
}

func (h *desktopMacOSCandidatePrefixHost) currentLocked(ctx context.Context, running bool) error {
	if h == nil || h.parent == nil || h.parent.session == nil || h.runtime == nil || h.runtime.host != h ||
		h.runtime.capture == nil || h.runtime.capture.platform == nil || h.runtime.capture.platform.parent != h.parent ||
		h.launch == nil || h.launch.candidatePrefix == nil || h.launch.candidatePrefix.platform != h.runtime ||
		h.launch.candidatePrefix.capture != h.runtime.capture || h.policy == nil || h.launch.candidatePrefix.policy != h.policy ||
		h.launch.ownedNode != nil || h.operation == nil || h.baselineRun == nil || h.retiring || h.closed ||
		h.launch.root != macOSOwnedControllerRoot {
		return errors.New("macOS candidate prefix lost its unique original policy and parent")
	}
	if err := h.runtime.capture.current(ctx); err != nil {
		return err
	}
	if err := validateDesktopNodeCandidatePrefixLaunch(ctx, h.launch); err != nil {
		return err
	}
	meta := h.policy.Metadata()
	expected := desktopMacOSCandidatePrefixSelection{Schema: 2, Family: macosprocess.CandidatePrefixFamily, ProfileID: meta.PolicyProfileID,
		Session: meta.SessionID, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy}
	if meta.TargetOS != "darwin" || h.selection != expected || !h.selection.valid() || meta.ApplicationOpen || meta.DNSOpen {
		return errors.New("macOS candidate prefix changed its closed protection selection or saved control")
	}
	a := h.parent.app
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	valid := !a.closing && a.localController == h.parent.controller && h.operation.Err() == nil &&
		a.checkCapturedConnectionOperationLocked(h.operation) == nil && a.connectionCancelIntent != h.operation && !a.state.Connected
	if _, err := orderedCandidateLaunchPurposeLocked(a, h.launch); err != nil {
		valid = false
	}
	if h.published {
		valid = valid && a.cmd == h.launch.command && a.state.RouterID == meta.PolicyProfileID &&
			a.state.Mode == "multihop" && a.state.LogicalMode == "multihop" && a.state.RuntimeMode == meta.Mode
	}
	a.mu.Unlock()
	if !valid {
		return errors.New("macOS candidate prefix lost its original private testing purpose")
	}
	if _, found := nativeMultihopOwners.Load(a); found {
		return errors.New("macOS candidate prefix cannot adopt an ordinary native graph")
	}
	if _, found := getActiveMultihopGraph(a); found {
		return errors.New("macOS candidate prefix cannot publish a connected graph")
	}
	if h.published {
		p := h.parent.parent
		if err := p.enter(ctx); err != nil {
			return err
		}
		_, retained := h.parent.session.dependents[h]
		selected := p.originalSession == h.parent.session && h.parent.session.candidatePrefix == h.runtime &&
			h.parent.session.nodeChain == nil && h.parent.session.external == nil && retained
		p.gate <- struct{}{}
		if !selected {
			return errors.New("macOS candidate prefix belongs to a replaced retained session")
		}
	}
	if running {
		scope := macosprocess.Scope{Family: macosprocess.CandidatePrefixFamily, Session: h.selection.Session, Source: h.selection.Source, Config: h.selection.Config, Workspace: h.launch.directory}
		if !h.published || h.process == nil || h.process.parent != h.parent || h.process.capture == nil || h.process.scope != scope ||
			h.process.command != h.launch.command || h.baseline == nil || h.baseline.Phase != "active" || h.started.IsZero() {
			return errors.New("macOS candidate prefix has no admitted original child and PF receipt")
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

func (h *desktopMacOSCandidatePrefixHost) readReadyLocked(ctx context.Context, fresh bool) error {
	if err := h.currentLocked(ctx, true); err != nil {
		return err
	}
	transfer, err := macosprocess.CandidatePrefixTransferSHA256(h.process.capture.Selection())
	if err != nil || h.transfer != "" && h.transfer != transfer {
		return errors.Join(err, errors.New("macOS candidate prefix changed its original inherited transfer"))
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
	// The prefix purpose has no live MTU optimizer or replacement-reader path.
	// The strict private receipt requires one unchanged original reader/utun.
	if _, err := readDesktopNodeCandidatePrefixReadyContext(ctx, h.launch, transfer, h.started, fresh, live); err != nil {
		return err
	}
	if err := h.currentLocked(ctx, true); err != nil {
		return err
	}
	if next, err := macosprocess.CandidatePrefixTransferSHA256(h.process.capture.Selection()); err != nil || next != transfer {
		return errors.Join(err, errors.New("macOS candidate prefix lost its original transfer after readback"))
	}
	h.transfer = transfer
	return nil
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) current(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return errors.New("macOS candidate prefix observation lost its original host")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.prepared {
		return h.readReadyLocked(ctx, false)
	}
	return h.currentLocked(ctx, true)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) activate(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return errors.New("macOS candidate prefix preparation lost its original host")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.prepared {
		return h.readReadyLocked(ctx, false)
	}
	budget, err := desktopCandidatePrefixReadyBudget(h.launch)
	if err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := h.currentLocked(call, true); err != nil {
			return err
		}
		if _, err := readDesktopRuntimeFileContext(call, h.launch, "node-mtu-status.json", 16384); err == nil {
			err = h.readReadyLocked(call, true)
			if err == nil {
				h.prepared = true
				return call.Err()
			}
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-call.Done():
			return call.Err()
		case <-h.process.joined:
			return errors.New("original macOS prefix child exited before its private proof")
		case <-ticker.C:
		}
	}
}

func (h *desktopMacOSCandidatePrefixHost) closeWithIntent(ctx context.Context, hold bool) error {
	return h.closeCaptured(ctx, hold, nil)
}

func (h *desktopMacOSCandidatePrefixHost) closeCaptured(ctx context.Context, hold bool, captured *desktopMacOSCandidatePrefixStopCapture) error {
	if h == nil {
		return nil
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.closed {
		return nil
	}
	if h.parent == nil || h.parent.session == nil || h.runtime == nil || h.runtime.host != h || h.launch == nil ||
		h.launch.candidatePrefix == nil || h.launch.candidatePrefix.platform != h.runtime || h.policy == nil ||
		h.launch.candidatePrefix.policy != h.policy || h.baselineRun == nil {
		return errors.New("macOS candidate prefix retirement lost its original typed host")
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return err
	}
	if captured != nil {
		if captured.host != h {
			return errors.New("macOS candidate prefix cleanup changed its captured Stop owner")
		}
		if err := captured.current(ctx); err != nil {
			return err
		}
	}
	// NativeCleanup is the original authenticated Stop plus successful child
	// join. A timeout, forced process Close or absent slot never certifies DOWN.
	if err := h.retireNative(ctx); err != nil {
		return err
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
	defer a.mu.Unlock()
	if h.published && (a.localController != h.parent.controller || a.cmd != nil && a.cmd != h.launch.command ||
		captured != nil && (a.cmd != captured.command || a.connectionContext != captured.operation)) {
		return errors.New("macOS candidate prefix retirement cannot clear a replacement controller or command")
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if p.originalSession != h.parent.session || h.published && (h.parent.session.candidatePrefix != h.runtime ||
		h.parent.session.nodeChain != nil || h.parent.session.external != nil) {
		return errors.New("macOS candidate prefix retirement belongs to another retained session")
	}
	if h.published {
		if _, found := nativeMultihopOwners.Load(a); found {
			return errors.New("macOS candidate prefix retirement cannot erase a native graph")
		}
		if _, found := getActiveMultihopGraph(a); found {
			return errors.New("macOS candidate prefix retirement cannot erase a connected graph")
		}
		h.parent.session.candidatePrefix = nil
		a.cmd = nil
		a.state.Connected, a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode, a.state.Base = false, "off", "", "", ""
		a.state.Phase, a.state.LastError = "off", ""
	}
	delete(h.parent.session.dependents, h)
	if h.process != nil {
		delete(h.parent.session.dependents, h.process)
	}
	clear(h.launch.config)
	clear(h.launch.metadata)
	h.closed = true
	return nil
}

type desktopMacOSCandidatePrefixStopCapture struct {
	host      *desktopMacOSCandidatePrefixHost
	command   *exec.Cmd
	operation context.Context
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) captureStop(ctx context.Context, a *app, p *desktopMacOSParent, s *desktopMacOSSession) (desktopRetainedStopCapture, error) {
	if owner == nil || owner.host == nil || owner.host.parent == nil || owner.host.parent.parent != p ||
		owner.host.parent.session != s || owner.host.parent.app != a || owner.host.runtime != owner {
		return nil, errors.New("macOS candidate prefix Stop cannot replace its malformed retained owner")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	captured := &desktopMacOSCandidatePrefixStopCapture{host: h, command: a.cmd, operation: a.connectionContext}
	a.mu.Unlock()
	return captured, captured.current(ctx)
}

func (captured *desktopMacOSCandidatePrefixStopCapture) current(ctx context.Context) error {
	if captured == nil || captured.host == nil || captured.host.parent == nil || captured.host.runtime == nil {
		return errors.New("macOS candidate prefix Stop has no original host")
	}
	h := captured.host
	if !h.published || h.closed || h.launch == nil || h.launch.candidatePrefix == nil || h.launch.candidatePrefix.platform != h.runtime {
		return errors.New("macOS candidate prefix Stop lost its retained original launch")
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return err
	}
	a, p := h.parent.app, h.parent.parent
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if a.localController != h.parent.controller || a.connectionContext != captured.operation || a.cmd != captured.command || captured.command != h.launch.command {
		return errors.New("macOS candidate prefix Stop belongs to a replacement command or operation")
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if p.originalSession != h.parent.session || h.parent.session.candidatePrefix != h.runtime || h.parent.session.nodeChain != nil || h.parent.session.external != nil {
		return errors.New("macOS candidate prefix Stop belongs to another retained session")
	}
	return ctx.Err()
}

func (captured *desktopMacOSCandidatePrefixStopCapture) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	if captured == nil || command != captured.command {
		return errors.New("macOS candidate prefix Stop changed its captured original command")
	}
	return captured.host.closeCaptured(ctx, !disconnect, captured)
}
