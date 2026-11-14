//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
	"sync/atomic"
	"time"
)

type desktopNodeCandidatePrefixPlatformRuntime struct {
	capture    *desktopNodeChainHostCapture
	host       *desktopLinuxNodeHost
	session    *desktopLinuxNodeSession
	registered bool
	prepared   bool // protected by original host.gate; never ordinary activation
}

func (capture *desktopNodeChainPlatformCapture) prepareCandidatePrefixForPurpose(ctx context.Context, owner *desktopNodeChainHostCapture,
	selection multihopSelection, purpose *orderedCandidatePreparation) (launch *desktopNodeLaunch, image string, failure error) {
	if owner == nil || owner.platform != capture || owner.windows != nil || owner.sources == nil ||
		selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.host != owner ||
		owner.sources.selection.Native != selection.Native || owner.app != capture.parent.app {
		return nil, "", errors.New("Linux ordered preparation changed its original source and controller")
	}
	if err := owner.current(ctx); err != nil {
		return nil, "", err
	}
	image, err := capture.verify(ctx, linuxOwnedControllerRoot)
	if err != nil || filepath.Clean(image) != filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()) {
		return nil, "", errors.Join(err, errors.New("Linux ordered preparation verified another installed image"))
	}
	a := owner.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, "", err
	}
	operation := a.connectionContext
	err = a.checkCapturedConnectionOperationLocked(operation)
	a.mu.Unlock()
	if err != nil {
		return nil, "", err
	}
	sessionID, err := randomHex(16)
	if err != nil {
		return nil, "", err
	}
	launch, err = newDesktopNodeCandidatePrefixLaunchForPurpose(ctx, selection, sessionID, "linux", purpose)
	if err != nil {
		return nil, "", err
	}
	launch.candidatePrefix.capture = owner
	_, meta, physicalCapture, err := launch.candidatePrefix.policy.PhysicalReadValidated()
	if err != nil {
		return launch, "", err
	}
	physical, err := captureDesktopLinuxRunningPath(physicalCapture.PhysicalRoots, physicalCapture.IPv6Mode)
	if err != nil {
		return launch, "", err
	}
	h := &desktopLinuxNodeHost{gate: make(chan struct{}, 1), parent: capture.parent, operation: operation,
		candidatePrefix: launch.candidatePrefix.policy, launch: launch, source: []byte(launch.candidatePrefix.input), network: owner.network,
		revision: desktopOwnedNodeProfileToken(selection.Control), options: owner.sources.options, savedOptions: owner.sources.options,
		physical: physical, monitor: &atomic.Pointer[desktopLinuxNodeMonitor]{},
		selection: linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
			ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}}
	runtime := &desktopNodeCandidatePrefixPlatformRuntime{capture: owner, host: h}
	launch.candidatePrefix.platform = runtime
	if err := h.current(ctx); err != nil {
		return launch, "", err
	}
	p := capture.parent.parent
	select {
	case <-ctx.Done():
		return launch, "", ctx.Err()
	case <-p.gate:
	}
	if err := p.currentLocked(true); err != nil {
		p.gate <- struct{}{}
		return launch, "", err
	}
	if p.dependents == nil {
		p.dependents = make(map[ownedDesktopNodeParent]struct{})
	}
	p.dependents[h] = struct{}{}
	p.gate <- struct{}{}
	h.gate <- struct{}{}
	runtime.registered = true
	runtime.session, err = captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return launch, "", err
	}
	if err := h.CheckLegacyTransition(ctx); err != nil {
		return launch, "", err
	}
	return launch, image, h.current(ctx)
}

func (h *desktopLinuxNodeHost) currentCandidatePrefix(ctx context.Context) error {
	if h == nil || ctx == nil || ctx.Err() != nil || h.closing || h.closed || h.operation == nil || h.parent == nil ||
		h.candidatePrefix == nil || (h.chain != nil || h.socksChain != nil) || h.policy != nil || h.imported != nil || h.external != nil || h.launch == nil || h.launch.candidatePrefix == nil ||
		h.launch.candidatePrefix.policy != h.candidatePrefix || h.launch.candidatePrefix.platform == nil || h.launch.ownedNode != nil {
		return errors.New("Linux ordered host lost its unique concrete policy")
	}
	runtime, ok := h.launch.candidatePrefix.platform.(*desktopNodeCandidatePrefixPlatformRuntime)
	if !ok || runtime == nil {
		return errors.New("Linux prefix changed its concrete platform owner")
	}
	if runtime.host != h || runtime.capture == nil || h.launch.candidatePrefix.capture != runtime.capture ||
		h.launch.candidatePrefix.selection.Native.chain.host != runtime.capture || runtime.capture.platform == nil || runtime.capture.platform.parent != h.parent ||
		runtime.capture.app != h.parent.app || runtime.capture.sources == nil ||
		runtime.capture.sources.selection.Native != h.launch.candidatePrefix.selection.Native {
		return errors.New("Linux ordered host substituted its captured parent or full source")
	}
	if err := runtime.capture.current(ctx); err != nil {
		return err
	}
	if err := validateDesktopNodeCandidatePrefixLaunch(ctx, h.launch); err != nil {
		return err
	}
	meta := h.candidatePrefix.Metadata()
	wanted := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
		ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	if meta.TargetOS != "linux" || meta.PolicyProfileID != h.launch.policyProfileID || h.selection != wanted || string(h.source) != h.launch.candidatePrefix.input || h.network != runtime.capture.network {
		return errors.New("Linux ordered host changed its native protection or projected source")
	}
	if h.activation != nil || h.ready != nil || h.proof != nil || h.operation.Err() != nil {
		return errors.New("Linux candidate prefix cannot adopt ordinary activation or lose its original finite lifetime")
	}
	a := h.parent.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.connectionCancelIntent == h.operation {
		return errConnectionOperationCancelled
	}
	if h.process != nil && (a.cmd != h.process.command || a.state.RouterID != h.launch.policyProfileID || a.state.RuntimeMode != meta.Mode || a.state.Connected) {
		return errors.New("Linux candidate prefix belongs to a replaced native process or Home source")
	}
	if _, err := orderedCandidateLaunchPurposeLocked(a, h.launch); err != nil {
		return err
	}
	return runtime.capture.sources.currentLocked(a)
}

func newDesktopLinuxCandidatePrefixTransaction(ctx context.Context, h *desktopLinuxNodeHost, journal *desktopLinuxNodeJournal,
	predecessor *desktopLinuxNodeTransaction) (*desktopLinuxNodeTransaction, error) {
	if h == nil || h.candidatePrefix == nil || h.launch == nil || h.launch.candidatePrefix == nil || h.launch.candidatePrefix.platform == nil ||
		h.process == nil || !h.process.Started() || journal == nil || !sameDesktopLinuxParentCapture(h.parent, journal.parent) ||
		!sameDesktopLinuxParentCapture(h.parent, h.process.parent) {
		return nil, errors.New("Linux ordered transaction lost its original process and journal")
	}
	if err := h.current(ctx); err != nil {
		return nil, err
	}
	t := &desktopLinuxNodeTransaction{gate: make(chan struct{}, 1), parent: h.parent, journal: journal, process: h.process,
		candidatePrefix: h.candidatePrefix, prefixSources: h.launch.candidatePrefix.capture.sources, mode: h.launch.mode, operation: h.operation,
		startup: ctx, selection: h.selection, profileID: h.launch.policyProfileID, revision: h.revision, network: h.network,
		options: h.options, savedOptions: h.savedOptions, predecessor: predecessor}
	return finishDesktopLinuxNodeTransaction(t)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) guard(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if owner == nil || !owner.registered || owner.host == nil || owner.host.launch != launch || owner.session == nil ||
		owner.capture == nil || owner.capture.app != a || launch.candidatePrefix == nil || launch.candidatePrefix.platform != owner ||
		!sameDesktopLinuxParentCapture(owner.session.parent, owner.host.parent) {
		return errors.New("Linux ordered transition lost its original retained host")
	}
	if err := owner.session.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.session.gate <- struct{}{} }()
	if err := owner.session.currentLocked(ctx); err != nil {
		return err
	}
	p := owner.host.parent.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	_, retained := p.dependents[owner.host]
	p.gate <- struct{}{}
	if !retained {
		return errors.New("Linux ordered transition lost original cleanup registration")
	}
	return owner.host.CheckLegacyTransition(ctx)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) stage(ctx context.Context) error {
	if owner == nil || owner.host == nil || owner.session == nil || !owner.registered {
		return errors.New("Linux ordered staging lost its retained session")
	}
	return owner.host.Stage(ctx)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) start(ctx context.Context) error {
	if owner == nil || owner.session == nil || owner.host == nil || owner.capture == nil || owner.capture.platform == nil {
		return errors.New("Linux ordered start lost its original session")
	}
	return owner.session.startWithVerifier(ctx, owner.host, os.Environ(), owner.capture.platform.verify)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) current(ctx context.Context) error {
	if owner == nil || owner.session == nil || owner.host == nil {
		return errors.New("Linux ordered observation lost its retained session")
	}
	s, h := owner.session, owner.host
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if s.active != h || s.journal == nil || h.transaction == nil || h.transaction.journal != s.journal {
		return errors.New("Linux ordered observation belongs to a replaced native session")
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.runningPolicyLocked(ctx); err != nil {
		return err
	}
	if owner.prepared {
		_, _, err := h.readCandidatePrefixReadyLocked(ctx, false)
		return err
	}
	return nil
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) activate(ctx context.Context) error {
	if owner == nil || owner.host == nil || owner.session == nil {
		return errors.New("Linux prefix preparation has no original session")
	}
	if err := owner.host.waitCandidatePrefixReady(ctx); err != nil {
		return err
	}
	return owner.current(ctx)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) close(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return nil
	}
	h := owner.host
	if !owner.registered {
		if h.process != nil || h.launch.command != nil || h.stageEntered {
			return errors.New("unregistered Linux ordered host retained an entered runtime")
		}
		clear(h.source)
		clear(h.launch.config)
		clear(h.launch.metadata)
		return nil
	}
	if owner.session != nil {
		if err := owner.session.enter(ctx); err != nil {
			return err
		}
		selected := owner.session.active == h
		owner.session.gate <- struct{}{}
		if selected {
			return owner.session.Retire(ctx, h, false)
		}
	}
	return h.Close(ctx)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) closePreparation(ctx context.Context, p *orderedCandidatePreparation) error {
	if owner == nil || owner.host == nil || p == nil || p.launch == nil || p.launch.candidatePrefix == nil ||
		owner.host.launch != p.launch || p.launch.candidatePrefix.platform != owner || p.launch.candidatePrefix.preparation != p {
		return errors.New("Linux candidate disconnect lost its captured original host")
	}
	h := owner.host
	if !owner.registered {
		return owner.close(ctx)
	}
	if owner.session != nil {
		if err := owner.session.enter(ctx); err != nil {
			return err
		}
		selected := owner.session.active == h
		owner.session.gate <- struct{}{}
		if selected {
			return owner.session.Retire(ctx, h, true)
		}
	}
	if err := h.Retire(ctx, true); err != nil {
		return err
	}
	return h.Close(ctx)
}

func (owner *desktopNodeCandidatePrefixPlatformRuntime) processDone() <-chan struct{} {
	if owner == nil || owner.host == nil || owner.host.process == nil {
		return nil
	}
	return owner.host.process.joined
}

func (h *desktopLinuxNodeHost) readCandidatePrefixReadyLocked(ctx context.Context, fresh bool) (mobilemultihop.DesktopNodeCandidatePreparationReadyRecord, desktopNodeMTURecord, error) {
	var empty mobilemultihop.DesktopNodeCandidatePreparationReadyRecord
	var noLive desktopNodeMTURecord
	if h == nil || h.candidatePrefix == nil || h.launch == nil || h.launch.candidatePrefix == nil {
		return empty, noLive, errors.New("Linux prefix readback lost its concrete host")
	}
	if err := h.runningPolicyLocked(ctx); err != nil {
		return empty, noLive, err
	}
	digest, err := h.selection.ControlSHA256()
	if err != nil {
		return empty, noLive, err
	}
	// Preserve only an actually missing initial heartbeat as startup waiting.
	if _, err := readDesktopRuntimeFileContext(ctx, h.launch, "node-mtu-status.json", desktopNodeMTURecordLimit); err != nil {
		return empty, noLive, err
	}
	live, err := readDesktopNodeMTUContext(ctx, h.launch)
	if err != nil {
		return empty, noLive, err
	}
	record, err := readDesktopNodeCandidatePrefixReadyContext(ctx, h.launch, digest, h.started, fresh, live)
	if err != nil {
		return empty, noLive, err
	}
	if err := desktopLinuxNodeTUNCurrentContext(ctx, live); err != nil {
		return empty, noLive, err
	}
	if err := h.runningPolicyLocked(ctx); err != nil {
		return empty, noLive, err
	}
	return record, live, nil
}

func (h *desktopLinuxNodeHost) waitCandidatePrefixReady(parent context.Context) (failure error) {
	if err := h.enter(parent); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	runtime, ok := h.launch.candidatePrefix.platform.(*desktopNodeCandidatePrefixPlatformRuntime)
	if !ok || runtime == nil || runtime.host != h || h.activation != nil || h.ready != nil || h.proof != nil {
		return errors.New("Linux prefix preparation changed its distinct purpose")
	}
	if runtime.prepared {
		_, _, err := h.readCandidatePrefixReadyLocked(parent, false)
		return err
	}
	budget, err := desktopCandidatePrefixReadyBudget(h.launch)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	stop := context.AfterFunc(h.operation, cancel)
	defer stop()
	defer func() {
		if failure != nil {
			failure = h.failProofLocked(failure)
		}
	}()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, _, err := h.readCandidatePrefixReadyLocked(ctx, true)
		if err == nil {
			runtime.prepared = true
			return ctx.Err()
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.process.joined:
			return errors.New("original prefix child exited before its private proof")
		case <-ticker.C:
		}
	}
}
