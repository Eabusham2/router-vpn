//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprotection"
	"sync/atomic"
)

type desktopNodeChainPlatformCapture struct {
	parent *desktopLinuxNodeParentCapture
	verify func(context.Context, string) (string, error)
}

type desktopNodeChainPlatformRuntime struct {
	capture    *desktopNodeChainHostCapture
	host       *desktopLinuxNodeHost
	session    *desktopLinuxNodeSession
	registered bool
}

func captureDesktopNodeChainPlatform(ctx context.Context, a *app, selection multihopSelection) (*desktopNodeChainPlatformCapture, error) {
	if selection.Native == nil || selection.Native.root != linuxOwnedControllerRoot {
		return nil, errors.New("Linux ordered source is outside its installed controller")
	}
	parent, err := captureDesktopLinuxNodeParentContext(ctx, a)
	if err != nil {
		return nil, err
	}
	return &desktopNodeChainPlatformCapture{parent: parent, verify: verifyBundledNativeContext}, nil
}

func (capture *desktopNodeChainPlatformCapture) current(ctx context.Context) error {
	if capture == nil || capture.parent == nil || capture.verify == nil {
		return errors.New("Linux ordered capture lost its installed original parent")
	}
	return capture.parent.Current(ctx)
}

func (capture *desktopNodeChainPlatformCapture) prepare(ctx context.Context, owner *desktopNodeChainHostCapture,
	selection multihopSelection) (launch *desktopNodeLaunch, image string, failure error) {
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
	launch, err = newDesktopNodeChainLaunch(selection, sessionID, "linux")
	if err != nil {
		return nil, "", err
	}
	launch.chain.capture = owner
	_, meta, physicalCapture, err := launch.chain.policy.ReadValidated()
	if err != nil {
		return launch, "", err
	}
	physical, err := captureDesktopLinuxRunningPath(physicalCapture.PhysicalRoots, physicalCapture.IPv6Mode)
	if err != nil {
		return launch, "", err
	}
	h := &desktopLinuxNodeHost{gate: make(chan struct{}, 1), parent: capture.parent, operation: operation,
		chain: launch.chain.policy, launch: launch, source: []byte(launch.chain.input), network: owner.network,
		revision: desktopOwnedNodeProfileToken(selection.Control), options: owner.sources.options, savedOptions: owner.sources.options,
		physical: physical, monitor: &atomic.Pointer[desktopLinuxNodeMonitor]{},
		selection: linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
			ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}}
	runtime := &desktopNodeChainPlatformRuntime{capture: owner, host: h}
	launch.chain.platform = runtime
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

func (h *desktopLinuxNodeHost) currentNodeChain(ctx context.Context) error {
	if h == nil || ctx == nil || ctx.Err() != nil || h.closing || h.closed || h.operation == nil || h.parent == nil ||
		h.chain == nil || h.policy != nil || h.imported != nil || h.external != nil || h.launch == nil || h.launch.chain == nil ||
		h.launch.chain.policy != h.chain || h.launch.chain.platform == nil || h.launch.ownedNode != nil {
		return errors.New("Linux ordered host lost its unique concrete policy")
	}
	runtime := h.launch.chain.platform
	if runtime.host != h || runtime.capture == nil || h.launch.chain.capture != runtime.capture ||
		h.launch.chain.selection.Native.chain.host != runtime.capture || runtime.capture.platform == nil || runtime.capture.platform.parent != h.parent ||
		runtime.capture.app != h.parent.app || runtime.capture.sources == nil ||
		runtime.capture.sources.selection.Native != h.launch.chain.selection.Native {
		return errors.New("Linux ordered host substituted its captured parent or full source")
	}
	if err := runtime.capture.current(ctx); err != nil {
		return err
	}
	if err := validateDesktopNodeChainLaunch(ctx, h.launch); err != nil {
		return err
	}
	meta := h.chain.Metadata()
	wanted := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
		ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	if meta.TargetOS != "linux" || h.selection != wanted || string(h.source) != h.launch.chain.input || h.network != runtime.capture.network {
		return errors.New("Linux ordered host changed its native protection or projected source")
	}
	if h.activation != nil {
		if err := h.activation.matches(h); err != nil {
			return err
		}
	} else if h.operation.Err() != nil {
		return errConnectionOperationCancelled
	}
	a := h.parent.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if h.activation == nil {
		if a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.connectionCancelIntent == h.operation {
			return errConnectionOperationCancelled
		}
	} else if h.process == nil || a.cmd != h.process.command || a.state.RouterID != meta.ProfileID || a.state.RuntimeMode != meta.Mode {
		return errors.New("Linux ordered activation belongs to a replaced connection")
	}
	return runtime.capture.sources.currentLocked(a)
}

func newDesktopLinuxNodeChainTransaction(ctx context.Context, h *desktopLinuxNodeHost, journal *desktopLinuxNodeJournal,
	predecessor *desktopLinuxNodeTransaction) (*desktopLinuxNodeTransaction, error) {
	if h == nil || h.chain == nil || h.launch == nil || h.launch.chain == nil || h.launch.chain.platform == nil ||
		h.process == nil || !h.process.Started() || journal == nil || !sameDesktopLinuxParentCapture(h.parent, journal.parent) ||
		!sameDesktopLinuxParentCapture(h.parent, h.process.parent) {
		return nil, errors.New("Linux ordered transaction lost its original process and journal")
	}
	if err := h.current(ctx); err != nil {
		return nil, err
	}
	t := &desktopLinuxNodeTransaction{gate: make(chan struct{}, 1), parent: h.parent, journal: journal, process: h.process,
		chain: h.chain, chainSources: h.launch.chain.platform.capture.sources, mode: h.launch.mode, operation: h.operation,
		startup: ctx, selection: h.selection, profileID: h.launch.profileID, revision: h.revision, network: h.network,
		options: h.options, savedOptions: h.savedOptions, predecessor: predecessor}
	return finishDesktopLinuxNodeTransaction(t)
}

func (owner *desktopNodeChainPlatformRuntime) guard(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if owner == nil || !owner.registered || owner.host == nil || owner.host.launch != launch || owner.session == nil ||
		owner.capture == nil || owner.capture.app != a || launch.chain == nil || launch.chain.platform != owner ||
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

func (owner *desktopNodeChainPlatformRuntime) stage(ctx context.Context) error {
	if owner == nil || owner.host == nil || owner.session == nil || !owner.registered {
		return errors.New("Linux ordered staging lost its retained session")
	}
	return owner.host.Stage(ctx)
}

func (owner *desktopNodeChainPlatformRuntime) start(ctx context.Context) error {
	if owner == nil || owner.session == nil || owner.host == nil || owner.capture == nil || owner.capture.platform == nil {
		return errors.New("Linux ordered start lost its original session")
	}
	return owner.session.startWithVerifier(ctx, owner.host, os.Environ(), owner.capture.platform.verify)
}

func (owner *desktopNodeChainPlatformRuntime) current(ctx context.Context) error {
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
	if h.ready != nil {
		_, _, err := h.readReadyLocked(ctx, false)
		return err
	}
	return nil
}

func (owner *desktopNodeChainPlatformRuntime) prove(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return errors.New("Linux ordered proof has no original host")
	}
	if err := owner.host.enter(ctx); err != nil {
		return err
	}
	active := owner.host.activation != nil
	owner.host.gate <- struct{}{}
	if active {
		return owner.current(ctx)
	}
	if _, err := owner.host.WaitReady(ctx); err != nil {
		return err
	}
	_, err := owner.host.Prove(ctx)
	return err
}

func (owner *desktopNodeChainPlatformRuntime) activate(ctx context.Context) error {
	if owner == nil || owner.host == nil || owner.session == nil {
		return errors.New("Linux ordered activation has no original session")
	}
	if err := owner.host.Activate(ctx); err != nil {
		return err
	}
	return owner.session.Monitor(ctx, owner.host)
}

func (owner *desktopNodeChainPlatformRuntime) close(ctx context.Context) error {
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

func (owner *desktopNodeChainPlatformRuntime) processDone() <-chan struct{} {
	if owner == nil || owner.host == nil || owner.host.process == nil {
		return nil
	}
	return owner.host.process.joined
}
