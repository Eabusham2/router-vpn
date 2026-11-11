//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"reflect"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

type desktopLinuxImportedConnection struct {
	capture    *desktopLinuxImportedCapture
	host       *desktopLinuxNodeHost
	session    *desktopLinuxNodeSession
	selection  multihopSelection
	registered bool
}

func guardDesktopImportedPlatformTransition(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if ctx == nil || ctx.Err() != nil || a == nil || launch == nil {
		return errors.New("Linux imported transition requires its original live caller")
	}
	owner, ok := launch.importedPlatform.(*desktopLinuxImportedConnection)
	if !ok || owner == nil || !owner.registered || owner.host == nil || owner.host.launch != launch ||
		owner.session == nil || owner.capture == nil || owner.capture.parent == nil || owner.capture.parent.app != a ||
		owner.host.parent != owner.capture.parent || owner.selection.Native == nil || owner.selection.Native.importedPlatform != owner.capture ||
		launch.ownedNode != nil || launch.external != nil {
		return errors.New("Linux imported transition changed its concrete original host")
	}
	s, h := owner.session, owner.host
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if !sameDesktopLinuxParentCapture(s.parent, h.parent) {
		return errors.New("Linux imported transition belongs to another retained session")
	}
	p := h.parent.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	_, retained := p.dependents[h]
	p.gate <- struct{}{}
	if !retained {
		return errors.New("Linux imported transition lost its original parent cleanup registration")
	}
	// This observes the original source and actual legacy protection again at
	// the common guard seam, before the existing command may be stopped.
	return h.CheckLegacyTransition(ctx)
}

func (owner *desktopLinuxImportedConnection) Stage(ctx context.Context) error {
	if owner == nil || owner.host == nil || owner.session == nil || !owner.registered {
		return errors.New("Linux imported staging lost its retained session")
	}
	h, a := owner.host, owner.host.parent.app
	if err := h.enter(ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		h.gate <- struct{}{}
		return err
	}
	err := owner.capture.sources.currentLocked(a, true)
	if err == nil && (h.stageEntered || h.importedProjected) {
		err = errors.New("Linux imported staging cannot re-enter its applied projection")
	}
	if err == nil {
		h.importedProjected = true
	}
	a.mu.Unlock()
	h.gate <- struct{}{}
	if err != nil {
		return err
	}
	return h.Stage(ctx)
}

func (owner *desktopLinuxImportedConnection) Start(ctx context.Context) error {
	if owner == nil || owner.session == nil || owner.host == nil || owner.capture == nil {
		return errors.New("Linux imported start lost its original session")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return owner.session.startWithVerifier(ctx, owner.host, os.Environ(), owner.capture.verify)
}

func (owner *desktopLinuxImportedConnection) Current(ctx context.Context) error {
	if owner == nil || owner.session == nil || owner.host == nil {
		return errors.New("Linux imported observation lost its original session")
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
		return errors.New("Linux imported observation belongs to a replaced session")
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

func (owner *desktopLinuxImportedConnection) Prove(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return errors.New("Linux imported proof has no original host")
	}
	if err := owner.host.enter(ctx); err != nil {
		return err
	}
	active := owner.host.activation != nil
	owner.host.gate <- struct{}{}
	if active {
		if err := owner.Current(ctx); err != nil {
			return err
		}
		if err := proveNativeMultihopCapture(ctx, owner.selection, func() bool { return owner.Current(ctx) == nil }, proveNativeMultihopLaneContext); err != nil {
			return err
		}
		if _, err := owner.host.parent.app.proveImportedNativeDNS(ctx, owner.selection, owner.host.launch.command); err != nil {
			return err
		}
		return owner.Current(ctx)
	}
	if _, err := owner.host.WaitReady(ctx); err != nil {
		return err
	}
	_, err := owner.host.Prove(ctx)
	return err
}

func (owner *desktopLinuxImportedConnection) Activate(ctx context.Context) error {
	if owner == nil || owner.host == nil || owner.session == nil {
		return errors.New("Linux imported activation has no original session")
	}
	if err := owner.host.Activate(ctx); err != nil {
		return err
	}
	return owner.session.Monitor(ctx, owner.host)
}

func (owner *desktopLinuxImportedConnection) ProcessDone() <-chan struct{} {
	if owner == nil || owner.host == nil || owner.host.process == nil {
		return nil
	}
	return owner.host.process.joined
}

func (owner *desktopLinuxImportedConnection) Close(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return nil
	}
	h := owner.host
	if !owner.registered {
		if h.process != nil || h.launch.command != nil || h.stageEntered {
			return errors.New("unregistered Linux imported host retained entered runtime")
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

func (owner *desktopLinuxImportedConnection) ValidateConfig(ctx context.Context, raw []byte) error {
	if owner == nil || owner.host == nil {
		return errors.New("Linux imported configuration has no retained host")
	}
	if err := owner.host.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.host.gate <- struct{}{} }()
	return owner.validateConfigLocked(ctx, raw)
}

func (owner *desktopLinuxImportedConnection) validateConfigLocked(ctx context.Context, raw []byte) error {
	if owner == nil || owner.host == nil || owner.host.imported == nil || owner.selection.Native == nil ||
		owner.selection.Native.importedPlatform != owner.capture || owner.host.launch.importedPlatform != owner ||
		owner.host.imported.Validate() != nil || string(raw) != owner.host.imported.Config() ||
		string(owner.host.source) != owner.selection.Native.importedInput {
		return errors.New("Linux imported configuration changed its retained constructor")
	}
	return ctx.Err()
}

func (owner *desktopLinuxImportedConnection) Restore(ctx context.Context) error {
	if err := owner.Current(ctx); err != nil {
		return err
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.activation == nil || h.activation.matches(h) != nil {
		return errors.New("Linux imported restoration has no proved original activation")
	}
	raw, err := readDesktopRuntimeFileContext(ctx, h.launch, "sing-box.json", 4<<20)
	if err != nil {
		return err
	}
	defer clear(raw)
	if err := owner.validateConfigLocked(ctx, raw); err != nil {
		return err
	}
	source, err := readDesktopRuntimeFileContext(ctx, h.launch, "imported-source.json", mobilemultihop.ImportedLaunchInputLimit)
	defer clear(source)
	if err != nil || !bytes.Equal(source, h.source) {
		return errors.Join(err, errors.New("Linux imported restoration replaced its original private input"))
	}
	return h.current(ctx)
}

func (h *desktopLinuxNodeHost) readyPolicy() (mobilemultihop.DesktopPhysicalPolicy, error) {
	if h != nil && h.chain != nil {
		if h.policy != nil || h.imported != nil || h.external != nil {
			return nil, errors.New("Linux ordered readiness mixed native policy families")
		}
		return h.chain, h.chain.Validate()
	}
	if h == nil || (h.policy == nil) == (h.imported == nil) || h.external != nil {
		return nil, errors.New("Linux readiness lost its unique typed source")
	}
	if h.imported != nil {
		return h.imported, h.imported.Validate()
	}
	return h.policy, h.policy.Validate()
}

func (h *desktopLinuxNodeHost) proveImportedLocked(parent context.Context) (elapsed time.Duration, failure error) {
	if h.activation != nil {
		return 0, errors.New("Linux imported proof cannot restart an activated host")
	}
	defer func() {
		if failure != nil {
			elapsed = 0
			failure = h.failProofLocked(failure)
		}
	}()
	h.proof = nil
	if h.ready == nil || h.operation == nil {
		return 0, errors.New("Linux imported proof preceded native selected-DNS readiness")
	}
	owner, ok := h.launch.importedPlatform.(*desktopLinuxImportedConnection)
	if !ok || owner.host != h {
		return 0, errors.New("Linux imported proof lost its captured host")
	}
	ready, live, err := h.readReadyLocked(parent, false)
	if err != nil || live.Active || live.Failure != "" {
		return 0, errors.Join(err, errors.New("Linux imported proof has no idle original TUN"))
	}
	a := h.parent.app
	a.mu.Lock()
	seconds := a.cfg.AutoTestSeconds
	a.mu.Unlock()
	if seconds < 1 || seconds > 300 {
		return 0, errors.New("Linux imported proof has no bounded configured deadline")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(seconds)*time.Second)
	stop := context.AfterFunc(h.operation, cancel)
	defer func() { stop(); cancel() }()
	current := func(call context.Context) error {
		after, next, err := h.readReadyLocked(call, false)
		if err != nil || after != ready || !sameDesktopLinuxNodeProofTUN(live, next) {
			return errors.Join(err, errors.New("Linux imported proof changed its original native reader"))
		}
		return nil
	}
	started := time.Now()
	if err := proveNativeMultihopCapture(ctx, owner.selection, func() bool { return current(ctx) == nil }, proveNativeMultihopLaneContext); err != nil {
		return 0, err
	}
	selected, err := expectedDNSSelection(owner.selection.Exit)
	if err != nil {
		return 0, err
	}
	if _, err := exchangeDesktopImportedDNS(ctx, h.launch, func(call context.Context) error {
		if err := current(call); err != nil {
			return err
		}
		return verifySingBoxDNSConfigBytes(h.launch.config, selected)
	}); err != nil {
		return 0, err
	}
	if err := current(ctx); err != nil {
		return 0, err
	}
	elapsed = time.Since(started)
	h.proof = &desktopLinuxNodeProof{ready: ready, live: live, provedAt: time.Now(), elapsed: elapsed}
	return elapsed, nil
}

func (owner *desktopLinuxImportedConnection) RetainMTU(ctx context.Context, mtu *desktopImportedMTUOwner) error {
	if owner == nil || owner.host == nil || mtu == nil || mtu.launch != owner.host.launch {
		return errors.New("Linux imported MTU lost its original launch")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.activation == nil || h.activation.matches(h) != nil || h.current(ctx) != nil {
		return errors.New("Linux imported MTU requires the original active host")
	}
	if h.importedMTU != nil && h.importedMTU != mtu {
		prior := h.importedMTU
		if !prior.cleanupJoined.Load() || prior.sockets.Load() != 0 {
			return errors.New("Linux imported MTU cannot replace an unjoined lease")
		}
	}
	h.importedMTU = mtu
	return nil
}

// Cleanup keeps the exact source/process identity, but deliberately does not
// require a live activation after this same host has begun closing.
func (owner *desktopLinuxImportedConnection) MTUCleanupCurrent(ctx context.Context, mtu *desktopImportedMTUOwner) error {
	if owner == nil || owner.host == nil || mtu == nil {
		return errors.New("Linux imported cleanup has no original lease")
	}
	h := owner.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	return owner.mtuCleanupCurrentLocked(ctx, mtu)
}

func (owner *desktopLinuxImportedConnection) mtuCleanupCurrentLocked(ctx context.Context, mtu *desktopImportedMTUOwner) error {
	h := owner.host
	if h.importedMTU != mtu || mtu.launch != h.launch || mtu.runtime == nil || mtu.runtime.launch != h.launch ||
		h.launch.importedPlatform != owner || h.process == nil || h.transaction == nil || h.transaction.process != h.process ||
		h.transaction.imported != h.imported || h.process.command != h.launch.command || owner.session == nil ||
		h.transaction.journal != owner.session.journal || h.closed || h.released {
		return errors.New("Linux imported cleanup substituted its original host or native lease")
	}
	return h.parent.retirementCurrent(ctx)
}

func (h *desktopLinuxNodeHost) finishImportedMTURetirementLocked(ctx context.Context) error {
	o := h.importedMTU
	owner, ok := h.launch.importedPlatform.(*desktopLinuxImportedConnection)
	if !ok || o == nil || owner.mtuCleanupCurrentLocked(ctx, o) != nil {
		return errors.New("Linux imported MTU retirement lost its original lease")
	}
	t := h.transaction
	if err := t.enter(ctx); err != nil {
		return err
	}
	joined := t.retired && t.engineJoined && t.pending == nil && t.retirement != nil && t.retirement.Validate() == nil &&
		t.prepared != nil && t.retirement.Source != nil && reflect.DeepEqual(t.retirement.Prepared, t.prepared)
	t.gate <- struct{}{}
	if !joined || h.process.command.ProcessState == nil {
		return errors.New("Linux imported MTU retirement preceded authenticated source and process join")
	}
	select {
	case <-h.process.joined:
	default:
		return errors.New("Linux imported MTU retirement preceded original Wait")
	}
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if iface.Name == o.record.Interface || iface.Index == o.record.Index {
			return errors.New("Linux imported MTU retirement retained its captured TUN")
		}
	}
	o.closeSockets()
	if o.sockets.Load() != 0 {
		return errors.New("Linux imported MTU sockets did not join retirement")
	}
	if o.kernel != nil {
		if err := mobilemtu.LockContext(ctx, &o.kernel.mu); err != nil {
			return err
		}
		o.kernel.closed, o.kernel.runtimeRetired, o.kernel.pending = true, true, nil
		o.kernel.discardCommitRevert()
		o.kernel.mu.Unlock()
	}
	if o.mailboxHeld {
		o.mailboxHeld = false
		o.launch.importedDNSMu.Unlock()
	}
	o.cleanupJoined.Store(true)
	h.importedMTU = nil
	return nil
}

var _ desktopImportedPlatformRuntime = (*desktopLinuxImportedConnection)(nil)

// Only explicit Stop may use this fallback after the exact MTU worker has
// joined. A Speed Lab hold cannot retire a live graph to manufacture rollback.
func prepareDesktopLinuxImportedMTUStop(ctx context.Context, a *app, command *exec.Cmd, operation context.Context, terminal bool, failedHold error) (bool, error) {
	raw, exists := desktopImportedMTUUIs.Load(a)
	u, ok := raw.(*desktopImportedMTUUI)
	if !exists || !ok || u == nil || u.runtime == nil || u.runtime.launch == nil || u.runtime.launch.importedPlatform == nil {
		return false, nil
	}
	owner, ok := u.runtime.launch.importedPlatform.(*desktopLinuxImportedConnection)
	if !ok || owner == nil || owner.session == nil || owner.host == nil || ctx == nil || ctx.Err() != nil || failedHold == nil ||
		errors.Is(failedHold, context.Canceled) || errors.Is(failedHold, context.DeadlineExceeded) {
		return true, errors.New("Linux imported MTU stop lost its bounded original caller")
	}
	lock := mtuRetestLockFor(a)
	if !lock.TryLock() {
		return true, errors.New("Linux imported MTU worker has not joined its original Retest")
	}
	defer lock.Unlock()
	if err := mobilemtu.LockContext(ctx, &u.mu); err != nil {
		return true, err
	}
	defer u.mu.Unlock()
	s, h := owner.session, owner.host
	if u.running || u.a != a || u.owner == nil || u.owner.runtime != u.runtime || u.owner.launch != h.launch || h.launch.command != command {
		return true, errors.New("Linux imported MTU stop changed its original worker or command")
	}
	if err := s.enter(ctx); err != nil {
		return true, err
	}
	defer func() { s.gate <- struct{}{} }()
	current := func() error {
		if s.active != h || s.closed || s.released || s.journal == nil || h.transaction == nil || h.transaction.journal != s.journal ||
			owner.mtuCleanupCurrentLocked(ctx, u.owner) != nil {
			return errors.New("Linux imported MTU stop lost its original retained session")
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return err
		}
		defer a.mu.Unlock()
		raw, found := desktopImportedMTUUIs.Load(a)
		_, duplicate := desktopNodeOwners.Load(a)
		if !found || raw != u || duplicate || a.cmd != command || a.connectionContext != operation || a.closing != terminal ||
			h.parent.currentAppLocked(terminal) != nil {
			return errors.New("Linux imported MTU stop belongs to a replaced application")
		}
		return nil
	}
	if err := h.enter(ctx); err != nil {
		return true, err
	}
	err := current()
	h.gate <- struct{}{}
	if err != nil {
		return true, err
	}
	if err := h.stopMonitorBeforeRetirement(ctx); err != nil {
		return true, err
	}
	if err := h.enter(ctx); err != nil {
		return true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := current(); err != nil {
		return true, err
	}
	h.revokeActivationLocked()
	if err := h.transaction.Retire(ctx); err != nil {
		return true, err
	}
	if err := h.finishImportedMTURetirementLocked(ctx); err != nil {
		return true, err
	}
	if u.operation != nil {
		u.operation.mu.Lock()
		u.operation.cleanupPending = false
		u.operation.status.Running, u.operation.status.Complete = false, true
		u.operation.status.Measured, u.operation.status.Restored = false, false
		u.operation.status.EffectiveMTU, u.operation.status.Source, u.operation.status.Phase = 0, "unavailable-stale-owner", "failed"
		u.operation.mu.Unlock()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cmd != command || a.connectionContext != operation {
		return true, errors.New("Linux imported MTU retirement cannot change a replacement command")
	}
	a.state.Connected, a.state.Phase = false, "stopping"
	return true, nil
}
