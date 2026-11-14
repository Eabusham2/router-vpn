//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// The original ordered host owns this bridge until its exact native lease has
// discharged. Every operation follows host.gate -> native.mu; no callback
// re-enters platform.current or the host gate while the raw mutex is held.
type desktopMacOSNodeMTUOwner struct {
	host                                *desktopMacOSNodeChainHost
	parent                              *desktopMacOSSessionCapture
	session                             *desktopMacOSSession
	runtime                             *desktopNodeChainPlatformRuntime
	process                             *desktopMacOSProcess
	launch                              *desktopNodeLaunch
	bound                               *nativeMultihopRuntime
	snapshot                            mtuRetestSnapshot
	native                              *desktopNodeMTUOwner
	initial                             desktopNodeMTURecord
	initialState, previous, current     mtuKernelState
	cleanupPrevious, cleanup            mtuKernelState
	admitted, closed, restored, retired bool
}

func sameDesktopMacOSMTUReadback(a, b desktopNodeMTURecord) bool {
	a.Heartbeat, b.Heartbeat = 0, 0
	return a == b
}
func desktopMacOSMTUState(record desktopNodeMTURecord, family int) mtuKernelState {
	return mtuKernelState{Interface: record.Interface, Family: family, Index: record.Index, MTU: record.MTU,
		Identity: fmt.Sprintf("%s/%s/%d", record.Session, record.Path, record.Reader)}
}
func desktopMacOSMTUFamily(snapshot mtuRetestSnapshot) (int, error) {
	host := strings.Trim(strings.TrimSpace(snapshot.Profile.DAITAHost), "[]")
	if host == "" {
		host = "10.77.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return 0, errors.New("macOS MTU capture requires its literal original private benchmark")
	}
	if ip.To4() != nil {
		return 4, nil
	}
	return 6, nil
}

func desktopMacOSMTUHost(snapshot mtuRetestSnapshot) (*desktopMacOSNodeChainHost, bool, error) {
	if !mtuNodeChainPlatformSnapshot(snapshot) {
		return nil, false, nil
	}
	capture := snapshot.Multihop.Chain
	runtime := capture.Platform
	if runtime == nil || runtime.host == nil || runtime.capture != capture.Capture ||
		runtime.host.runtime != runtime || runtime.host.launch != capture.Launch ||
		capture.Launch == nil || capture.Launch.chain != capture.Chain ||
		!capture.Chain.hasPolicy() || capture.Chain.policy != capture.Policy || capture.Chain.socksPolicy != capture.SOCKSPolicy || capture.Chain.policyMetadata().TargetOS != "darwin" {
		return nil, true, errors.New("macOS ordered MTU capture lost its original platform host")
	}
	return runtime.host, true, nil
}

// This comparison neither reads the OS nor enters native Current. Its caller
// already holds the retained host gate and independently reads full readiness.
func validateDesktopMacOSMTUSnapshotLocked(h *desktopMacOSNodeChainHost, snapshot mtuRetestSnapshot) error {
	if h == nil || h.parent == nil || h.parent.app == nil || h.parent.session == nil ||
		h.runtime == nil || h.runtime.host != h || h.launch == nil || h.launch.chain == nil ||
		snapshot.Multihop == nil || snapshot.Multihop.Chain == nil || snapshot.Multihop.Native == nil {
		return errors.New("macOS MTU snapshot lost its complete original host")
	}
	path, chain := snapshot.Multihop, snapshot.Multihop.Chain
	if h.runtime != chain.Platform || h.runtime.capture != chain.Capture || h.launch != chain.Launch ||
		h.launch.chain != chain.Chain || h.policy != chain.Policy || h.socksPolicy != chain.SOCKSPolicy || h.launch.chain.policy != h.policy || h.launch.chain.socksPolicy != h.socksPolicy ||
		h.launch.chain.platform != h.runtime || h.runtime.capture == nil || h.runtime.capture.platform == nil ||
		h.runtime.capture.platform.parent != h.parent || h.bound != path.Native || h.graph == nil || *h.graph != path.Graph ||
		path.Native.launch != h.launch || path.Native.selection.Native != chain.Native ||
		h.process == nil || h.process.parent != h.parent || h.process.command != path.Command ||
		h.launch.command != path.Command || !h.launch.chain.hasPolicy() || h.launch.chain.policyMetadata().TargetOS != "darwin" ||
		!h.proved || !h.activated || h.retiring || h.closed ||
		snapshot.Profile.ID != h.launch.profileID || snapshot.Mode != h.launch.mode ||
		!strings.EqualFold(strings.TrimSpace(snapshot.Profile.MTUPolicy), "auto") {
		return errors.New("macOS MTU snapshot substituted its proved original session or full graph")
	}
	return validateMTURetestSnapshotState(h.parent.app, snapshot)
}

// The first read validates full original source/process/PF/utun/proof. The
// subsequent status must still name that exact proof reader; a concurrently
// changed status is refused rather than reconstructed from a current name.
func readDesktopMacOSMTURecordLocked(ctx context.Context, h *desktopMacOSNodeChainHost) (desktopNodeMTURecord, error) {
	var empty desktopNodeMTURecord
	if err := h.readReadyLocked(ctx, false); err != nil {
		return empty, err
	}
	record, err := readDesktopNodeMTUContext(ctx, h.launch)
	if err != nil {
		return empty, err
	}
	if err := mobilemtu.LockContext(ctx, &h.launch.chain.mu); err != nil {
		return empty, err
	}
	ready := h.launch.chain.ready
	matched := ready != nil && ready.Reader == record.Reader && ready.InterfaceName == record.Interface &&
		int(ready.InterfaceIndex) == record.Index && ready.MTU == record.MTU &&
		ready.Identity.SessionID == record.Session && ready.Identity.ConfigSHA256 == record.Config &&
		h.launch.chain.mtuPath == record.Path
	h.launch.chain.mu.Unlock()
	if !matched {
		return empty, errors.New("macOS MTU status changed its original proved reader")
	}
	link, _, err := desktopnetwork.InterfaceContext(ctx, record.Index)
	if err != nil {
		return empty, err
	}
	if err := validateDesktopMacOSNodeChainInterface(record, link); err != nil {
		return empty, err
	}
	return record, ctx.Err()
}

// Active Retest work is not a connection transaction. Claim the existing
// operation guard only for this captured command so its monitor defers a
// bounded observation while the same host performs a native MTU command.
// Cleanup deliberately does not require this claim: Stop already owns it.
func claimDesktopMacOSMTUOperation(ctx context.Context, a *app, command *exec.Cmd) (func(), error) {
	if ctx == nil || a == nil || command == nil {
		return nil, errors.New("macOS MTU action lost its original caller or command")
	}
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	if ctx.Err() != nil || a.cmd != command || a.controllerClosingLocked() {
		a.mu.Unlock()
		return nil, errors.New("macOS MTU action belongs to a retired original command")
	}
	if !a.operationMu.TryLock() {
		a.mu.Unlock()
		return nil, errors.New("macOS MTU action conflicts with a captured connection operation")
	}
	a.mu.Unlock()
	return a.operationMu.Unlock, nil
}

func captureDesktopPlatformMTUSnapshot(a *app, snapshot mtuRetestSnapshot) (mtuLiveSnapshot, bool, error) {
	h, handled, err := desktopMacOSMTUHost(snapshot)
	if err != nil || !handled {
		return mtuLiveSnapshot{}, handled, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	releaseOperation, err := claimDesktopMacOSMTUOperation(ctx, a, snapshot.Multihop.Command)
	if err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	defer releaseOperation()
	if err := h.enter(ctx); err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.parent == nil || h.parent.app != a {
		return mtuLiveSnapshot{}, true, errors.New("macOS MTU capture changed its original application")
	}
	if err := validateDesktopMacOSMTUSnapshotLocked(h, snapshot); err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	record, err := readDesktopMacOSMTURecordLocked(ctx, h)
	if err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	if h.mtu != nil || record.Active || record.Failure != "" {
		return mtuLiveSnapshot{}, true, errors.New("macOS MTU capture cannot replace an outstanding original lease")
	}
	family, err := desktopMacOSMTUFamily(snapshot)
	if err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	copy := record
	return mtuLiveSnapshot{Interface: record.Interface, Family: family, OriginalMTU: record.MTU, nodeRecord: &copy}, true, nil
}

func openDesktopPlatformMTUOwner(a *app, snapshot mtuRetestSnapshot, live mtuLiveSnapshot, token string, command *exec.Cmd) (mtuKernelOwner, bool, error) {
	h, handled, err := desktopMacOSMTUHost(snapshot)
	if err != nil {
		return nil, true, err
	}
	if !handled {
		if live.nodeRecord != nil {
			return nil, true, errors.New("captured macOS MTU host disappeared before lease opening")
		}
		return nil, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	releaseOperation, err := claimDesktopMacOSMTUOperation(ctx, a, snapshot.Multihop.Command)
	if err != nil {
		return nil, true, err
	}
	defer releaseOperation()
	if err := h.enter(ctx); err != nil {
		return nil, true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.parent == nil || h.parent.app != a {
		return nil, true, errors.New("macOS MTU opening changed its original application")
	}
	if err := validateDesktopMacOSMTUSnapshotLocked(h, snapshot); err != nil {
		return nil, true, err
	}
	before, err := readDesktopMacOSMTURecordLocked(ctx, h)
	family, familyErr := desktopMacOSMTUFamily(snapshot)
	if err != nil || familyErr != nil || command == nil || command != h.process.command || h.mtu != nil ||
		live.nodeRecord == nil || !sameDesktopMacOSMTUReadback(before, *live.nodeRecord) || before.Active || before.Failure != "" ||
		live.Interface != before.Interface || live.OriginalMTU != before.MTU || live.Family != family {
		return nil, true, errors.Join(err, familyErr, errors.New("macOS MTU opening lost its exact original TUN reader"))
	}
	kernel, beginErr := openDesktopNodeMTUOwnerContext(ctx, h.launch, live, token)
	native, ok := kernel.(*desktopNodeMTUOwner)
	if !ok || native == nil {
		return nil, true, errors.Join(beginErr, errors.New("macOS MTU begin returned no retained original lease"))
	}
	initial := desktopMacOSMTUState(before, family)
	owner := &desktopMacOSNodeMTUOwner{host: h, parent: h.parent, session: h.parent.session, runtime: h.runtime, process: h.process, launch: h.launch,
		bound: h.bound, snapshot: snapshot, native: native, initial: before, initialState: initial, previous: initial, current: initial}
	h.mtu = owner // Retain a partial begin before releasing the original host.
	if beginErr != nil {
		return owner, true, beginErr
	}
	if native.record.Reader != before.Reader || native.state() != initial || native.verifyReaderChange != nil {
		return owner, true, errors.New("macOS MTU begin replaced its original reader or verifier")
	}
	native.verifyReaderChange = owner.verifyReaderChangeLocked
	owner.admitted = true
	return owner, true, owner.currentLocked(ctx)
}

func (owner *desktopMacOSNodeMTUOwner) nativeOwner() *desktopNodeMTUOwner {
	if owner == nil {
		return nil
	}
	return owner.native
}

// Original cleanup ownership survives profile/selection changes. No changed
// preference, current interface label or new child can replace these objects.
func (owner *desktopMacOSNodeMTUOwner) originalLocked() error {
	if owner == nil || owner.host == nil || owner.parent == nil || owner.session == nil || owner.parent.session != owner.session ||
		owner.runtime == nil || owner.process == nil || owner.launch == nil || owner.bound == nil || owner.native == nil ||
		owner.snapshot.Multihop == nil || owner.snapshot.Multihop.Chain == nil {
		return errors.New("macOS MTU lease has no retained original ownership")
	}
	h, chain := owner.host, owner.snapshot.Multihop.Chain
	if h.mtu != owner || h.parent != owner.parent || h.runtime != owner.runtime || h.process != owner.process ||
		h.launch != owner.launch || h.bound != owner.bound || owner.runtime.host != h ||
		owner.runtime.capture != chain.Capture || owner.runtime.capture == nil || owner.runtime.capture.platform == nil ||
		owner.runtime.capture.platform.parent != owner.parent || owner.launch.chain != chain.Chain ||
		owner.launch.chain == nil || owner.launch.chain.platform != owner.runtime || owner.launch.chain.policy != chain.Policy || owner.launch.chain.socksPolicy != chain.SOCKSPolicy ||
		h.policy != chain.Policy || h.socksPolicy != chain.SOCKSPolicy || !h.launch.chain.hasPolicy() || h.launch.chain.policyMetadata().TargetOS != "darwin" ||
		owner.snapshot.Multihop.Native != owner.bound || owner.bound.launch != owner.launch ||
		chain.Native == nil || owner.bound.selection.Native != chain.Native || owner.launch.chain.selection.Native != chain.Native ||
		chain.Native.chain == nil || chain.Native.chain.host != chain.Capture || chain.Capture == nil ||
		chain.Capture.sources != chain.Sources || owner.launch.chain.capture != chain.Capture ||
		chain.Native.source != chain.Source || owner.bound.network != chain.Network || chain.Capture.network != chain.Network ||
		owner.process.parent != owner.parent || owner.process.command != owner.launch.command ||
		owner.snapshot.Multihop.Command != owner.launch.command || owner.native.launch != owner.launch ||
		owner.native.record.Session != owner.initial.Session || owner.native.record.Config != owner.initial.Config ||
		owner.native.record.Path != owner.initial.Path || owner.native.family != owner.initialState.Family ||
		owner.native.originalMTU != owner.initial.MTU || owner.launch.mtuSession != owner.initial.Session ||
		owner.launch.configSHA256 != owner.initial.Config {
		return errors.New("macOS MTU lease substituted an original host, command, native owner or source")
	}
	return nil
}

func (owner *desktopMacOSNodeMTUOwner) currentLocked(ctx context.Context) error {
	if owner == nil || owner.closed || owner.retired || !owner.admitted {
		return errors.New("macOS MTU lease is not an admitted live owner")
	}
	if err := owner.originalLocked(); err != nil {
		return err
	}
	if err := validateDesktopMacOSMTUSnapshotLocked(owner.host, owner.snapshot); err != nil {
		return err
	}
	live, err := readDesktopMacOSMTURecordLocked(ctx, owner.host)
	if err != nil || !sameDesktopMacOSMTUReadback(live, owner.native.record) {
		return errors.Join(err, errors.New("macOS MTU native readback differs from its exact original lease"))
	}
	return ctx.Err()
}
func (owner *desktopMacOSNodeMTUOwner) enterCurrent(ctx context.Context) (func(), error) {
	if owner == nil || owner.host == nil {
		return nil, errors.New("macOS MTU has no original active host")
	}
	if owner.parent == nil || owner.parent.app == nil || owner.launch == nil {
		return nil, errors.New("macOS MTU action lost its captured application")
	}
	releaseOperation, err := claimDesktopMacOSMTUOperation(ctx, owner.parent.app, owner.launch.command)
	if err != nil {
		return nil, err
	}
	if err := owner.host.enter(ctx); err != nil {
		releaseOperation()
		return nil, err
	}
	release := func() { owner.host.gate <- struct{}{}; releaseOperation() }
	if err := owner.currentLocked(ctx); err != nil {
		release()
		return nil, err
	}
	if owner.current != owner.native.state() {
		release()
		return nil, errors.New("macOS MTU result has no adopted original proof receipt")
	}
	return release, nil
}

// Called only from this bridge's raw command under host.gate -> native.mu.
// Check the explicit old record even if an earlier proof read pinned next but
// a later canceled callback prevented raw adoption.
func (owner *desktopMacOSNodeMTUOwner) verifyReaderChangeLocked(ctx context.Context, old, next desktopNodeMTURecord) error {
	if err := owner.originalLocked(); err != nil {
		return err
	}
	if !sameDesktopMacOSMTUReadback(old, owner.native.record) || old.Interface == next.Interface ||
		next.Reader <= old.Reader || old.Session != next.Session || old.Config != next.Config || old.Path != next.Path {
		return errors.New("macOS MTU reader callback replaced its original predecessor")
	}
	if err := validateDesktopMacOSMTUSnapshotLocked(owner.host, owner.snapshot); err != nil {
		return err
	}
	live, err := readDesktopMacOSMTURecordLocked(ctx, owner.host)
	if err != nil || !sameDesktopMacOSMTUReadback(live, next) {
		return errors.Join(err, errors.New("macOS MTU successor lacks its exact full native ACK proof"))
	}
	interfaces, err := desktopnetwork.InterfacesContext(ctx)
	if err != nil {
		return err
	}
	previous := &mobilemultihop.DesktopNodeChainReadyRecord{Reader: old.Reader,
		InterfaceName: old.Interface, InterfaceIndex: uint32(old.Index)}
	if err := validateDesktopMacOSNodeChainReaderRetirement(previous, next, interfaces); err != nil {
		return err
	}
	return ctx.Err()
}

func (owner *desktopMacOSNodeMTUOwner) Read() (mtuKernelState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	release, err := owner.enterCurrent(ctx)
	if err != nil {
		return mtuKernelState{}, err
	}
	defer release()
	state, err := owner.native.ReadContext(ctx)
	if err != nil {
		return state, err
	}
	return state, owner.currentLocked(ctx)
}
func (owner *desktopMacOSNodeMTUOwner) Change(expected mtuKernelState, mtu int) (mtuKernelState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	release, err := owner.enterCurrent(ctx)
	if err != nil {
		return mtuKernelState{}, err
	}
	defer release()
	before := owner.current
	state, err := owner.native.ChangeContext(ctx, expected, mtu)
	if err != nil {
		return state, err
	}
	if err := owner.currentLocked(ctx); err != nil {
		return state, err
	}
	owner.previous, owner.current = before, state
	return state, nil
}
func (owner *desktopMacOSNodeMTUOwner) Commit() error {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	release, err := owner.enterCurrent(ctx)
	if err != nil {
		return err
	}
	defer release()
	return owner.native.commitWithValidationContext(ctx, owner.currentLocked)
}

func (owner *desktopMacOSNodeMTUOwner) Restore() (mtuKernelState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	if owner == nil || owner.host == nil {
		return mtuKernelState{}, errors.New("macOS MTU rollback lost its original host")
	}
	if err := owner.host.enter(ctx); err != nil {
		return mtuKernelState{}, err
	}
	defer func() { owner.host.gate <- struct{}{} }()
	if owner.closed {
		return mtuKernelState{}, errors.New("macOS MTU rollback belongs to a closed lease")
	}
	if err := owner.originalLocked(); err != nil {
		return mtuKernelState{}, err
	}
	finishObservation, err := owner.beginCleanupObservationLocked(ctx)
	if err != nil {
		return mtuKernelState{}, err
	}
	defer finishObservation()
	if err := owner.parent.cleanupCurrent(ctx); err != nil {
		return mtuKernelState{}, err
	}
	before := owner.current
	state, err := owner.native.RestoreContext(ctx)
	if err != nil {
		return state, err
	}
	if err := owner.currentLocked(ctx); err != nil {
		return state, err
	}
	owner.previous, owner.current = before, state
	return state, nil
}

// Parent shutdown calls this only after its original authenticated native
// cleanup and sole process waiter joined, before releasing PF/workspace.
func (owner *desktopMacOSNodeMTUOwner) closeRetiredLocked(ctx context.Context) error {
	if owner == nil {
		return errors.New("macOS MTU retirement lost its original bridge")
	}
	if owner.closed {
		return nil
	}
	if err := owner.originalLocked(); err != nil {
		return err
	}
	if !owner.host.nativeRetired || !owner.host.retiring || owner.process.NativeCleanup(ctx) != nil {
		return errors.New("macOS MTU retirement preceded original native cleanup and process join")
	}
	if err := owner.parent.cleanupCurrent(ctx); err != nil {
		return err
	}
	// A begin that never published its nonce may already be locally closed.
	// Re-read this exact child's stop receipt even then; raw Close's idempotent
	// branch alone cannot prove native retirement or discharge another lease.
	stopped, err := readDesktopNodeStoppedContext(ctx, owner.launch)
	if err != nil || !stopped {
		return errors.Join(err, errors.New("macOS MTU retirement lacks its exact original child stop receipt"))
	}
	if err := owner.native.CloseContext(ctx); err != nil {
		return err
	}
	if !owner.native.closed || owner.native.pending != nil || owner.native.unconfirmedCommit != nil {
		return errors.New("macOS MTU native retirement has no discharged original lease")
	}
	owner.closed, owner.retired, owner.restored = true, true, false
	owner.host.mtu = nil
	return nil
}
func (owner *desktopMacOSNodeMTUOwner) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	if owner == nil || owner.host == nil {
		return errors.New("macOS MTU close lost its original host")
	}
	if err := owner.host.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.host.gate <- struct{}{} }()
	if owner.closed {
		return nil
	}
	if err := owner.originalLocked(); err != nil {
		return err
	}
	if owner.host.nativeRetired {
		return owner.closeRetiredLocked(ctx)
	}
	finishObservation, err := owner.beginCleanupObservationLocked(ctx)
	if err != nil {
		return err
	}
	defer finishObservation()
	if err := owner.parent.cleanupCurrent(ctx); err != nil {
		return err
	}
	before := owner.current
	if err := owner.native.CloseContext(ctx); err != nil {
		return err
	}
	live, err := readDesktopMacOSMTURecordLocked(ctx, owner.host)
	if err != nil || !sameDesktopMacOSMTUReadback(live, owner.native.record) {
		return errors.Join(err, errors.New("macOS MTU close lost its exact original native readback"))
	}
	state, restored, err := owner.native.CleanupRestoredContext(ctx)
	if err != nil {
		return err
	}
	owner.closed, owner.restored = true, restored
	if restored {
		owner.cleanupPrevious, owner.cleanup = before, state
	}
	owner.host.mtu = nil
	return nil
}
func (owner *desktopMacOSNodeMTUOwner) CleanupRestored() (mtuKernelState, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if owner == nil || owner.host == nil || owner.host.enter(ctx) != nil {
		return mtuKernelState{}, false
	}
	defer func() { owner.host.gate <- struct{}{} }()
	return owner.cleanup, owner.closed && owner.restored && !owner.retired
}

// This is the only opt-in interface-succession capability. The outer owner
// never gains a writer by name; it can accept only the exact latest verified
// transition or an idempotent confirmation of that same current receipt.
func (owner *desktopMacOSNodeMTUOwner) validateMTUInterfaceSuccession(initial, previous, next mtuKernelState, cleanup bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if owner == nil || owner.host == nil {
		return errors.New("macOS MTU succession lost its original bridge")
	}
	if !cleanup {
		if owner.parent == nil || owner.parent.app == nil || owner.launch == nil {
			return errors.New("macOS MTU succession lost its captured application")
		}
		releaseOperation, err := claimDesktopMacOSMTUOperation(ctx, owner.parent.app, owner.launch.command)
		if err != nil {
			return err
		}
		defer releaseOperation()
	}
	if err := owner.host.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.host.gate <- struct{}{} }()
	if initial != owner.initialState {
		return errors.New("macOS MTU succession replaced its immutable initial reader")
	}
	if cleanup {
		if !owner.closed || !owner.restored || owner.retired || next != owner.cleanup ||
			previous != next && previous != owner.cleanupPrevious {
			return errors.New("macOS MTU cleanup has no exact authenticated stored rollback receipt")
		}
		return nil
	}
	if err := owner.currentLocked(ctx); err != nil {
		return err
	}
	if next != owner.current || previous != next && previous != owner.previous || next != owner.native.state() {
		return errors.New("macOS MTU succession changed its original verified transition")
	}
	return nil
}
