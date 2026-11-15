//go:build darwin

package main

import (
	"context"
	"errors"
	"os/exec"
	"router-vpn/internal/desktopnetwork"
	"strings"
	"time"
)

type desktopMacOSPairedNodeMTUOwner struct {
	host                                *desktopMacOSPairedNodeHost
	parent                              *desktopMacOSSessionCapture
	session                             *desktopMacOSSession
	process                             *desktopMacOSProcess
	launch                              *desktopNodeLaunch
	snapshot                            mtuRetestSnapshot
	native                              *desktopNodeMTUOwner
	initial                             desktopNodeMTURecord
	initialState, previous, current     mtuKernelState
	cleanupPrevious, cleanup            mtuKernelState
	admitted, closed, restored, retired bool
}

func desktopMacOSPairedNodeMTUHost(a *app, snapshot mtuRetestSnapshot) (*desktopMacOSPairedNodeHost, bool, error) {
	value, exists := desktopNodeOwners.Load(a)
	if !exists {
		return nil, false, nil
	}
	launch, ok := value.(*desktopNodeLaunch)
	if !ok || launch == nil {
		return nil, true, errors.New("macOS MTU lost captured node registry")
	}
	if launch.pairedNode == nil {
		return nil, false, nil
	}
	h, ok := launch.pairedNode.(*desktopMacOSPairedNodeHost)
	if !ok || h == nil || h.launch != launch || h.parent == nil || h.parent.app != a {
		return nil, true, errors.New("macOS MTU changed its original paired host")
	}
	return h, true, nil
}
func validateDesktopMacOSPairedNodeMTUSnapshotLocked(h *desktopMacOSPairedNodeHost, snapshot mtuRetestSnapshot) error {
	if h == nil || h.parent == nil || h.process == nil || h.launch == nil || h.launch.pairedNode != h || !h.activated || !h.proved || h.retiring || h.closed || snapshot.Multihop != nil || snapshot.Profile.ID != h.launch.profileID || snapshot.Mode != h.launch.mode || desktopOwnedNodeProfileToken(snapshot.Profile) != h.revision || !strings.EqualFold(strings.TrimSpace(snapshot.Profile.MTUPolicy), "auto") {
		return errors.New("macOS paired Node MTU changed its original source and active path")
	}
	return validateMTURetestSnapshotState(h.parent.app, snapshot)
}
func readDesktopMacOSPairedNodeMTURecordLocked(ctx context.Context, h *desktopMacOSPairedNodeHost) (desktopNodeMTURecord, error) {
	_, live, err := h.readReadyLocked(ctx, false)
	return live, err
}
func captureDesktopMacOSPairedNodeMTUSnapshot(a *app, snapshot mtuRetestSnapshot) (mtuLiveSnapshot, bool, error) {
	h, handled, err := desktopMacOSPairedNodeMTUHost(a, snapshot)
	if err != nil || !handled {
		return mtuLiveSnapshot{}, handled, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	release, err := claimDesktopMacOSMTUOperation(ctx, a, h.launch.command)
	if err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	defer release()
	if err := h.enter(ctx); err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := validateDesktopMacOSPairedNodeMTUSnapshotLocked(h, snapshot); err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	record, err := readDesktopMacOSPairedNodeMTURecordLocked(ctx, h)
	if err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	if h.mtu != nil || record.Active || record.Failure != "" {
		return mtuLiveSnapshot{}, true, errors.New("macOS paired MTU cannot replace original lease")
	}
	family, err := desktopMacOSMTUFamily(snapshot)
	if err != nil {
		return mtuLiveSnapshot{}, true, err
	}
	return mtuLiveSnapshot{Interface: record.Interface, Family: family, OriginalMTU: record.MTU, nodeRecord: &record}, true, nil
}
func openDesktopMacOSPairedNodeMTUOwner(a *app, snapshot mtuRetestSnapshot, live mtuLiveSnapshot, token string, command *exec.Cmd) (mtuKernelOwner, bool, error) {
	h, handled, err := desktopMacOSPairedNodeMTUHost(a, snapshot)
	if err != nil || !handled {
		return nil, handled, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	release, err := claimDesktopMacOSMTUOperation(ctx, a, command)
	if err != nil {
		return nil, true, err
	}
	defer release()
	if err := h.enter(ctx); err != nil {
		return nil, true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := validateDesktopMacOSPairedNodeMTUSnapshotLocked(h, snapshot); err != nil {
		return nil, true, err
	}
	before, err := readDesktopMacOSPairedNodeMTURecordLocked(ctx, h)
	family, familyErr := desktopMacOSMTUFamily(snapshot)
	if err != nil || familyErr != nil || command != h.launch.command || h.mtu != nil || live.nodeRecord == nil || !sameDesktopMacOSMTUReadback(before, *live.nodeRecord) || before.Active || before.Failure != "" || live.Interface != before.Interface || live.OriginalMTU != before.MTU || live.Family != family {
		return nil, true, errors.Join(err, familyErr, errors.New("macOS paired MTU opening lost its exact original reader"))
	}
	kernel, beginErr := openDesktopNodeMTUOwnerContext(ctx, h.launch, live, token)
	native, ok := kernel.(*desktopNodeMTUOwner)
	if !ok || native == nil {
		return nil, true, errors.Join(beginErr, errors.New("macOS paired MTU begin returned no original lease"))
	}
	initial := desktopMacOSMTUState(before, family)
	owner := &desktopMacOSPairedNodeMTUOwner{host: h, parent: h.parent, session: h.parent.session, process: h.process, launch: h.launch, snapshot: snapshot, native: native, initial: before, initialState: initial, previous: initial, current: initial}
	h.measurementEpoch.Add(1)
	h.mtu = owner
	if beginErr != nil {
		return owner, true, beginErr
	}
	if native.record.Reader != before.Reader || native.state() != initial || native.verifyReaderChange != nil {
		return owner, true, errors.New("macOS paired MTU begin replaced original reader")
	}
	native.verifyReaderChange = owner.verifyReaderChangeLocked
	owner.admitted = true
	return owner, true, owner.currentLocked(ctx)
}
func (owner *desktopMacOSPairedNodeMTUOwner) originalLocked() error {
	if owner == nil || owner.host == nil || owner.parent == nil || owner.session == nil || owner.process == nil || owner.launch == nil || owner.native == nil {
		return errors.New("macOS paired MTU lost original owner")
	}
	h := owner.host
	if h.mtu != owner || h.parent != owner.parent || owner.parent.session != owner.session || h.process != owner.process || h.launch != owner.launch || owner.launch.pairedNode != h || owner.process.parent != owner.parent || owner.process.command != owner.launch.command || owner.native.launch != owner.launch || owner.native.record.Session != owner.initial.Session || owner.native.record.Config != owner.initial.Config || owner.native.record.Path != owner.initial.Path || owner.native.family != owner.initialState.Family || owner.native.originalMTU != owner.initial.MTU {
		return errors.New("macOS paired MTU substituted retained ownership")
	}
	return nil
}
func (owner *desktopMacOSPairedNodeMTUOwner) currentLocked(ctx context.Context) error {
	if owner == nil || owner.closed || owner.retired || !owner.admitted {
		return errors.New("macOS paired MTU lease is not admitted")
	}
	if err := owner.originalLocked(); err != nil {
		return err
	}
	if err := validateDesktopMacOSPairedNodeMTUSnapshotLocked(owner.host, owner.snapshot); err != nil {
		return err
	}
	live, err := readDesktopMacOSPairedNodeMTURecordLocked(ctx, owner.host)
	if err != nil || !sameDesktopMacOSMTUReadback(live, owner.native.record) {
		return errors.Join(err, errors.New("macOS paired MTU status differs from original lease"))
	}
	return ctx.Err()
}
func (h *desktopMacOSPairedNodeHost) validateMTUReaderChange(ctx context.Context, native *desktopNodeMTUOwner, next desktopNodeMTURecord) error {
	if h == nil || h.mtu == nil || h.mtu.native != native || native == nil || native.launch != h.launch || native.verifyReaderChange == nil {
		return errors.New("macOS paired MTU changed its installed native verifier")
	}
	if next.Reader == native.record.Reader && next.Index == native.record.Index && next.Interface == native.record.Interface {
		return nil
	}
	return native.verifyReaderChange(ctx, native.record, next)
}
func (owner *desktopMacOSPairedNodeMTUOwner) enterCurrent(ctx context.Context) (func(), error) {
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
	if err := owner.host.refreshExpiredReaderLocked(ctx); err != nil {
		release()
		return nil, err
	}
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
func (owner *desktopMacOSPairedNodeMTUOwner) verifyReaderChangeLocked(ctx context.Context, old, next desktopNodeMTURecord) error {
	if err := owner.originalLocked(); err != nil {
		return err
	}
	if !sameDesktopMacOSMTUReadback(old, owner.native.record) || next.Reader <= old.Reader || old.Index == next.Index || old.Session != next.Session || old.Config != next.Config || old.Path != next.Path {
		return errors.New("macOS paired Node MTU successor changed its original acknowledged predecessor")
	}
	if err := validateDesktopMacOSPairedNodeMTUSnapshotLocked(owner.host, owner.snapshot); err != nil {
		return err
	}
	live, err := readDesktopNodeMTUContext(ctx, owner.launch)
	if err != nil || !sameDesktopMacOSMTUReadback(live, next) {
		return errors.Join(err, errors.New("macOS paired MTU successor lacks its exact full native ACK proof"))
	}
	interfaces, err := desktopnetwork.InterfacesContext(ctx)
	if err != nil {
		return err
	}
	if err := validateDesktopMacOSPairedNodeReaderRetirement(old, next, interfaces); err != nil {
		return err
	}
	if _, err := owner.host.proveReaderLocked(ctx, next); err != nil {
		return err
	}
	copy := next
	owner.host.reader = &copy
	owner.host.measurementEpoch.Add(1)
	return ctx.Err()
}

func (owner *desktopMacOSPairedNodeMTUOwner) Read() (mtuKernelState, error) {
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
func (owner *desktopMacOSPairedNodeMTUOwner) Change(expected mtuKernelState, mtu int) (mtuKernelState, error) {
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
func (owner *desktopMacOSPairedNodeMTUOwner) Commit() error {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	release, err := owner.enterCurrent(ctx)
	if err != nil {
		return err
	}
	defer release()
	return owner.native.commitWithValidationContext(ctx, owner.currentLocked)
}

func (owner *desktopMacOSPairedNodeMTUOwner) Restore() (mtuKernelState, error) {
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
func (owner *desktopMacOSPairedNodeMTUOwner) closeRetiredLocked(ctx context.Context) error {
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
func (owner *desktopMacOSPairedNodeMTUOwner) Close() error {
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
	live, err := readDesktopMacOSPairedNodeMTURecordLocked(ctx, owner.host)
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
func (owner *desktopMacOSPairedNodeMTUOwner) CleanupRestored() (mtuKernelState, bool) {
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
func (owner *desktopMacOSPairedNodeMTUOwner) validateMTUInterfaceSuccession(initial, previous, next mtuKernelState, cleanup bool) error {
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

// An independently expired lease may publish its original rollback before a
// foreground Read. Adopt it only through the retained raw nonce/generation
// verifier, which performs the same kernel absence and paired reproof callback.
// Call only under host.gate and before taking native.mu, never from a callback.
func (h *desktopMacOSPairedNodeHost) refreshExpiredReaderLocked(ctx context.Context) error {
	if h.mtu == nil || h.reader == nil {
		return nil
	}
	live, err := readDesktopNodeMTUContext(ctx, h.launch)
	if err != nil {
		return err
	}
	if live.Reader == h.reader.Reader && live.Index == h.reader.Index && live.Interface == h.reader.Interface {
		return nil
	}
	if !live.Expired || !live.Restored || live.Active || live.Failure != "captured MTU lease expired; original MTU restored" {
		return errors.New("macOS paired Node has an unacknowledged changed reader")
	}
	if _, err := h.mtu.native.ReadContext(ctx); err != nil && !errors.Is(err, errDesktopNodeMTUExpired) {
		return err
	}
	if h.reader.Reader != live.Reader || h.reader.Index != live.Index || h.reader.Interface != live.Interface {
		return errors.New("macOS paired Node expiry did not adopt exact original rollback reader")
	}
	return nil
}

// The outer exporter may expose the original interface only for this exact
// retained bridge. This reads immutable captures without entering native locks.
func (owner *desktopMacOSPairedNodeMTUOwner) validatePairedMTUInterfaceScope(outer *mtuLiveOwner) error {
	if owner == nil || outer == nil || owner.host == nil || owner.parent == nil || owner.launch == nil ||
		outer.kernel != owner || outer.a != owner.parent.app || outer.command != owner.launch.command ||
		owner.host.launch != owner.launch || owner.launch.pairedNode != owner.host ||
		outer.snapshot.Multihop != nil || outer.snapshot.ProfileToken != owner.snapshot.ProfileToken ||
		outer.snapshot.SessionID != owner.snapshot.SessionID || outer.snapshot.SelectedID != owner.snapshot.SelectedID ||
		outer.snapshot.StateToken != owner.snapshot.StateToken || outer.snapshot.Mode != owner.snapshot.Mode ||
		desktopOwnedNodeProfileToken(outer.snapshot.Profile) != desktopOwnedNodeProfileToken(owner.snapshot.Profile) ||
		outer.initial != owner.initialState || !desktopNodeChainDarwinInterfaceName(outer.initial.Interface) {
		return errors.New("MTU interface scope substituted its original paired Darwin owner")
	}
	return nil
}
