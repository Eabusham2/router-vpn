//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"router-vpn/internal/mobilemultihop"
)

// This owner is created only from the existing original session's activated
// host. It does not register a legacy desktopNodeOwner, start another process
// waiter, reopen an interface for writes, or reconstruct a session from files.
// Host gate protects this wrapper and serializes its private mailbox with
// retirement. The mailbox retains every pending command until exact discharge.
type desktopLinuxNodeMTUOwner struct {
	host        *desktopLinuxNodeHost
	session     *desktopLinuxNodeSession
	activation  *desktopLinuxNodeActivation
	process     *desktopLinuxNodeProcess
	transaction *desktopLinuxNodeTransaction
	launch      *desktopNodeLaunch
	snapshot    mtuRetestSnapshot
	native      *desktopNodeMTUOwner
	initial     desktopNodeMTURecord
	closed      bool
	restored    bool
	cleanup     mtuKernelState
}

func sameDesktopNodeMTUReadback(a, b desktopNodeMTURecord) bool {
	a.Heartbeat, b.Heartbeat = 0, 0
	return a == b
}

// Lock order is original session -> host -> transaction/native owner -> app
// as required by the called native observers. Parent gate is released before
// either session or host is entered. Empty current sessions may defer to an
// unrelated legacy path; malformed, replaced or partially active ones cannot.
func withDesktopLinuxNodeMTUHost(ctx context.Context, a *app, action func(*desktopLinuxNodeSession, *desktopLinuxNodeHost) error) (bool, error) {
	if a == nil {
		return false, nil
	}
	a.mu.Lock()
	controller := a.localController
	a.mu.Unlock()
	if controller == nil || controller.nodeParent == nil {
		return false, nil
	}
	p, ok := controller.nodeParent.(*desktopLinuxNodeParent)
	if !ok || p == nil || p.gate == nil || ctx == nil || ctx.Err() != nil {
		return true, errors.New("Linux MTU capture has no current original native parent")
	}
	select {
	case <-ctx.Done():
		return true, ctx.Err()
	case <-p.gate:
	}
	s := p.session
	p.gate <- struct{}{}
	if s == nil {
		return false, nil
	}
	if err := s.enter(ctx); err != nil {
		return true, err
	}
	defer func() { s.gate <- struct{}{} }()
	if s.parent == nil || s.parent.app != a || s.parent.controller != controller || s.parent.parent != p {
		return true, errors.New("Linux MTU capture substituted its original application session")
	}
	if err := s.currentLocked(ctx); err != nil {
		return true, err
	}
	h := s.active
	if h == nil {
		return false, nil
	}
	if _, conflict := desktopNodeOwners.Load(a); conflict {
		return true, errors.New("Linux MTU capture has conflicting native process ownership")
	}
	if err := h.enter(ctx); err != nil {
		return true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.external != nil {
		if err := h.observeLocked(ctx); err != nil {
			return true, err
		}
		return false, nil // Its existing typed external MTU owner serves this path.
	}
	if !sameDesktopLinuxParentCapture(h.parent, s.parent) || h.activation == nil || h.transaction == nil ||
		h.transaction.journal != s.journal || h.activation.matches(h) != nil {
		return true, errors.New("Linux MTU capture has no original proved active host")
	}
	return true, action(s, h)
}

func desktopLinuxMTUFamily(snapshot mtuRetestSnapshot) (int, error) {
	host := strings.Trim(strings.TrimSpace(snapshot.Profile.DAITAHost), "[]")
	if host == "" {
		host = "10.77.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return 0, errors.New("Linux MTU capture requires its literal private benchmark address")
	}
	if ip.To4() != nil {
		return 4, nil
	}
	return 6, nil
}

func validateDesktopLinuxMTUSnapshot(h *desktopLinuxNodeHost, snapshot mtuRetestSnapshot) error {
	if h == nil || h.parent == nil || h.parent.app == nil || h.launch == nil || snapshot.Multihop != nil || snapshot.Profile.ID != h.launch.profileID ||
		snapshot.Mode != h.launch.mode || snapshot.State.RouterID != h.launch.profileID || !snapshot.State.Connected ||
		snapshot.State.Phase != "connected" || strings.ToLower(strings.TrimSpace(snapshot.Profile.MTUPolicy)) != "auto" ||
		desktopOwnedNodeProfileToken(snapshot.Profile) != h.revision ||
		[3]bool{snapshot.Profile.DAITAEnabled, snapshot.Profile.JumboTUN, snapshot.Profile.SocksEnabled} != h.savedOptions ||
		[3]bool{snapshot.State.DAITA, snapshot.State.Jumbo, snapshot.State.Socks} != h.options {
		return errors.New("Linux MTU Retest changed its captured active Auto profile")
	}
	return validateMTURetestSnapshot(h.parent.app, snapshot)
}

func captureDesktopPlatformMTUSnapshot(a *app, snapshot mtuRetestSnapshot) (live mtuLiveSnapshot, handled bool, failure error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	handled, failure = withDesktopLinuxNodeMTUHost(ctx, a, func(_ *desktopLinuxNodeSession, h *desktopLinuxNodeHost) error {
		if err := validateDesktopLinuxMTUSnapshot(h, snapshot); err != nil {
			return err
		}
		_, record, err := h.readReadyLocked(ctx, false) // Same active native observation as host.Current.
		if err != nil {
			return err
		}
		if record.Active || record.Failure != "" || h.mtu != nil {
			return errors.New("Linux MTU snapshot cannot replace an outstanding original lease")
		}
		family, err := desktopLinuxMTUFamily(snapshot)
		if err != nil {
			return err
		}
		copy := record
		live = mtuLiveSnapshot{Interface: record.Interface, Family: family, OriginalMTU: record.MTU, nodeRecord: &copy}
		return nil
	})
	return
}

func openDesktopPlatformMTUOwner(a *app, snapshot mtuRetestSnapshot, live mtuLiveSnapshot, token string, command *exec.Cmd) (owner mtuKernelOwner, handled bool, failure error) {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	handled, failure = withDesktopLinuxNodeMTUHost(ctx, a, func(s *desktopLinuxNodeSession, h *desktopLinuxNodeHost) error {
		if err := validateDesktopLinuxMTUSnapshot(h, snapshot); err != nil {
			return err
		}
		_, before, err := h.readReadyLocked(ctx, false)
		family, familyErr := desktopLinuxMTUFamily(snapshot)
		if err != nil || familyErr != nil || command == nil || command != h.process.command || h.mtu != nil ||
			live.nodeRecord == nil || !sameDesktopNodeMTUReadback(before, *live.nodeRecord) || before.Active || before.Failure != "" ||
			before.Interface != live.Interface || before.MTU != live.OriginalMTU || live.Family != family {
			return errors.Join(err, familyErr, errors.New("Linux MTU opening lost its exact captured original TUN reader"))
		}
		kernel, beginErr := openDesktopNodeMTUOwner(h.launch, live, token)
		native, ok := kernel.(*desktopNodeMTUOwner)
		if !ok || native == nil {
			return errors.Join(beginErr, errors.New("Linux MTU opening returned no retained original lease"))
		}
		captured := &desktopLinuxNodeMTUOwner{host: h, session: s, activation: h.activation, process: h.process,
			transaction: h.transaction, launch: h.launch, snapshot: snapshot, native: native, initial: before}
		h.mtu, owner = captured, captured // Retain even a failed begin before releasing the host gate.
		if beginErr != nil {
			return beginErr
		}
		return captured.currentLocked(ctx)
	})
	if !handled && live.nodeRecord != nil {
		return nil, true, errors.New("captured Linux MTU host disappeared before opening its lease")
	}
	return
}

// This comparison retains cleanup authority only for these original objects.
// Saved profile/network changes do not retarget the lease, and do not erase
// the old owner's responsibility to restore or prove authenticated retirement.
func (owner *desktopLinuxNodeMTUOwner) originalLocked() error {
	if owner == nil {
		return errors.New("Linux MTU has no retained original lease")
	}
	h := owner.host
	if h == nil || owner.session == nil || owner.activation == nil || owner.process == nil || owner.transaction == nil ||
		owner.launch == nil || owner.native == nil || h.mtu != owner || h.activation != owner.activation || h.process != owner.process ||
		h.transaction != owner.transaction || h.launch != owner.launch || owner.native.launch != owner.launch ||
		owner.activation.host != h || owner.activation.process != owner.process || owner.activation.transaction != owner.transaction ||
		owner.activation.launch != owner.launch || owner.activation.policy != h.policy || owner.activation.selection != h.selection ||
		owner.activation.options != h.options || owner.activation.savedOptions != h.savedOptions ||
		!sameDesktopLinuxParentCapture(h.parent, owner.activation.parent) ||
		!sameDesktopLinuxParentCapture(h.parent, owner.session.parent) || !sameDesktopLinuxParentCapture(h.parent, owner.process.parent) ||
		!sameDesktopLinuxParentCapture(h.parent, owner.transaction.parent) || owner.transaction.journal != owner.session.journal ||
		owner.transaction.process != owner.process || owner.transaction.policy != h.policy || owner.transaction.selection != h.selection ||
		owner.transaction.options != h.options || owner.transaction.savedOptions != h.savedOptions ||
		owner.process.command == nil || owner.process.command != owner.launch.command ||
		owner.native.record.Session != owner.initial.Session || owner.native.record.Config != owner.initial.Config ||
		owner.native.record.Path != owner.initial.Path || owner.native.record.Interface != owner.initial.Interface ||
		owner.launch.mtuSession != owner.initial.Session || owner.launch.configSHA256 != owner.initial.Config {
		return errors.New("Linux MTU lease substituted its original host, process or private reader")
	}
	return nil
}

// Caller holds the original host gate. The native Read/Change/Commit is
// bracketed by the same active readiness/policy readback used by host.Current.
func (owner *desktopLinuxNodeMTUOwner) currentLocked(ctx context.Context) error {
	if owner.closed || owner.originalLocked() != nil || owner.activation.matches(owner.host) != nil ||
		validateDesktopLinuxMTUSnapshot(owner.host, owner.snapshot) != nil {
		return errors.New("Linux MTU measurement lost its original active session")
	}
	_, live, err := owner.host.readReadyLocked(ctx, false)
	if err != nil || !sameDesktopNodeMTUReadback(live, owner.native.record) {
		return errors.Join(err, errors.New("Linux MTU native reader differs from its exact lease acknowledgement"))
	}
	return nil
}

func (owner *desktopLinuxNodeMTUOwner) enterCurrent(ctx context.Context) (func(), error) {
	if owner == nil || owner.session == nil || owner.host == nil {
		return nil, errors.New("Linux MTU has no original live owner")
	}
	s, h := owner.session, owner.host
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	if err := s.currentLocked(ctx); err != nil || s.active != h {
		s.gate <- struct{}{}
		return nil, errors.Join(err, errors.New("Linux MTU belongs to a replaced retained session"))
	}
	if err := h.enter(ctx); err != nil {
		s.gate <- struct{}{}
		return nil, err
	}
	release := func() { h.gate <- struct{}{}; s.gate <- struct{}{} }
	if err := owner.currentLocked(ctx); err != nil {
		release()
		return nil, err
	}
	if _, conflict := desktopNodeOwners.Load(h.parent.app); conflict {
		release()
		return nil, errors.New("Linux MTU observation has conflicting native process ownership")
	}
	return release, nil
}

func (owner *desktopLinuxNodeMTUOwner) Read() (mtuKernelState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	release, err := owner.enterCurrent(ctx)
	if err != nil {
		return mtuKernelState{}, err
	}
	defer release()
	state, err := owner.native.Read()
	return state, errors.Join(err, owner.currentLocked(ctx))
}

func (owner *desktopLinuxNodeMTUOwner) Change(expected mtuKernelState, mtu int) (mtuKernelState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	release, err := owner.enterCurrent(ctx)
	if err != nil {
		return mtuKernelState{}, err
	}
	defer release()
	state, err := owner.native.Change(expected, mtu)
	return state, errors.Join(err, owner.currentLocked(ctx))
}

func (owner *desktopLinuxNodeMTUOwner) Commit() error {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	release, err := owner.enterCurrent(ctx)
	if err != nil {
		return err
	}
	defer release()
	return owner.native.commitWithValidation(func() error { return owner.currentLocked(ctx) })
}

func (owner *desktopLinuxNodeMTUOwner) cleanupCurrentLocked(ctx context.Context) error {
	if err := owner.originalLocked(); err != nil {
		return err
	}
	return owner.host.parent.retirementCurrent(ctx)
}

func (owner *desktopLinuxNodeMTUOwner) Restore() (mtuKernelState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	if owner == nil || owner.host == nil {
		return mtuKernelState{}, errors.New("Linux MTU rollback has no original owner")
	}
	if err := owner.host.enter(ctx); err != nil {
		return mtuKernelState{}, err
	}
	defer func() { owner.host.gate <- struct{}{} }()
	if owner.closed || owner.cleanupCurrentLocked(ctx) != nil {
		return mtuKernelState{}, errors.New("Linux MTU rollback lost its original cleanup capture")
	}
	if err := owner.cleanupReaderAvailableLocked(); err != nil {
		return mtuKernelState{}, err
	}
	state, err := owner.native.Restore()
	return state, errors.Join(err, owner.cleanupReadbackLocked(ctx))
}

func (owner *desktopLinuxNodeMTUOwner) cleanupReadbackLocked(ctx context.Context) error {
	if err := owner.cleanupCurrentLocked(ctx); err != nil {
		return err
	}
	live, err := readDesktopNodeMTU(owner.launch)
	if err != nil || !sameDesktopNodeMTUReadback(live, owner.native.record) {
		return errors.Join(err, errors.New("Linux MTU cleanup lost its exact original native readback"))
	}
	return desktopLinuxNodeTUNCurrent(live)
}

// A stopped.json file alone cannot discharge this Linux host's outstanding
// lease. The original authenticated source must have retired and its original
// Cmd.Wait must already have joined, with the exact captured TUN absent.
func (owner *desktopLinuxNodeMTUOwner) retiredLocked(ctx context.Context) error {
	t := owner.transaction
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer func() { t.gate <- struct{}{} }()
	if !t.complete || !t.retired || !t.engineJoined || t.pending != nil || t.retirement == nil || t.retirement.Validate() != nil ||
		t.prepared == nil || t.retirement.Source == nil || !reflect.DeepEqual(t.retirement.Prepared, t.prepared) ||
		owner.process.command.ProcessState == nil {
		return errors.New("Linux MTU retirement preceded its authenticated source and original engine join")
	}
	select {
	case <-owner.process.joined:
	default:
		return errors.New("Linux MTU retirement preceded its original Cmd.Wait completion")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if iface.Name == owner.initial.Interface || iface.Index == owner.initial.Index || iface.Index == owner.native.record.Index {
			return errors.New("Linux MTU retirement retained or replaced its captured TUN")
		}
	}
	return owner.cleanupCurrentLocked(ctx)
}

// Only the original host's explicit retirement calls this after t.Retire.
// Native rollback can no longer complete once a failing graph is waiting for
// the original parent's ACK. Retain its exact lease until the authenticated
// source, original Cmd.Wait and actual interface absence all prove retirement.
// No numeric rollback or committed-MTU result is manufactured from that fact.
func (owner *desktopLinuxNodeMTUOwner) finishRetirementLocked(ctx context.Context) error {
	if err := owner.cleanupCurrentLocked(ctx); err != nil {
		return err
	}
	if err := owner.retiredLocked(ctx); err != nil {
		return err
	}
	owner.native.mu.Lock()
	owner.native.closed, owner.native.runtimeRetired = true, true
	owner.native.pending = nil
	owner.native.discardCommitRevert()
	owner.native.mu.Unlock()
	owner.cleanup, owner.restored = mtuKernelState{}, false
	owner.closed = true
	owner.host.mtu = nil
	return nil
}

func (owner *desktopLinuxNodeMTUOwner) cleanupReaderAvailableLocked() error {
	h := owner.host
	if h.ready == nil {
		return errors.New("Linux MTU cleanup has no captured original readiness")
	}
	digest, err := h.selection.ControlSHA256()
	if err != nil {
		return err
	}
	raw, err := readDesktopRuntimeFile(owner.launch, "node-ready.json", mobilemultihop.DesktopNodeReadyRecordLimit)
	if err != nil {
		// The child removes readiness when graph cleanup starts, before it
		// waits for the original parent's retirement ACK. Keep this lease and
		// return promptly; spending its ACK window on another mailbox command
		// could prevent authenticated retirement. Absence proves no cleanup.
		return errors.Join(err, errors.New("Linux MTU cleanup requires original source retirement after readiness loss"))
	}
	ready, err := mobilemultihop.ParseDesktopNodeReadyRecord(raw, h.policy, digest)
	if err != nil || ready != *h.ready {
		return errors.Join(err, errors.New("Linux MTU cleanup changed its original readiness capture"))
	}
	return nil
}

// Called under host gate by both checked wrapper Close and original host
// retirement. It never takes the outer HTTP-owner lock or acquires session
// gate from host gate. Failed drain leaves h.mtu and the exact pending lease.
func (owner *desktopLinuxNodeMTUOwner) closeLocked(ctx context.Context) error {
	if owner.closed {
		return nil
	}
	if err := owner.cleanupCurrentLocked(ctx); err != nil {
		return err
	}
	if err := owner.cleanupReaderAvailableLocked(); err != nil {
		return err
	}
	if err := owner.native.Close(); err != nil {
		return err
	}
	if owner.native.runtimeRetired {
		if err := owner.retiredLocked(ctx); err != nil {
			return err
		}
	} else if err := owner.cleanupReadbackLocked(ctx); err != nil {
		return err
	}
	owner.cleanup, owner.restored = owner.native.CleanupRestored()
	owner.closed = true
	owner.host.mtu = nil
	return nil
}

func (owner *desktopLinuxNodeMTUOwner) Close() error {
	if owner == nil || owner.host == nil {
		return errors.New("Linux MTU cleanup has no original host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	if err := owner.host.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.host.gate <- struct{}{} }()
	return owner.closeLocked(ctx)
}

func (owner *desktopLinuxNodeMTUOwner) CleanupRestored() (mtuKernelState, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if owner == nil || owner.host == nil || owner.host.enter(ctx) != nil {
		return mtuKernelState{}, false
	}
	defer func() { owner.host.gate <- struct{}{} }()
	return owner.cleanup, owner.closed && owner.restored
}
