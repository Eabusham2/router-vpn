//go:build linux

package main

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
)

// Only Activate creates this one-shot capability after the actual routed
// proof and final native readbacks. It retains the original owners separately
// from the startup request, which ordinary request completion always cancels.
// Neither Connected nor a saved/decoded readiness record creates this owner.
type desktopLinuxNodeActivation struct {
	host        *desktopLinuxNodeHost
	parent      *desktopLinuxNodeParentCapture
	operation   context.Context
	process     *desktopLinuxNodeProcess
	transaction *desktopLinuxNodeTransaction
	policy      *mobilemultihop.DesktopNodePolicy
	launch      *desktopNodeLaunch
	selection   linuxprotection.NodeSelection
	network     string
	revision    string
	options     [3]bool
	proof       desktopLinuxNodeProof
	activatedAt time.Time
	lifetime    context.Context
	cancel      context.CancelFunc
}

func validateDesktopLinuxNodeActivationProof(proof *desktopLinuxNodeProof, ready mobilemultihop.DesktopNodeReadyRecord,
	live desktopNodeMTURecord, started, now time.Time, seconds int) error {
	// Round(0) strips the monotonic clock. These private timestamps must come
	// from this running host, never from a serialized historical measurement.
	if proof == nil || seconds < 1 || seconds > 300 || started.IsZero() || started == started.Round(0) ||
		proof.provedAt.IsZero() || proof.provedAt == proof.provedAt.Round(0) || now == now.Round(0) ||
		proof.provedAt.Before(started) || now.Sub(proof.provedAt) < 0 || now.Sub(proof.provedAt) > 30*time.Second ||
		proof.elapsed <= 0 || proof.elapsed > time.Duration(seconds)*time.Second || proof.elapsed > proof.provedAt.Sub(started) ||
		proof.ready != ready || !sameDesktopLinuxNodeProofTUN(proof.live, live) || live.Active || live.Failure != "" {
		return errors.New("Linux Node activation lost its fresh original routed proof and native reader")
	}
	return nil
}

// matches compares retained private owners only. Every caller also performs
// the original native process, journal, running-policy and readiness checks.
// A finished startup context is deliberately not a lifetime failure here.
func (active *desktopLinuxNodeActivation) matches(h *desktopLinuxNodeHost) error {
	if active == nil || h == nil || active.host != h || h.activation != active || active.parent == nil ||
		active.parent != h.parent || active.operation == nil || active.operation != h.operation ||
		active.process == nil || active.process != h.process || active.transaction == nil || active.transaction != h.transaction ||
		active.policy == nil || active.policy != h.policy || active.launch == nil || active.launch != h.launch ||
		active.selection != h.selection || active.network == "" || active.network != h.network || active.revision != h.revision || active.options != h.options ||
		active.lifetime == nil || active.lifetime.Err() != nil || active.cancel == nil || h.proof == nil || *h.proof != active.proof ||
		h.ready == nil || *h.ready != active.proof.ready || active.activatedAt.IsZero() || active.activatedAt == active.activatedAt.Round(0) ||
		active.activatedAt.Sub(active.proof.provedAt) < 0 || active.activatedAt.Sub(active.proof.provedAt) > 30*time.Second {
		return errors.New("Linux Node lost its original proved activation capability")
	}
	t, p := active.transaction, active.process
	if !sameDesktopLinuxParentCapture(t.parent, active.parent) || !sameDesktopLinuxParentCapture(p.parent, active.parent) ||
		t.process != p || t.policy != active.policy || t.selection != active.selection || t.operation != active.operation ||
		t.profileID != active.launch.profileID || t.revision != active.revision || t.network != active.network || t.options != active.options ||
		p.ctx == nil || p.ctx.Err() != nil || !p.Started() || p.retiring.Load() || p.joined == nil || p.command == nil || p.command != active.launch.command {
		return errors.New("Linux Node activation substituted an original transaction or process")
	}
	select {
	case <-p.joined:
		return errors.New("Linux Node activation outlived its original joined engine")
	default:
	}
	return nil
}

func (h *desktopLinuxNodeHost) revokeActivationLocked() {
	if h != nil && h.activation != nil && h.activation.cancel != nil {
		h.activation.cancel()
	}
}

// Activate is the sole private transition from proved Starting to Connected.
// The original operation still has to be live at the final app-lock commit.
// It creates no public Linux mode admission or replacement cleanup authority.
func (h *desktopLinuxNodeHost) Activate(parent context.Context) (failure error) {
	if err := h.enter(parent); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.activation != nil {
		return errors.New("Linux Node activation cannot reuse an entered original capability")
	}
	defer func() {
		if failure != nil {
			failure = h.failProofLocked(failure)
		}
	}()
	if h.proof == nil || h.ready == nil || h.operation == nil || h.operation.Err() != nil {
		return errors.New("Linux Node activation preceded its original live routed proof")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	stop := context.AfterFunc(h.operation, cancel)
	defer func() { stop(); cancel() }()
	if _, err := h.capturedProofProfile(); err != nil {
		return err
	}
	ready, live, err := h.readReadyLocked(ctx, false)
	if err != nil {
		return err
	}
	a := h.parent.app
	a.mu.Lock()
	seconds := a.cfg.AutoTestSeconds
	a.mu.Unlock()
	if err := validateDesktopLinuxNodeActivationProof(h.proof, ready, live, h.started, time.Now(), seconds); err != nil {
		return err
	}
	t := h.transaction
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer func() { t.gate <- struct{}{} }()
	if t.process != h.process || t.policy != h.policy || t.selection != h.selection || !t.complete || !t.served || !t.admitted ||
		!t.nativeCommitted || t.stopRequested.Load() || t.retiring || t.retirement != nil || t.closed || t.retired || t.pending != nil {
		return errors.New("Linux Node activation lost its original admitted durable transaction")
	}
	if err := t.accepted(ctx); err != nil {
		return err
	}
	if err := t.checkHead(ctx); err != nil {
		return err
	}
	if err := t.control.Current(ctx); err != nil {
		return err
	}
	// Parent/native observations above may acquire app.mu. The final commit
	// uses only the already retained original capture's lock-aware comparison.
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, exists := a.profileByIDLocked(h.launch.profileID)
	if ctx.Err() != nil || h.parent.currentAppLocked(false) != nil ||
		a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.connectionCancelIntent == h.operation ||
		physicalNetworkIdentity() != h.network ||
		!exists || desktopOwnedNodeProfileToken(profile) != h.revision ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != h.options ||
		a.cmd != h.process.command || a.state.Connected || a.state.Phase != "starting" ||
		a.state.RouterID != h.launch.profileID || a.state.RuntimeMode != h.launch.mode ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != h.options ||
		h.process.ctx == nil || h.process.ctx.Err() != nil || t.stopRequested.Load() {
		return errors.New("Linux Node activation lost its original request, controller or connection slot")
	}
	select {
	case <-h.process.joined:
		return errors.New("Linux Node activation followed its original engine exit")
	default:
	}
	now := time.Now()
	if err := validateDesktopLinuxNodeActivationProof(h.proof, ready, live, h.started, now, a.cfg.AutoTestSeconds); err != nil {
		return err
	}
	lifetime, stopLifetime := context.WithCancel(h.parent.lifetime)
	if lifetime.Err() != nil {
		stopLifetime()
		return errors.New("Linux Node activation lost its original controller lifetime")
	}
	h.activation = &desktopLinuxNodeActivation{host: h, parent: h.parent, operation: h.operation, process: h.process,
		transaction: t, policy: h.policy, launch: h.launch, selection: h.selection, network: h.network, revision: h.revision,
		options: h.options, proof: *h.proof, activatedAt: now, lifetime: lifetime, cancel: stopLifetime}
	a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""
	return nil
}

// Current is an observation of this exact proved session. Request completion
// cannot supply or remove its authority, and presentation state cannot create
// one. The caller retains retirement responsibility for a failed observation.
func (h *desktopLinuxNodeHost) Current(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.activation == nil {
		return errors.New("Linux Node has no original proved active session")
	}
	_, _, err := h.readReadyLocked(ctx, false)
	return err
}
