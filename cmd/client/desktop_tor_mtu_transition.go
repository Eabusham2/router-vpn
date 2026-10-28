package main

import (
	"errors"
	"time"

	"router-vpn/internal/mobiletor"
)

var errDesktopTorMTUTransitionPending = errors.New("the captured Tor interface is completing its bounded MTU transaction")

func desktopTorTransitionFollows(previous *mobiletor.DesktopBridgeMTUTransition, next mobiletor.DesktopBridgeMTUTransition) bool {
	if previous == nil {
		return true
	}
	if next.TransitionID == previous.TransitionID {
		return next == *previous
	}
	return next.TransitionID > previous.TransitionID && next.FromHeartbeatAt > previous.FromHeartbeatAt && next.StartedAt >= previous.StartedAt
}

func noteDesktopTorStrictHeartbeat(owner *desktopTorRuntime, proof desktopTorProof) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := noteDesktopTorPaddingLocked(owner, proof, time.Now()); err != nil {
		return err
	}
	if proof.HeartbeatAt > owner.lastProofHeartbeat {
		owner.lastProofHeartbeat = proof.HeartbeatAt
	}
	if transition := owner.mtuTransition; transition != nil && proof.HeartbeatAt > transition.FromHeartbeatAt {
		owner.mtuRetiredTransition = transition.TransitionID
		owner.mtuTransition = nil
	}
	return nil
}

func noteDesktopTorPaddingLocked(owner *desktopTorRuntime, proof desktopTorProof, now time.Time) error {
	if err := owner.expected.ValidatePaddingProof(proof.Padding, proof.PaddingProof, owner.started, now); err != nil {
		return err
	}
	if err := mobiletor.ValidateDesktopPaddingProgress(owner.paddingReceipt, proof.Padding, owner.paddingProof, proof.PaddingProof); err != nil {
		return err
	}
	if proof.Padding != nil {
		receipt, witness := *proof.Padding, *proof.PaddingProof
		owner.paddingReceipt, owner.paddingProof = &receipt, &witness
	}
	return nil
}

// A transition receipt is only a bounded explanation for a paused heartbeat.
// It cannot authorize a result, DNS selection, connection proof or MTU save.
// Its base proof is verified at the exact pre-mutation publication time; the
// current process, workspace, source and physical network are checked outside
// this pure admission function on both sides of the read.
func acceptDesktopTorMTUTransition(owner *desktopTorRuntime, transition mobiletor.DesktopBridgeMTUTransition, baseRaw []byte, now time.Time) bool {
	if owner == nil || transition.Schema != 1 || transition.TransitionID == 0 || !validDesktopTorMTUReadback(&transition.From) ||
		transition.Generation != transition.From.Generation || transition.RequestID != transition.From.RequestID ||
		transition.TargetMTU < 1280 || transition.TargetMTU > 9000 || transition.StartedAt <= 0 || transition.ExpiresAt <= transition.StartedAt ||
		transition.ExpiresAt-transition.StartedAt > mobiletor.DesktopBridgeMTUTransitionLimit.Milliseconds() ||
		transition.StartedAt > now.Add(time.Second).UnixMilli() || now.UnixMilli() >= transition.ExpiresAt ||
		transition.FromHeartbeatAt < transition.StartedAt || transition.FromHeartbeatAt >= transition.ExpiresAt || transition.FromHeartbeatAt > now.Add(time.Second).UnixMilli() {
		return false
	}
	owner.mu.Lock()
	expected, authority, session := owner.expected, owner.mtuAuthority, owner.mtu
	if expected.MTUPolicy != "auto" || transition.SessionID != expected.SessionID || transition.SourceSHA256 != expected.SourceSHA256 || transition.ConfigSHA256 != expected.ConfigSHA256 ||
		authority.generation != transition.Generation || authority.request != transition.RequestID || session == nil || owner.adopted == nil ||
		transition.TransitionID <= owner.mtuRetiredTransition || owner.lastProofHeartbeat > transition.FromHeartbeatAt {
		owner.mu.Unlock()
		return false
	}
	if !desktopTorTransitionFollows(owner.mtuTransition, transition) {
		owner.mu.Unlock()
		return false
	}
	// Validation uses a separate owner value: historical admission must never
	// advance the live reader or refresh the connection's heartbeat.
	adopted := *owner.adopted
	captured := &desktopTorRuntime{expected: expected, started: owner.started, adopted: &adopted,
		mtu: session, mtuAuthority: authority, mtuReadback: owner.mtuReadback,
		paddingReceipt: owner.paddingReceipt, paddingProof: owner.paddingProof}
	owner.mu.Unlock()
	session.mu.Lock()
	active := session.generation == transition.Generation && (session.active == transition.RequestID || session.restoreMTU != 0)
	session.mu.Unlock()
	if !active {
		return false
	}
	base, err := validateDesktopTorProofAt(baseRaw, captured, time.UnixMilli(transition.FromHeartbeatAt), now)
	if err != nil || base.HeartbeatAt != transition.FromHeartbeatAt || base.MTUReadback == nil || *base.MTUReadback != transition.From {
		return false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.mtu != session || owner.mtuAuthority != authority || transition.TransitionID <= owner.mtuRetiredTransition || owner.lastProofHeartbeat > transition.FromHeartbeatAt {
		return false
	}
	if !desktopTorTransitionFollows(owner.mtuTransition, transition) {
		return false
	}
	if noteDesktopTorPaddingLocked(owner, base, now) != nil {
		return false
	}
	copy := transition
	owner.mtuTransition = &copy
	return true
}

func (a *app) desktopTorMTUTransitionPending(launch *desktopNodeLaunch) bool {
	if launch == nil || launch.tor == nil || a.desktopTorCurrent(launch) != nil {
		return false
	}
	launch.tor.proofMu.Lock()
	defer launch.tor.proofMu.Unlock()
	raw, err := readDesktopRuntimeFile(launch, "mtu-transition.json", 8192)
	var transition mobiletor.DesktopBridgeMTUTransition
	if err != nil || decodeRelayControlJSON(raw, &transition) != nil {
		return false
	}
	base, err := readDesktopRuntimeFile(launch, "proof.json", 64<<10)
	if err != nil || !acceptDesktopTorMTUTransition(launch.tor, transition, base, time.Now()) {
		return false
	}
	return a.desktopTorCurrent(launch) == nil
}

func (a *app) desktopTorMonitorCurrent(launch *desktopNodeLaunch) bool {
	if _, err := a.readDesktopTorProof(launch); err == nil {
		return true
	}
	if a.desktopTorMTUTransitionPending(launch) {
		return true
	}
	// The strict publication can advance while the transition reader checks
	// its old base. One new read resolves that race without accepting the base
	// as current proof or extending any transition deadline.
	_, err := a.readDesktopTorProof(launch)
	return err == nil
}
