package main

import "router-vpn/internal/common"

// The public session API exposes only an exit proved for its exact live path.
// Profile.PublicIP is historical metadata, not a current-session assertion.
// Keep this separate from snapshot: internal snapshot callers can already hold
// app.mu, whereas proof validation must take tracker.mu -> app.mu in that order.
func (t *sessionTracker) snapshotWithLiveExitProof() connectionSession {
	out := t.snapshot(0)
	out.ExitIP = ""
	if !out.Connected || out.Phase != "connected" || out.PathProof != "passed" {
		return out
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.a.mu.Lock()
	defer t.a.mu.Unlock()
	if owner, ok := sessionTrackers.Load(t.a); !ok || owner != t {
		return out
	}
	raw, ok := homeExitProofs.Load(t.a)
	proof, typed := raw.(*homeExitProof)
	if !ok || !typed || proof == nil || proof.At.IsZero() {
		return out
	}
	if validateHomeExitBindingLocked(t.a, t.session, proof) != nil ||
		validateHomeExitBindingLocked(t.a, &out, proof) != nil {
		return out
	}
	if ip, err := common.NormalizeExpectedPublicIP(proof.IP); err == nil {
		out.ExitIP = ip
	}
	return out
}
