package main

import (
	"context"
	"errors"
	"time"
)

type selectedDNSProbe func(context.Context, *app, observedConnection, string) dnsProofState

func (t *sessionTracker) dnsProofPathContext(sessionID string, s observedConnection, runtimeID string) (context.Context, func(), error) {
	// A detached tracker must not create another process observer while proving
	// a path. Production registers its tracker before starting the loop.
	if owner, ok := sessionTrackers.Load(t.a); !ok || owner != t {
		return nil, nil, errors.New("DNS proof has no matching process session owner")
	}
	before := t.snapshot(0)
	if before.ID != sessionID || before.RouterID != s.RouterID || before.ActualMode != runtimeID || before.ActualBase != s.Base {
		return nil, nil, errors.New("DNS proof observation no longer belongs to the active session")
	}
	st := state{Connected: s.Connected, Phase: s.Phase, Mode: s.Mode, LogicalMode: s.LogicalMode, RuntimeMode: s.RuntimeMode, Base: s.Base, RouterID: s.RouterID}
	ctx, stop, _, err := asyncMeasurementPathContext(context.Background(), t.a, s.Profile, st, before, asyncMeasurementProfileToken(s.Profile))
	return ctx, stop, err
}

func (t *sessionTracker) discardDNSProof(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == nil || t.session.ID != sessionID {
		return
	}
	t.dnsProofRunning = false
	t.dnsProofLastAttempt = time.Time{}
	t.dnsProofBinding = nil
	t.session.DNSProof = dnsProofState{Status: "not-proven", Reason: "active VPN session, graph, credentials or DNS policy changed while DNS proof was running; stale result discarded"}
	t.eventLocked("dns-proof-stale", t.session.Phase, t.session.DNSProof.Reason, t.session.Connected, t.session.ActualMode, t.session.ActualBase)
}

func (t *sessionTracker) proveDNSAsyncWithProbe(sessionID string, s observedConnection, runtimeID string, probe selectedDNSProbe) {
	ctx, stop, err := t.dnsProofPathContext(sessionID, s, runtimeID)
	if err != nil {
		t.discardDNSProof(sessionID)
		return
	}
	defer stop()
	if probe == nil {
		t.discardDNSProof(sessionID)
		return
	}
	proof := probe(ctx, t.a, s, runtimeID)
	// The same immutable binding validates both the in-flight network work
	// and publication. Never wait for a connection/settings transaction or
	// hold its locks while contacting a resolver.
	release, err := t.a.beginAsyncMeasurementAdoption(ctx)
	if err != nil {
		t.discardDNSProof(sessionID)
		return
	}
	defer release()
	t.dnsProofRunning = false
	t.dnsProofBinding = nil
	t.session.DNSProof = proof
	if proof.Status == "passed" {
		t.dnsProofBinding, _ = ctx.Value(asyncMeasurementBindingKey{}).(*asyncMeasurementAdoption)
	}
	t.eventLocked("dns-proof", t.session.Phase, proof.Reason, t.session.Connected, t.session.ActualMode, t.session.ActualBase)
}

// Caller holds tracker.mu. A previous successful proof must not survive a
// later same-session mode switch, graph replacement, or credential/policy edit.
// Keep the lock order tracker -> app used by terminal proof adoption.
func (t *sessionTracker) invalidateDNSProofBindingLocked() {
	if t.dnsProofBinding == nil || t.session == nil {
		return
	}
	t.a.mu.Lock()
	err := t.dnsProofBinding.validateLocked(t.session)
	t.a.mu.Unlock()
	if err != nil {
		t.dnsProofBinding = nil
		t.dnsProofLastAttempt = time.Time{}
		t.session.DNSProof = dnsProofState{Status: "not-proven", Reason: "the previously proved DNS session/path changed; a fresh resolver proof is required"}
	}
}
