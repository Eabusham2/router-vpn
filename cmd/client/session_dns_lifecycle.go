package main

import (
	"context"
	"strings"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// One budget covers admission, the original native observations and resolver
// proof. Lower operations keep their shorter deadlines; none can renew this
// worker or wait indefinitely before the path observer has been installed.
const sessionDNSProofBudget = 30 * time.Second

type sessionDNSProofWork struct {
	sessionID string
	runtimeID string
	routerID  string
	base      string
	profile   string
	cancel    context.CancelFunc
	done      chan struct{}
}

// The caller holds tracker.mu. Keep an old worker until it has actually
// returned, even if a new session has already replaced its visible status.
func (t *sessionTracker) startDNSProofLocked(sessionID string, s observedConnection, runtimeID string, probe selectedDNSProbe) {
	if t.dnsProofClosed || t.session == nil || t.session.ID != sessionID {
		return
	}
	if previous := t.dnsProofWork; previous != nil {
		select {
		case <-previous.done:
			t.dnsProofWork = nil
		default:
			return
		}
	}
	ctx, cancel := context.WithTimeout(t.observationContext(), sessionDNSProofBudget)
	work := &sessionDNSProofWork{sessionID: sessionID, runtimeID: runtimeID, routerID: s.RouterID, base: s.Base,
		profile: asyncMeasurementProfileToken(s.Profile), cancel: cancel, done: make(chan struct{})}
	t.dnsProofWork = work
	t.dnsProofRunning = true
	t.dnsProofLastAttempt = time.Now()
	t.session.DNSProof.Status = "checking"
	t.session.DNSProof.Reason = "verifying active selected-DNS enforcement and OS resolver path"
	go func() {
		defer close(work.done)
		defer cancel()
		t.proveDNSAsyncWithProbeContext(ctx, sessionID, s, runtimeID, probe)
	}()
}

// The periodic observation can revoke admission before a blocked worker has
// managed to install its detailed immutable path observer.
func (t *sessionTracker) cancelStaleDNSProofLocked(s observedConnection, runtimeID string) {
	work := t.dnsProofWork
	if work != nil && (t.session == nil || t.session.ID != work.sessionID || !s.Connected || strings.TrimSpace(s.Phase) != "connected" ||
		runtimeID != work.runtimeID || s.RouterID != work.routerID || s.Base != work.base || asyncMeasurementProfileToken(s.Profile) != work.profile) {
		work.cancel()
	}
}

// Retirement is terminal for this exact tracker. A caller whose wait expires
// may retry; the original worker and join receipt remain retained meanwhile.
func (t *sessionTracker) stopDNSProofs(ctx context.Context) error {
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return err
	}
	t.dnsProofClosed = true
	work := t.dnsProofWork
	if work != nil {
		work.cancel()
	}
	t.mu.Unlock()
	if work == nil {
		return ctx.Err()
	}
	select {
	case <-work.done:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func stopSessionDNSProofs(a *app) error {
	raw, found := sessionTrackers.Load(a)
	tracker, valid := raw.(*sessionTracker)
	if !found || !valid || tracker == nil || tracker.a != a {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tracker.stopDNSProofs(ctx)
}
