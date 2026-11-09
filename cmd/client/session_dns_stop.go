package main

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/desktopnetwork"
)

var errSessionDNSStopPending = errors.New("the previous Stop has not completed; retry Disconnect before connecting")

// An ordinary Stop fences one reusable tracker until both its captured DNS
// worker and runtime teardown have completed. A failed Stop retains this exact
// receipt for retry; terminal observation retirement remains separate.
type sessionDNSStopReceipt struct {
	tracker *sessionTracker
	work    *sessionDNSProofWork
	epoch   uint64
	token   string
	// A public Stop may wait behind an existing transition. That transition
	// may retire its runtime, but cannot reopen admission for the waiting
	// caller. Only the exact public receipt/retry or terminal shutdown can.
	publicReserved bool
}

// Caller holds tracker.mu. Registration, cancellation, join, and completion
// are distinct so a public caller can fence/cancel before operationMu while
// retaining the same receipt for the later serialized teardown.
func (t *sessionTracker) captureDNSStopLocked(ctx context.Context, expected *sessionDNSStopReceipt) (*sessionDNSStopReceipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner, ok := sessionTrackers.Load(t.a); !ok || owner != t || t.a == nil {
		return nil, errors.New("selected-DNS Stop lost its original registered tracker")
	}
	receipt := t.dnsProofStop
	if expected != nil && receipt != expected {
		return nil, errors.New("Stop retry belongs to a replaced retirement receipt")
	}
	if receipt == nil {
		token, err := randomHex(16)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		receipt = &sessionDNSStopReceipt{tracker: t, work: t.dnsProofWork, epoch: t.dnsProofEpoch.Add(1), token: token}
		t.dnsProofStop = receipt
		t.dnsProofBinding = nil
		if t.session != nil {
			t.session.DNSProof = dnsProofState{Status: "not-proven", Reason: "selected-DNS proof retired by Stop"}
		}
	}
	return receipt, receipt.currentLocked()
}

// The caller owns operationMu, but no tracker/app/native/MTU lock. Registering
// the ordinary tracker first also fences a concurrent first status request.
func (a *app) drainSessionDNSForStop(ctx context.Context) (*sessionDNSStopReceipt, error) {
	return a.drainCapturedSessionDNSForStop(ctx, nil)
}

func (a *app) drainCapturedSessionDNSForStop(ctx context.Context, expected *sessionDNSStopReceipt) (*sessionDNSStopReceipt, error) {
	if a == nil || ctx == nil {
		return nil, errors.New("selected-DNS Stop requires its original cleanup caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var t *sessionTracker
	if expected != nil {
		t = expected.tracker
		if t == nil || t.a != a {
			return nil, errors.New("Stop retry lost its original DNS tracker")
		}
	} else {
		t = sessionTrackerFor(a)
	}
	if t == nil || t.a != a {
		return nil, errors.New("selected-DNS Stop lost its original application tracker")
	}
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return nil, err
	}
	receipt, err := t.captureDNSStopLocked(ctx, expected)
	if err != nil {
		t.mu.Unlock()
		return nil, err
	}
	if receipt.work != nil {
		receipt.work.cancel()
	}
	t.mu.Unlock()
	if receipt.work != nil {
		select {
		case <-receipt.work.done:
		case <-ctx.Done():
			return receipt, ctx.Err()
		}
	}
	// No runtime cleanup may proceed after a timeout or owner replacement,
	// even if the old worker happened to finish at the same instant.
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return receipt, err
	}
	defer t.mu.Unlock()
	return receipt, errors.Join(ctx.Err(), receipt.currentLocked())
}

// Caller holds the original tracker lock. Never look up and mutate a newer
// tracker or accept a same-ID replacement worker as this Stop's join receipt.
func (r *sessionDNSStopReceipt) currentLocked() error {
	if r == nil || r.tracker == nil || r.tracker.a == nil {
		return errors.New("selected-DNS Stop lost its captured retirement receipt")
	}
	t := r.tracker
	owner, found := sessionTrackers.Load(t.a)
	if !found || owner != t || t.dnsProofStop != r || t.dnsProofWork != r.work || t.dnsProofEpoch.Load() != r.epoch {
		return errors.New("selected-DNS Stop belongs to a replaced tracker, worker or retirement receipt")
	}
	return nil
}

// Only complete runtime retirement may reopen this exact reusable tracker.
// Advance again so an observation captured while Stop was fenced cannot start
// a worker after a fast reconnect restores identical presentation fields.
func (r *sessionDNSStopReceipt) finish(ctx context.Context) error {
	return r.finishCaptured(ctx, nil)
}

func (r *sessionDNSStopReceipt) finishCaptured(ctx context.Context, expected *sessionDNSStopReceipt) error {
	if r == nil || r.tracker == nil || ctx == nil {
		return errors.New("selected-DNS Stop completion lost its captured owner")
	}
	t := r.tracker
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if err := r.currentLocked(); err != nil {
		return err
	}
	if r.work != nil {
		select {
		case <-r.work.done:
		default:
			return errors.New("selected-DNS Stop cannot reopen before its original worker joins")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if expected != nil && expected != r {
		return errors.New("Stop completion belongs to another captured receipt")
	}
	if r.publicReserved && expected == nil && !t.dnsProofClosed {
		return nil
	}
	t.dnsProofEpoch.Add(1)
	t.dnsProofStop = nil
	t.dnsProofWork = nil
	t.dnsProofRunning = false
	t.dnsProofLastAttempt = time.Time{}
	return nil
}

// Connection admission cannot hide a failed Stop by starting a new session
// with DNS permanently fenced. Only an explicit owned Stop retry clears it.
func (a *app) guardSessionDNSStopPending(ctx context.Context) error {
	raw, found := sessionTrackers.Load(a)
	if !found {
		return ctx.Err()
	}
	t, valid := raw.(*sessionTracker)
	if !valid || t == nil || t.a != a {
		return errors.New("connection admission lost its original DNS tracker")
	}
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if owner, ok := sessionTrackers.Load(a); !ok || owner != t {
		return errors.New("connection admission DNS tracker was replaced")
	}
	if t.dnsProofStop != nil {
		return errSessionDNSStopPending
	}
	return ctx.Err()
}
