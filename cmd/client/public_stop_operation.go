package main

import (
	"context"
	"errors"

	"router-vpn/internal/desktopnetwork"
)

// Public Stop cannot first wait for operationMu: an original selected-DNS
// result may own it while waiting for a contextual native guard. Reserve its
// exact reusable receipt and cancel that work before attempting the lock.
func (a *app) capturePublicStopContext(ctx context.Context, reason string) (*sessionDNSStopReceipt, error) {
	if a == nil || ctx == nil {
		return nil, errors.New("public Stop requires its original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Avoid installing the first observer for a request already cancelled at
	// the app boundary. First status/connection/shutdown still share the same
	// existing LoadOrStore registration and permanent shutdown tombstone.
	if _, found := sessionTrackers.Load(a); !found {
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return nil, err
		}
		if a.controllerClosingLocked() {
			a.mu.Unlock()
			return nil, errControllerClosing
		}
		sessionTrackerFor(a)
		a.mu.Unlock()
	}
	raw, found := sessionTrackers.Load(a)
	t, valid := raw.(*sessionTracker)
	if !found || !valid || t == nil || t.a != a {
		return nil, errors.New("public Stop lost its original DNS tracker")
	}
	return a.cancelStopReceiptContext(ctx, t, nil, reason)
}

// Owned Retry already validated its token under operationMu. Its cancellation
// must retain that exact receipt and caller rather than use a broad lookup of
// whichever connection or candidate happens to be current later.
func (a *app) cancelCapturedStopContext(ctx context.Context, expected *sessionDNSStopReceipt) error {
	if expected == nil {
		return errors.New("Stop retry cancellation requires its captured receipt")
	}
	_, err := a.cancelStopReceiptContext(ctx, expected.tracker, expected, "")
	return err
}

func (a *app) cancelStopReceiptContext(ctx context.Context, t *sessionTracker, expected *sessionDNSStopReceipt, reason string) (*sessionDNSStopReceipt, error) {
	if a == nil || ctx == nil || t == nil || t.a != a || expected != nil && expected.tracker != t {
		return nil, errors.New("Stop cancellation lost its original caller or tracker")
	}
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return nil, err
	}
	defer t.mu.Unlock()
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	if a.controllerClosingLocked() {
		a.mu.Unlock()
		return nil, errControllerClosing
	}
	receipt, err := t.captureDNSStopLocked(ctx, expected)
	if err != nil {
		a.mu.Unlock()
		return nil, err
	}
	if !validStopRetryToken(receipt.token) {
		a.mu.Unlock()
		return nil, errors.New("public Stop lost its original retry token")
	}
	receipt.publicReserved = true
	if receipt.work != nil {
		receipt.work.cancel()
	}
	connectionCancel, recovery := a.connectionCancel, a.nodeRecovery
	if connectionCancel != nil && a.connectionContext != nil {
		a.connectionCancelIntent = a.connectionContext
	}
	startup, startupPresent := startupPolicyCancels.LoadAndDelete(a)
	if reason != "" {
		homeExitProofs.Delete(a)
		if t.session != nil {
			t.session.StopReason = reason
			t.eventLocked("stop-request", t.session.Phase, reason, t.session.Connected, t.session.ActualMode, t.session.ActualBase)
		}
	}
	a.mu.Unlock()
	// These are the captured, nonjoining context cancellation functions. Keep
	// the receipt locked until cancellation is issued: a simultaneous owned
	// retry cannot complete it and expose a replacement between these calls.
	if connectionCancel != nil {
		connectionCancel()
	}
	if recovery != nil {
		recovery.cancel()
	}
	if startupPresent {
		startup.(context.CancelFunc)()
	}
	// The candidate control may acquire app, so app is released first. Its
	// wait retains this caller and no join runs under tracker/control locks.
	if err := cancelViaEntryOperationContext(ctx, a); err != nil {
		return receipt, err
	}
	return receipt, ctx.Err()
}

// The original public receipt is checked after operation admission. A caller
// delayed past another Stop/retry must never recapture the replacement, even
// when the tracker, presentation, or epoch number happens to look identical.
func (a *app) beginCapturedPublicStopContext(ctx context.Context, receipt *sessionDNSStopReceipt) (func(), error) {
	if receipt == nil || receipt.tracker == nil || receipt.tracker.a != a {
		return nil, errors.New("public Stop lost its captured retirement receipt")
	}
	if err := desktopnetwork.LockContext(ctx, &a.operationMu); err != nil {
		return nil, err
	}
	current, err := a.captureStopRetryContext(ctx, receipt.token)
	if err != nil || current != receipt {
		a.operationMu.Unlock()
		return nil, errors.Join(err, errors.New("public Stop belongs to a completed or replaced receipt"))
	}
	return a.operationMu.Unlock, nil
}

// Final connection context publication shares tracker -> app with public
// Stop capture. The earlier admission check precedes filesystem/native work;
// a Stop registered during that work must win before a new context appears.
func (a *app) lockConnectionPublicationContext(ctx context.Context) (func(), error) {
	for {
		raw, found := sessionTrackers.Load(a)
		if !found {
			if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
				return nil, err
			}
			if _, registered := sessionTrackers.Load(a); registered {
				a.mu.Unlock()
				continue
			}
			return a.mu.Unlock, nil
		}
		t, valid := raw.(*sessionTracker)
		if !valid || t == nil || t.a != a {
			return nil, errors.New("connection publication lost its registered DNS tracker")
		}
		if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
			return nil, err
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			t.mu.Unlock()
			return nil, err
		}
		release := func() { a.mu.Unlock(); t.mu.Unlock() }
		if owner, ok := sessionTrackers.Load(a); !ok || owner != t {
			release()
			return nil, errors.New("connection publication DNS tracker was replaced")
		}
		if t.dnsProofStop != nil {
			release()
			return nil, errSessionDNSStopPending
		}
		return release, nil
	}
}

// Candidate measurements also publish a cancellable operation owner. Serialize
// that publication with public Stop: tracker -> control -> app when registered.
// Without a tracker, control -> app prevents first Stop capture until this
// owner is visible; recheck registration before accepting that shorter path.
// No branch waits for tracker while holding either control or app.
func (a *app) lockCandidatePublicationContext(ctx context.Context, control *viaEntryControl) (func(), error) {
	for {
		raw, found := sessionTrackers.Load(a)
		var tracker *sessionTracker
		if found {
			var valid bool
			tracker, valid = raw.(*sessionTracker)
			if !valid || tracker == nil || tracker.a != a {
				return nil, errors.New("candidate publication lost its registered DNS tracker")
			}
			if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
				return nil, err
			}
		}
		if err := desktopnetwork.LockContext(ctx, &control.mu); err != nil {
			if tracker != nil {
				tracker.mu.Unlock()
			}
			return nil, err
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			control.mu.Unlock()
			if tracker != nil {
				tracker.mu.Unlock()
			}
			return nil, err
		}
		release := func() {
			a.mu.Unlock()
			control.mu.Unlock()
			if tracker != nil {
				tracker.mu.Unlock()
			}
		}
		current, registered := sessionTrackers.Load(a)
		if tracker == nil && registered {
			release()
			continue
		}
		if tracker != nil && (!registered || current != tracker) {
			release()
			return nil, errors.New("candidate publication DNS tracker was replaced")
		}
		if a.controllerClosingLocked() {
			release()
			return nil, errControllerClosing
		}
		if tracker != nil && tracker.dnsProofStop != nil {
			release()
			return nil, errSessionDNSStopPending
		}
		return release, nil
	}
}
