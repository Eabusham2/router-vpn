package main

import (
	"context"
	"errors"

	"router-vpn/internal/desktopnetwork"
)

// An observation may only borrow the already registered tracker. It neither
// creates a process observer nor follows a replacement with the same session ID.
func measurementSessionContext(ctx context.Context, a *app, expected *sessionTracker) (*sessionTracker, connectionSession, error) {
	if ctx == nil {
		return nil, connectionSession{}, errors.New("measurement has no original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, connectionSession{}, err
	}
	raw, found := sessionTrackers.Load(a)
	tracker, valid := raw.(*sessionTracker)
	if !found || !valid || tracker == nil || tracker.a != a || expected != nil && tracker != expected {
		return nil, connectionSession{}, errors.New("measurement lost its original session tracker")
	}
	if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
		return nil, connectionSession{}, err
	}
	defer tracker.mu.Unlock()
	actual, retained := sessionTrackers.Load(a)
	if !retained || actual != tracker || tracker.session == nil {
		return nil, connectionSession{}, errors.New("measurement session tracker was replaced")
	}
	snapshot := *tracker.session
	snapshot.Events = append([]connectionEvent(nil), tracker.session.Events...)
	return tracker, snapshot, ctx.Err()
}
