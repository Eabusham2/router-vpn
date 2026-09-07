package main

import (
	"context"
	"errors"
	"strings"
)

type asyncMeasurementBindingKey struct{}

// This immutable context value owns the terminal write as well as the HTTP
// observer. It contains profile hashes, never captured credentials or mutable
// profile pointers. The owner check prevents another app from adopting it.
type asyncMeasurementAdoption struct {
	owner      *app
	session    connectionSession
	stateToken string
	profiles   map[string]string
	multihop   bool
	graph      activeMultihopGraph
	generation uint64
}

// Caller holds tracker.mu -> app.mu. Do not call snapshot or an app-locking
// validation helper here: persistence must remain atomic with these checks.
func (b *asyncMeasurementAdoption) validateLocked(current *connectionSession) error {
	a := b.owner
	if current == nil || !b.session.Connected || b.session.Phase != "connected" || b.session.PathProof != "passed" || !sameAsyncMeasurementSession(b.session, *current) {
		return errors.New("VPN session changed before live measurement adoption")
	}
	if homeExitProofs.generation(a) != b.generation {
		return errors.New("VPN lifecycle invalidated the live measurement before adoption")
	}
	if !a.state.Connected || strings.TrimSpace(a.state.Phase) != "connected" || mtuStateSnapshotToken(a.state) != b.stateToken || a.state.RouterID != b.session.RouterID {
		return errors.New("VPN runtime path changed before live measurement adoption")
	}
	runtimeID := strings.TrimSpace(a.state.RuntimeMode)
	if runtimeID == "" && a.state.Mode != "off" {
		runtimeID = strings.TrimSpace(a.state.Mode)
	}
	if runtimeID != current.ActualMode || a.state.Base != current.ActualBase {
		return errors.New("live measurement refused a lagging session tracker")
	}
	if b.multihop {
		graph, ok := getActiveMultihopGraph(a)
		if err := validateActiveMultihopSpeedGraph(a.state, graph, ok, b.graph.EntryID, b.graph.ExitID); err != nil {
			return err
		}
		if !sameActiveMultihopGraph(graph, b.graph) {
			return errors.New("multihop graph changed before live measurement adoption")
		}
	}
	return validateMeasurementProfilesLocked(a, b.profiles)
}

func (b *asyncMeasurementAdoption) validate() error {
	tracker := sessionTrackerFor(b.owner)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	b.owner.mu.Lock()
	defer b.owner.mu.Unlock()
	return b.validateLocked(tracker.session)
}

// Acquire only after all HTTP work finishes. Never hold the operation lock
// during probes, and never wait behind a connection/settings transaction.
// The returned function releases app, tracker, and operation locks in reverse.
func (a *app) beginAsyncMeasurementAdoption(ctx context.Context) (func(), error) {
	binding, ok := ctx.Value(asyncMeasurementBindingKey{}).(*asyncMeasurementAdoption)
	if !ok || binding == nil || binding.owner != a {
		return nil, errors.New("live measurement has no matching immutable adoption binding")
	}
	releaseOperation, err := a.beginNodeBoundOperation()
	if err != nil {
		return nil, err
	}
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	a.mu.Lock()
	release := func() { a.mu.Unlock(); tracker.mu.Unlock(); releaseOperation() }
	if err := context.Cause(ctx); err != nil {
		release()
		return nil, err
	}
	if err := binding.validateLocked(tracker.session); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
