package main

import (
	"context"
	"errors"
	"strings"
	"sync"

	"router-vpn/internal/desktopnetwork"
)

type asyncMeasurementBindingKey struct{}

// This immutable context value owns the terminal write as well as the HTTP
// observer. It contains profile hashes, never captured credentials or mutable
// profile pointers. The owner check prevents another app from adopting it.
type asyncMeasurementAdoption struct {
	trackerOnce     sync.Once
	tracker         *sessionTracker
	trackerErr      error
	owner           *app
	session         connectionSession
	stateToken      string
	profiles        map[string]string
	multihop        bool
	graph           activeMultihopGraph
	generation      uint64
	tor             *desktopTorMeasurementBinding
	importedOpenVPN *nativeMultihopRuntime
}

// speedLabPathContext runs validate synchronously before starting its observer.
// Capture the registered tracker exactly once at that preflight, without the
// side effect of sessionTrackerFor (which creates a new observer when absent).
// The same session ID in a replacement tracker is not the same process owner.
func (b *asyncMeasurementAdoption) sessionOwner() (*sessionTracker, error) {
	b.trackerOnce.Do(func() {
		value, ok := sessionTrackers.Load(b.owner)
		tracker, typed := value.(*sessionTracker)
		if !ok || !typed || tracker == nil || tracker.a != b.owner {
			b.trackerErr = errors.New("live measurement has no matching process session owner")
			return
		}
		b.tracker = tracker
	})
	if b.trackerErr != nil {
		return nil, b.trackerErr
	}
	current, ok := sessionTrackers.Load(b.owner)
	if !ok || current != b.tracker {
		return nil, errors.New("live measurement process session owner changed")
	}
	return b.tracker, nil
}

// Caller holds tracker.mu -> app.mu. Do not call snapshot or an app-locking
// validation helper here: persistence must remain atomic with these checks.
func (b *asyncMeasurementAdoption) validateLocked(current *connectionSession) error {
	return b.validateLockedWithTor(current, func() error { return b.tor.currentLocked(b.owner) })
}

func (b *asyncMeasurementAdoption) validateLockedContext(ctx context.Context, current *connectionSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := b.validateLockedWithTor(current, func() error { return b.tor.currentLockedContext(ctx, b.owner) })
	return errors.Join(err, ctx.Err())
}

func (b *asyncMeasurementAdoption) validateLockedWithTor(current *connectionSession, torCurrent func() error) error {
	a := b.owner
	tracker, err := b.sessionOwner()
	if err != nil {
		return err
	}
	if current != tracker.session {
		return errors.New("live measurement adoption holds a different session owner's locks")
	}
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
		if graph.ImportedEntry && graph.EntryMode == "openvpn" {
			owner := b.importedOpenVPN
			raw, present := nativeMultihopOwners.Load(a)
			if owner == nil || owner.launch == nil || owner.launch.importedOpenVPN == nil || owner.launch.importedOpenVPN.retired.Load() ||
				!present || raw != owner || a.cmd != owner.launch.command {
				return errors.New("live measurement lost its original imported OpenVPN child")
			}
			if raw, present := desktopNodeOwners.Load(a); !present || raw != owner.launch {
				return errors.New("live measurement lost its imported OpenVPN TUN owner")
			}
		}
	}
	if b.tor != nil {
		if err := torCurrent(); err != nil {
			return err
		}
	}
	return validateMeasurementProfilesLocked(a, b.profiles)
}

func (b *asyncMeasurementAdoption) validate() error {
	return b.validateContext(context.Background())
}

func (b *asyncMeasurementAdoption) validateContext(ctx context.Context) error {
	if b.importedOpenVPN != nil {
		if err := validateDesktopImportedOpenVPNRuntime(ctx, b.owner, b.importedOpenVPN); err != nil {
			return err
		}
	}
	tracker, err := b.sessionOwner()
	if err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
		return err
	}
	defer tracker.mu.Unlock()
	if err := desktopnetwork.LockContext(ctx, &b.owner.mu); err != nil {
		return err
	}
	defer b.owner.mu.Unlock()
	return b.validateLockedContext(ctx, tracker.session)
}

// Acquire only after all HTTP work finishes. Never hold the operation lock
// during probes, and never wait behind a connection/settings transaction.
// The returned function releases app, tracker, and operation locks in reverse.
func (a *app) beginAsyncMeasurementAdoption(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, errors.New("live measurement adoption has no original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	binding, ok := ctx.Value(asyncMeasurementBindingKey{}).(*asyncMeasurementAdoption)
	if !ok || binding == nil || binding.owner != a {
		return nil, errors.New("live measurement has no matching immutable adoption binding")
	}
	if binding.importedOpenVPN != nil {
		if err := validateDesktopImportedOpenVPNRuntime(ctx, a, binding.importedOpenVPN); err != nil {
			return nil, err
		}
	}
	tracker, err := binding.sessionOwner()
	if err != nil {
		return nil, err
	}
	// The general transaction may synchronously join protection recovery. It
	// retains its compatibility contract; cancellation cannot detach it or
	// authorize a later measurement write after it finally returns.
	releaseOperation, err := a.beginNodeBoundOperation()
	if err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
		releaseOperation()
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		tracker.mu.Unlock()
		releaseOperation()
		return nil, err
	}
	release := func() { a.mu.Unlock(); tracker.mu.Unlock(); releaseOperation() }
	if err := context.Cause(ctx); err != nil {
		release()
		return nil, err
	}
	if err := binding.validateLockedContext(ctx, tracker.session); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
