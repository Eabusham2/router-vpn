package main

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/hopmeasure"
)

func (s desktopLatencySnapshot) currentLocked(a *app) error {
	if s.temporary == nil {
		return s.desktopDNSSnapshot.currentLocked(a)
	}
	if !a.speedLabOwnerCurrentLocked(s.temporary) || a.cmd != s.temporary.runtime || a.cmd != s.path.Command ||
		a.closing || !a.state.Connected || a.state.Phase != "connected" || a.state.RouterID != s.path.RouterID ||
		mtuStateSnapshotToken(a.state) != s.path.StateToken || s.temporary.current == nil || s.temporary.current.Err() != nil {
		return errors.New("external comparison no longer owns this temporary native path")
	}
	owner, found := lookupDesktopNativeLaunch(a)
	if !found || owner != s.launch || s.launch == nil || s.launch.command != a.cmd {
		return errors.New("external comparison native process was replaced")
	}
	profile, entry, ok := a.dnsPolicySelectionLocked()
	if !ok || profile.ID != s.profileID || dnsPolicySelectionToken(profile, entry) != s.profileToken {
		return errors.New("external comparison selected source or DNS changed")
	}
	return nil
}

func (s desktopLatencySnapshot) current(a *app) error {
	if s.temporary == nil {
		return s.desktopDNSSnapshot.current(a)
	}
	if s.cohort == nil {
		return errors.New("external comparison has no captured source and network cohort")
	}
	if err := s.cohort(); err != nil {
		return err
	}
	if err := validateSpeedLabIdentity(a, s.path); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return s.currentLocked(a)
}

func captureDesktopComparisonLatency(a *app, temporary *speedLabTemporaryOwner, path speedLabPathIdentity, cohort func() error) (desktopLatencySnapshot, error) {
	launch := path.External
	if path.Tor != nil {
		launch = path.Tor
	}
	identity, err := capturedDesktopLatencyRuntime(launch)
	if err != nil || temporary == nil || cohort == nil {
		return desktopLatencySnapshot{}, errors.Join(err, errors.New("external comparison requires its exact native temporary owner"))
	}
	a.mu.Lock()
	profile, entry, ok := a.dnsPolicySelectionLocked()
	snapshot := desktopLatencySnapshot{desktopDNSSnapshot: desktopDNSSnapshot{launch: launch, session: identity.session,
		profileID: profile.ID, profileToken: dnsPolicySelectionToken(profile, entry)}, temporary: temporary, path: path, cohort: cohort}
	a.mu.Unlock()
	if !ok {
		return desktopLatencySnapshot{}, errors.New("external comparison lost its saved DNS source")
	}
	return snapshot, snapshot.current(a)
}

// The batch already holds beginSpeedLabRun, operationMu, the temporary owner
// and the MTU lease. Keep those owners through the native mailbox's final drain.
func (a *app) measureDesktopComparisonLatency(ctx context.Context, temporary *speedLabTemporaryOwner, path speedLabPathIdentity, cohort func() error, progress func(*desktopLatencyOperation)) (hopmeasure.Status, error) {
	snapshot, err := captureDesktopComparisonLatency(a, temporary, path, cohort)
	if err != nil {
		return hopmeasure.Status{}, err
	}
	request, err := randomHex(16)
	if err != nil {
		return hopmeasure.Status{}, err
	}
	child, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	operation := &desktopLatencyOperation{snapshot: snapshot, request: request, cancel: cancel, done: make(chan struct{}),
		status: hopmeasure.Status{Request: request, Stage: "preparing", Results: []hopmeasure.Result{}}}
	defer close(operation.done)
	if progress != nil {
		progress(operation)
		defer progress(nil)
	}
	result, err := a.runDesktopLatencyNative(child, operation)
	if err == nil {
		err = snapshot.current(a)
	}
	if err != nil {
		return hopmeasure.Status{}, err
	}
	return result, nil
}
