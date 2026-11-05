//go:build linux

package main

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
)

var linuxStandardServiceMonitors sync.Map // map[*linuxStandardServiceLaunch]*linuxStandardServiceMonitor

// The monitor observes an already proved activation. A finished Connect request
// does not end that activation, and a planned controller Cmd never pretends to
// own the engine that the retained service actually created and joins.
type linuxStandardServiceMonitor struct {
	owner        *linuxStandardServiceLaunch
	app          *app
	prepared     *linuxLegacyStandardExitOwner
	dns          *legacyStandardDNS
	command      *exec.Cmd
	request      linuxStandardServiceRequest
	tracker      *sessionTracker
	profileToken string
	ctx          context.Context
	operation    context.Context
	cancel       context.CancelFunc
	watchDone    chan struct{}
	finished     chan struct{}
	endOnce      sync.Once
	probe        func(context.Context) error // caller holds the original owner.mu
	stop         func() error
	observations atomic.Uint64
	pendingLoss  error // owned only by the original serial watch loop
}

func (o *linuxStandardServiceLaunch) ActivateMonitor(operation context.Context) error {
	return o.activateMonitor(operation, func(ctx context.Context) error {
		return o.call(ctx, linuxStandardServiceRequest{Schema: 1, Action: "observe", Session: o.request.Session}, nil)
	}, func() error { return o.app.stopModeWithIntent(true) })
}

// Only the actual post-proof Connect path calls this in production. The two
// private callbacks let tests exercise ownership and joined cancellation without
// substituting a fabricated native service or physical network acceptance.
func (o *linuxStandardServiceLaunch) activateMonitor(operation context.Context, probe func(context.Context) error, stop func() error) error {
	if o == nil || operation == nil || probe == nil || stop == nil {
		return errors.New("standard service monitor has no original live activation")
	}
	if err := desktopnetwork.LockContext(operation, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if !o.registered || !o.attempted || o.joined || o.copiesClosed || !o.dnsProved || o.prepared == nil || o.prepared.dns == nil || o.request.Session == "" {
		return errors.New("standard service monitor preceded original proved activation")
	}
	if err := o.currentIntentContext(operation, operation, o.Command()); err != nil {
		return err
	}
	raw, exists := sessionTrackers.Load(o.app)
	tracker, valid := raw.(*sessionTracker)
	if !exists || !valid || tracker == nil || tracker.a != o.app {
		return errors.New("standard service monitor lost its original session tracker")
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &linuxStandardServiceMonitor{owner: o, app: o.app, prepared: o.prepared, dns: o.prepared.dns,
		command: o.Command(), request: o.request, tracker: tracker, profileToken: o.prepared.dns.profileToken,
		ctx: ctx, operation: operation, cancel: cancel, watchDone: make(chan struct{}), finished: make(chan struct{}), probe: probe, stop: stop}
	if err := desktopnetwork.LockContext(operation, &o.app.mu); err != nil {
		cancel()
		return err
	}
	current := o.app.state.Connected && o.app.state.Phase == "connected" && o.app.connectionCancelIntent != operation
	o.app.mu.Unlock()
	selected, selectedErr := m.selectedLocked(operation)
	sourceErr := m.sourceLocked(operation)
	if err := errors.Join(selectedErr, sourceErr, operation.Err()); err != nil {
		cancel()
		return err
	}
	if !current || !selected {
		cancel()
		return errors.New("standard service monitor lost its exact connected source")
	}
	if _, loaded := linuxStandardServiceMonitors.LoadOrStore(o, m); loaded {
		cancel()
		return errors.New("standard service cannot replace its retained monitor")
	}
	go m.run()
	return nil
}

// Caller holds owner.mu. This is identity comparison, not readiness proof.
// A failed original service/engine still belongs to this exact Stop owner.
func (m *linuxStandardServiceMonitor) selectedLocked(ctx context.Context) (bool, error) {
	if m == nil || m.owner == nil || m.ctx == nil || m.ctx.Err() != nil || m.app == nil || m.prepared == nil || m.command == nil {
		return false, nil
	}
	o := m.owner
	if o.app != m.app || o.prepared != m.prepared || o.prepared.dns != m.dns || o.Command() != m.command || o.request != m.request ||
		!o.registered || !o.attempted || o.joined || o.copiesClosed || !o.dnsProved {
		return false, nil
	}
	owner, exists := linuxStandardServiceOwners.Load(m.app)
	tracker, tracked := sessionTrackers.Load(m.app)
	if !exists || owner != o || !tracked || tracker != m.tracker {
		return false, nil
	}
	if err := desktopnetwork.LockContext(ctx, &m.app.mu); err != nil {
		return false, err
	}
	defer m.app.mu.Unlock()
	return m.app.cmd == m.command && m.app.state.RouterID == m.prepared.routerID &&
		m.app.state.RuntimeMode == m.prepared.runtimeMode && m.app.state.Base == m.prepared.base, ctx.Err()
}

// Caller holds owner.mu. Source replacement is a failed proof of the original
// runtime, distinct from a different runtime acquiring the application.
func (m *linuxStandardServiceMonitor) sourceLocked(ctx context.Context) error {
	if m.dns == nil || m.dns.profileToken != m.profileToken || m.prepared.session != m.request.Session ||
		m.prepared.digest != m.request.ConfigSHA256 || m.dns.networkID != m.request.NetworkID {
		return errors.New("standard service monitor changed its captured source or network")
	}
	if err := desktopnetwork.LockContext(ctx, &m.app.mu); err != nil {
		return err
	}
	profile, exists := m.app.profileByIDLocked(m.request.ProfileID)
	m.app.mu.Unlock()
	if !exists || asyncMeasurementProfileToken(profile) != m.profileToken {
		return errors.New("standard service monitor's original profile changed")
	}
	return ctx.Err()
}

func (m *linuxStandardServiceMonitor) lockOwner(ctx context.Context) error {
	return desktopnetwork.LockContext(ctx, &m.owner.mu)
}

func (m *linuxStandardServiceMonitor) observe(ctx context.Context) (failure error, selected bool) {
	if err := m.lockOwner(ctx); err != nil {
		return err, false
	}
	defer m.owner.mu.Unlock()
	current, err := m.selectedLocked(ctx)
	if err != nil || !current {
		return err, false
	}
	failure = m.sourceLocked(ctx)
	if failure == nil && m.owner.prepared.requestEpoch != nil && m.owner.prepared.requestEpoch.mtuTransition != nil {
		// A planned transition retains its original observer. Source checks do not
		// count as a successful network observation or publish a healthy sample.
		return errors.Join(m.owner.prepared.requestEpoch.sources(ctx), ctx.Err()), true
	}
	if failure == nil {
		failure = m.probe(ctx)
	}
	failure = errors.Join(failure, ctx.Err())
	// If selection cannot finish within this same caller budget, retain any
	// already witnessed real loss for bounded original-owner confirmation. This
	// incomplete read cannot adopt success or authorize Stop over a replacement.
	current, err = m.selectedLocked(ctx)
	if err == nil && !current {
		return nil, false
	}
	failure = errors.Join(failure, err, m.sourceLocked(ctx), ctx.Err())
	if failure == nil {
		m.observations.Add(1)
	}
	return failure, true
}

func (m *linuxStandardServiceMonitor) claimOperation(ctx context.Context) (func(), bool, error) {
	if err := desktopnetwork.LockContext(ctx, &m.app.mu); err != nil {
		return nil, false, err
	}
	defer m.app.mu.Unlock()
	if m.app.cmd != m.command {
		return nil, false, nil
	}
	if !m.app.operationMu.TryLock() {
		return nil, true, nil
	}
	if err := ctx.Err(); err != nil {
		m.app.operationMu.Unlock()
		return nil, true, err
	}
	return m.app.operationMu.Unlock, true, nil
}

// One tick uses its supplied observation budget. A proved mixed loss survives
// that expired read; a later original transaction may confirm ownership and
// retire it, but cannot reinterpret the expired read as a healthy result.
func (m *linuxStandardServiceMonitor) poll(ctx context.Context) bool {
	failure, selected := m.pendingLoss, true
	if failure == nil {
		failure, selected = m.observe(ctx)
	}
	if m.ctx.Err() != nil {
		return false
	}
	if common.ObservationContextExpired(ctx, failure) {
		return true
	}
	if !selected {
		return false
	}
	if failure == nil {
		return true
	}
	if ctx.Err() != nil {
		m.pendingLoss = failure
	}
	// This is the existing second, transaction-owned confirmation step. It
	// neither extends the earlier read nor repeats native work after its expiry.
	confirmation, cancel := context.WithTimeout(m.ctx, 4*time.Second)
	defer cancel()
	release, current, err := m.claimOperation(confirmation)
	if err != nil {
		return common.ObservationContextExpired(confirmation, err)
	}
	if !current {
		return false
	}
	if release == nil {
		return true
	}
	defer release()
	if m.pendingLoss != nil {
		if err = m.lockOwner(confirmation); err != nil {
			return common.ObservationContextExpired(confirmation, err)
		}
		selected, err = m.selectedLocked(confirmation)
		if selected && err == nil {
			err = m.sourceLocked(confirmation)
		}
		m.owner.mu.Unlock()
		if common.ObservationContextExpired(confirmation, err) {
			return true
		}
		if !selected || m.ctx.Err() != nil {
			return false
		}
		failure = errors.Join(m.pendingLoss, err)
	} else {
		failure, selected = m.observe(confirmation)
		if common.ObservationContextExpired(confirmation, failure) {
			return true
		}
		if !selected || m.ctx.Err() != nil {
			return false
		}
		if failure == nil {
			return true
		}
		if confirmation.Err() != nil {
			m.pendingLoss = failure
			return true
		}
	}
	if confirmation.Err() != nil {
		return true
	}
	// Stop joins observation, never itself; operationMu still owns this exact
	// command until cleanup and guarded failure publication finish. Keep
	// On-connect protection, as with every automatic original-runtime failure.
	m.endWatch()
	invalidateDesktopDNSResults(m.app)
	stopErr := m.stop()
	m.publishFailure(stopErr)
	return false
}

func (m *linuxStandardServiceMonitor) endWatch() {
	m.endOnce.Do(func() { m.cancel(); close(m.watchDone) })
}

func (m *linuxStandardServiceMonitor) run() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	defer close(m.finished)
	defer linuxStandardServiceMonitors.CompareAndDelete(m.owner, m)
	defer m.endWatch()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(m.ctx, 4*time.Second)
		keep := m.poll(ctx)
		cancel()
		if !keep {
			return
		}
	}
}

// operationMu remains held after exact Stop. Completed cleanup may remove its
// registry entry; failed cleanup must retain the original command and owner.
func (m *linuxStandardServiceMonitor) publishFailure(stopErr error) {
	o := m.owner
	o.mu.Lock()
	owner, exists := linuxStandardServiceOwners.Load(m.app)
	tracker, tracked := sessionTrackers.Load(m.app)
	if o.prepared != m.prepared || o.Command() != m.command || o.request != m.request || exists && owner != o || !tracked || tracker != m.tracker {
		o.mu.Unlock()
		return
	}
	message := "captured standard runtime lost its original service, source or network proof"
	if stopErr != nil {
		message += "; original cleanup remains pending: " + stopErr.Error()
	}
	m.app.mu.Lock()
	current := o.joined && m.app.cmd == nil || !o.joined && exists && owner == o && m.app.cmd == m.command
	if current {
		m.app.state.Connected, m.app.state.Phase, m.app.state.LastError = false, "failed", message
	}
	m.app.mu.Unlock()
	o.mu.Unlock()
	if current {
		m.tracker.markRequestFailure(message)
	}
}

// User Stop calls this before owner.mu. A monitor-initiated Stop has already
// ended its watch while owning operationMu, which also joins its cleanup before
// another connection or controller shutdown can acquire that transaction.
func (o *linuxStandardServiceLaunch) stopMonitor(ctx context.Context) error {
	if o == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("standard service monitor retirement has no live original caller")
	}
	raw, exists := linuxStandardServiceMonitors.Load(o)
	if !exists {
		return nil
	}
	m, ok := raw.(*linuxStandardServiceMonitor)
	if !ok || m == nil || m.owner != o || m.cancel == nil || m.watchDone == nil {
		return errors.New("standard service retirement lost its original monitor")
	}
	m.cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.watchDone:
		return nil
	}
}
