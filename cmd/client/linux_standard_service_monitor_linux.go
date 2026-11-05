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
	cancel       context.CancelFunc
	watchDone    chan struct{}
	finished     chan struct{}
	endOnce      sync.Once
	probe        func(context.Context) error // caller holds the original owner.mu
	stop         func() error
	observations atomic.Uint64
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
	if o == nil || operation == nil || operation.Err() != nil || probe == nil || stop == nil {
		return errors.New("standard service monitor has no original live activation")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.registered || !o.attempted || o.joined || o.copiesClosed || !o.dnsProved || o.prepared == nil || o.prepared.dns == nil || o.request.Session == "" {
		return errors.New("standard service monitor preceded original proved activation")
	}
	if err := o.currentIntent(operation, o.Command()); err != nil {
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
		ctx: ctx, cancel: cancel, watchDone: make(chan struct{}), finished: make(chan struct{}), probe: probe, stop: stop}
	o.app.mu.Lock()
	current := o.app.state.Connected && o.app.state.Phase == "connected" && o.app.connectionCancelIntent != operation
	o.app.mu.Unlock()
	if !current || !m.selectedLocked() || m.sourceLocked() != nil {
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
func (m *linuxStandardServiceMonitor) selectedLocked() bool {
	if m == nil || m.owner == nil || m.ctx == nil || m.ctx.Err() != nil || m.app == nil || m.prepared == nil || m.command == nil {
		return false
	}
	o := m.owner
	if o.app != m.app || o.prepared != m.prepared || o.prepared.dns != m.dns || o.Command() != m.command || o.request != m.request ||
		!o.registered || !o.attempted || o.joined || o.copiesClosed || !o.dnsProved {
		return false
	}
	owner, exists := linuxStandardServiceOwners.Load(m.app)
	tracker, tracked := sessionTrackers.Load(m.app)
	if !exists || owner != o || !tracked || tracker != m.tracker {
		return false
	}
	m.app.mu.Lock()
	defer m.app.mu.Unlock()
	return m.app.cmd == m.command && m.app.state.RouterID == m.prepared.routerID &&
		m.app.state.RuntimeMode == m.prepared.runtimeMode && m.app.state.Base == m.prepared.base
}

// Caller holds owner.mu. Source replacement is a failed proof of the original
// runtime, distinct from a different runtime acquiring the application.
func (m *linuxStandardServiceMonitor) sourceLocked() error {
	if m.dns == nil || m.dns.profileToken != m.profileToken || m.prepared.session != m.request.Session ||
		m.prepared.digest != m.request.ConfigSHA256 || m.dns.networkID != m.request.NetworkID {
		return errors.New("standard service monitor changed its captured source or network")
	}
	m.app.mu.Lock()
	profile, exists := m.app.profileByIDLocked(m.request.ProfileID)
	m.app.mu.Unlock()
	if !exists || asyncMeasurementProfileToken(profile) != m.profileToken {
		return errors.New("standard service monitor's original profile changed")
	}
	return nil
}

func (m *linuxStandardServiceMonitor) lockOwner(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("standard service monitor observation was cancelled")
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if m.owner.mu.TryLock() {
			if ctx.Err() != nil {
				m.owner.mu.Unlock()
				return ctx.Err()
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *linuxStandardServiceMonitor) observe() (failure error, selected bool) {
	ctx, cancel := context.WithTimeout(m.ctx, 4*time.Second)
	defer cancel()
	if err := m.lockOwner(ctx); err != nil {
		return err, false
	}
	defer m.owner.mu.Unlock()
	if !m.selectedLocked() {
		return nil, false
	}
	failure = m.sourceLocked()
	if failure == nil {
		failure = m.probe(ctx)
	}
	if ctx.Err() != nil {
		failure = errors.Join(failure, ctx.Err())
	}
	// The callback can complete after cancellation or a new application owner.
	// Neither completion may publish failure or acquire Stop over that owner.
	if !m.selectedLocked() {
		return nil, false
	}
	if failure == nil {
		failure = m.sourceLocked()
	}
	if failure == nil {
		m.observations.Add(1)
	} else if common.ObservationContextExpired(ctx, failure) {
		// This was a read of an already proved activation. An expired read
		// neither proves the runtime healthy nor authorizes its retirement.
		// Classify before the deferred cancel: a genuine source/engine error,
		// including one joined with cancellation, still needs the final owned
		// transaction recheck. The next tick keeps this same original monitor.
		return nil, true
	}
	return failure, true
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
		failure, selected := m.observe()
		if !selected {
			if m.ctx.Err() == nil && errors.Is(failure, context.DeadlineExceeded) {
				continue // A busy owner did not admit a native observation.
			}
			return
		}
		if failure == nil {
			continue
		}
		release, current := m.app.claimRuntimeMonitorOperation(m.command)
		if !current {
			return
		}
		if release == nil {
			continue
		}
		retired := func() bool {
			defer release()
			failure, selected = m.observe()
			if !selected || m.ctx.Err() != nil {
				return !(m.ctx.Err() == nil && errors.Is(failure, context.DeadlineExceeded))
			}
			if failure == nil {
				return false
			}
			// Stop joins observation, never itself. The exact operation mutex
			// remains held until cleanup and guarded failure publication finish.
			m.endWatch()
			invalidateDesktopDNSResults(m.app)
			stopErr := m.stop()
			m.publishFailure(stopErr)
			return true
		}()
		if retired {
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
