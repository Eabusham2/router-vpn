//go:build linux

package main

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// A monitor observes the already activated, retained session. It neither
// creates an activation from Connected nor becomes another process waiter.
// The private functions are captured from that same host/app by Monitor;
// tests can isolate native observation and Stop without claiming a TUN proof.
type desktopLinuxNodeMonitor struct {
	app           *app
	session       *desktopLinuxNodeSession
	host          *desktopLinuxNodeHost
	sessionParent *desktopLinuxNodeParentCapture
	hostParent    *desktopLinuxNodeParentCapture
	activation    *desktopLinuxNodeActivation
	process       *desktopLinuxNodeProcess
	transaction   *desktopLinuxNodeTransaction
	journal       *desktopLinuxNodeJournal
	launch        *desktopNodeLaunch
	command       *exec.Cmd
	processJoined <-chan struct{}
	lifetime      context.Context
	ctx           context.Context
	cancel        context.CancelFunc
	watchDone     chan struct{}
	finished      chan struct{}
	currentLocked func(context.Context) error
	stop          func() error
	// Diagnostic only: a completed original Current plus the final captured
	// owner comparison. This count never creates readiness or Stop authority.
	observations atomic.Uint64
}

// Monitor is called after Activate, while the original Connect still owns
// operationMu. The admission caller is bounded, but its ordinary completion
// cannot cancel the independent activation lifetime retained below.
func (s *desktopLinuxNodeSession) Monitor(ctx context.Context, h *desktopLinuxNodeHost) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Linux Node monitor admission has no live bounded caller")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if s.active != h || h == nil || !sameDesktopLinuxParentCapture(s.parent, h.parent) {
		return errors.New("Linux Node monitor has no exact retained session host")
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.activation == nil || h.transaction == nil || h.transaction.journal != s.journal || h.monitor == nil {
		return errors.New("Linux Node monitor preceded original proved activation")
	}
	if err := h.observeLocked(ctx); err != nil {
		return err
	}
	if previous := h.monitor.Load(); previous != nil {
		selected, err := previous.selectedLocked(ctx)
		if err != nil {
			return err
		}
		if previous.ctx != nil && previous.ctx.Err() == nil && selected {
			return nil
		}
		return errors.New("Linux Node monitor cannot replace a retired or foreign observer")
	}
	m, err := newDesktopLinuxNodeMonitor(s, h, func(observation context.Context) error {
		return h.observeLocked(observation)
	}, func() error { return h.parent.app.stopModeWithIntent(true) })
	if err != nil {
		return err
	}
	h.monitor.Store(m)
	selected, err := m.selectedLocked(ctx)
	if err != nil || !selected {
		m.cancel()
		h.monitor.Store(nil)
		return errors.Join(err, errors.New("Linux Node monitor changed its captured application before observation"))
	}
	go m.run()
	return nil
}

// The caller holds both original session and host gates. Only Monitor admits
// this object in shipping code, after its real running-policy/TUN readbacks.
func newDesktopLinuxNodeMonitor(s *desktopLinuxNodeSession, h *desktopLinuxNodeHost,
	current func(context.Context) error, stop func() error) (*desktopLinuxNodeMonitor, error) {
	if s == nil || h == nil || s.active != h || s.parent == nil || s.parent.app == nil ||
		h.parent == nil || !sameDesktopLinuxParentCapture(s.parent, h.parent) ||
		h.activation == nil || h.activation.matches(h) != nil || h.transaction.journal != s.journal ||
		h.closing || h.closed || h.released || h.monitor == nil || current == nil || stop == nil {
		return nil, errors.New("Linux Node monitor lost its original activated owners")
	}
	ctx, cancel := context.WithCancel(h.activation.lifetime)
	if ctx.Err() != nil {
		cancel()
		return nil, errors.New("Linux Node monitor lost its activation lifetime")
	}
	return &desktopLinuxNodeMonitor{app: s.parent.app, session: s, host: h,
		sessionParent: s.parent, hostParent: h.parent, activation: h.activation,
		process: h.process, transaction: h.transaction, journal: s.journal,
		launch: h.launch, command: h.launch.command, processJoined: h.process.joined,
		lifetime: h.activation.lifetime, ctx: ctx, cancel: cancel,
		watchDone: make(chan struct{}), finished: make(chan struct{}), currentLocked: current, stop: stop}, nil
}

// This is ownership comparison, not a replacement for Current. In particular
// an exited original child is still the original Stop owner; its already
// joined channel causes a failed observation rather than foreign ownership.
// The caller holds session.gate and host.gate, in that order.
func (m *desktopLinuxNodeMonitor) selectedLocked(ctx context.Context) (bool, error) {
	if m == nil || ctx == nil || m.ctx == nil || m.ctx.Err() != nil ||
		m.session == nil || m.host == nil || m.app == nil || m.sessionParent == nil || m.hostParent == nil {
		return false, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	s, h := m.session, m.host
	if s.closed || s.released || s.active != h || s.parent != m.sessionParent || s.journal != m.journal ||
		h.closing || h.closed || h.released || h.monitor == nil || h.monitor.Load() != m || h.parent != m.hostParent ||
		h.activation != m.activation || h.process != m.process || h.transaction != m.transaction || h.launch != m.launch ||
		m.activation == nil || m.activation.host != h || m.activation.lifetime != m.lifetime ||
		m.process == nil || m.process.command != m.command || m.process.joined != m.processJoined ||
		m.command == nil || h.launch.command != m.command || m.transaction == nil || m.transaction.journal != m.journal ||
		m.sessionParent.app != m.app || !sameDesktopLinuxParentCapture(m.sessionParent, m.hostParent) {
		return false, nil
	}
	p := m.sessionParent.parent
	if p == nil || p.gate == nil {
		return false, nil
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-p.gate:
	}
	_, retainedSession := p.dependents[s]
	_, retainedHost := p.dependents[h]
	selected := p.complete && !p.closed && !p.stopping && p.session == s && retainedSession && retainedHost
	p.gate <- struct{}{}
	if !selected {
		return false, nil
	}
	m.app.mu.Lock()
	defer m.app.mu.Unlock()
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	_, duplicate := desktopNodeOwners.Load(m.app)
	return !duplicate && m.sessionParent.currentAppLocked(false) == nil && m.app.cmd == m.command &&
		m.app.state.RouterID == desktopExternalPathProfileID(m.launch) && m.app.state.RuntimeMode == m.launch.mode, nil
}

func (m *desktopLinuxNodeMonitor) observationWait(ctx context.Context) error {
	if m.ctx.Err() == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (m *desktopLinuxNodeMonitor) retryObservation(failure error, selected bool) bool {
	return !selected && m.ctx.Err() == nil && errors.Is(failure, context.DeadlineExceeded)
}

func (m *desktopLinuxNodeMonitor) observe() (failure error, selected bool) {
	ctx, cancel := context.WithTimeout(m.ctx, 4*time.Second)
	defer cancel()
	s, h := m.session, m.host
	if s.enter(ctx) != nil {
		return m.observationWait(ctx), false
	}
	defer func() { s.gate <- struct{}{} }()
	if h.enter(ctx) != nil {
		return m.observationWait(ctx), false
	}
	defer func() { h.gate <- struct{}{} }()
	selected, failure = m.selectedLocked(ctx)
	if !selected {
		return failure, false
	}
	select {
	case <-m.processJoined:
		failure = errors.New("Linux Node monitor observed its original joined engine")
	default:
		failure = m.currentLocked(ctx)
	}
	// The exact host gate remains held across the shared native readReady path.
	// Thus a deadline here followed an entered proof; it is not gate contention
	// and cannot leave Connected indefinitely without successful observations.
	if ctx.Err() != nil {
		failure = errors.Join(failure, ctx.Err())
	}
	// A completed native observation still needs a fresh bounded comparison of
	// its original owner. A cancelled monitor or replacement never gains Stop.
	check, stopCheck := context.WithTimeout(m.ctx, 2*time.Second)
	defer stopCheck()
	var compareErr error
	selected, compareErr = m.selectedLocked(check)
	if compareErr != nil {
		return compareErr, false
	}
	if selected && failure == nil {
		m.observations.Add(1)
	}
	return failure, selected
}

func (m *desktopLinuxNodeMonitor) run() {
	ticker := time.NewTicker(500 * time.Millisecond)
	var finish sync.Once
	endWatch := func() { finish.Do(func() { ticker.Stop(); close(m.watchDone) }) }
	defer close(m.finished)
	defer m.cancel()
	defer endWatch()
	joined := m.processJoined
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-joined:
			joined = nil // A retained exit must not spin while another app operation owns the mutex.
		case <-ticker.C:
		}
		failure, selected := m.observe()
		if !selected {
			if m.retryObservation(failure, selected) {
				continue
			}
			return
		}
		if failure == nil {
			continue
		}
		release, selected := m.app.claimRuntimeMonitorOperation(m.command)
		if !selected {
			return
		}
		if release == nil {
			continue
		}
		stop := func() bool {
			defer release()
			failure, selected = m.observe()
			if !selected || m.ctx.Err() != nil {
				return !m.retryObservation(failure, selected)
			}
			if failure == nil {
				return false // A healthy final read keeps this same observer alive.
			}
			// The mutex only serializes the final comparison. End observation
			// before Stop captures native authority and joins this exact host.
			endWatch()
			invalidateDesktopDNSResults(m.app)
			err := m.stop()
			m.publishFailure(err)
			return true
		}()
		if stop {
			return
		}
	}
}

// operationMu is still held. A failed or completed Stop may clear the command,
// but a replacement session, process or presentation must remain untouched.
func (m *desktopLinuxNodeMonitor) publishFailure(stopErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, h := m.session, m.host
	if s.enter(ctx) != nil {
		return
	}
	defer func() { s.gate <- struct{}{} }()
	if h.enter(ctx) != nil {
		return
	}
	defer func() { h.gate <- struct{}{} }()
	if s.parent != m.sessionParent || s.journal != m.journal || s.closed || s.released ||
		s.active != nil && s.active != h || s.active == nil && s.predecessor != nil && s.predecessor != m.transaction ||
		h.monitor == nil || h.monitor.Load() != m || h.parent != m.hostParent || h.process != m.process || h.transaction != m.transaction ||
		h.launch != m.launch || m.process.command != m.command || h.launch.command != m.command {
		return
	}
	p := m.sessionParent.parent
	select {
	case <-ctx.Done():
		return
	case <-p.gate:
	}
	sameSession := p.session == s && !p.closed && !p.stopping
	p.gate <- struct{}{}
	if !sameSession {
		return
	}
	message := "captured Linux Router source or network lost its proof; exact protection is held"
	if stopErr != nil {
		message = "captured Linux Router source or network lost its proof; original retirement failed: " + stopErr.Error()
	}
	m.app.mu.Lock()
	_, duplicate := desktopNodeOwners.Load(m.app)
	selected := !duplicate && m.sessionParent.currentAppLocked(false) == nil &&
		(m.app.cmd == nil || m.app.cmd == m.command) && m.app.state.RouterID == desktopExternalPathProfileID(m.launch) &&
		(m.app.state.RuntimeMode == "" || m.app.state.RuntimeMode == m.launch.mode)
	if selected {
		m.app.state.Connected, m.app.state.Phase, m.app.state.LastError = false, "failed", message
	}
	m.app.mu.Unlock()
	if selected {
		sessionTrackerFor(m.app).markRequestFailure(message)
	}
}

// Stop and terminal parent retirement call this before holding h.gate through
// native teardown. Cancellation revokes a queued final comparison; observation
// is joined without holding the gate it needs. A monitor initiating Stop has
// already ended that loop while retaining operationMu for the remaining work.
func (h *desktopLinuxNodeHost) stopMonitorBeforeRetirement(ctx context.Context) error {
	if h == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("Linux Node monitor retirement has no bounded original caller")
	}
	// The holder is immutable from host construction. Cancel the exact retained
	// observer before waiting for h.gate, so an entered native read can unwind.
	if h.monitor != nil {
		if m := h.monitor.Load(); m != nil {
			if m.host != h || m.cancel == nil || m.watchDone == nil {
				return errors.New("Linux Node retirement lost its captured monitor owner")
			}
			m.cancel()
		}
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	h.closing = true
	var m *desktopLinuxNodeMonitor
	if h.monitor != nil {
		m = h.monitor.Load()
	}
	if m != nil && (m.host != h || m.cancel == nil || m.watchDone == nil) {
		h.gate <- struct{}{}
		return errors.New("Linux Node retirement lost its captured monitor owner")
	}
	if m != nil {
		m.cancel()
	}
	h.gate <- struct{}{}
	if m == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.watchDone:
		return nil
	}
}
