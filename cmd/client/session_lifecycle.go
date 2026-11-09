package main

import (
	"context"
	"strings"
	"sync"
	"time"
)

// The observation loop belongs to one registered tracker. DNS workers derive
// their bounded context from this lifetime and retain their separate proof
// completion receipt. Admission and retirement share a lock so Wait can never
// race a later Add. Cancellation alone is not a terminal receipt.
type sessionWorkerLifetime struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
	joined  bool
	workers sync.WaitGroup
}

func (l *sessionWorkerLifetime) contextLocked() context.Context {
	if l.ctx == nil {
		l.ctx, l.cancel = context.WithCancel(context.Background())
		if l.stopped {
			l.cancel()
		}
	}
	return l.ctx
}

func (t *sessionTracker) observationContext() context.Context {
	t.lifetime.mu.Lock()
	defer t.lifetime.mu.Unlock()
	return t.lifetime.contextLocked()
}

func (t *sessionTracker) startWorker(run func(context.Context)) bool {
	t.lifetime.mu.Lock()
	defer t.lifetime.mu.Unlock()
	if t.lifetime.stopped || run == nil {
		return false
	}
	ctx := t.lifetime.contextLocked()
	t.lifetime.workers.Add(1)
	go func() {
		defer t.lifetime.workers.Done()
		run(ctx)
	}()
	return true
}

func cancelSessionTracker(a *app) *sessionTracker {
	// Capture the existing owner or install a retired owner atomically. A first
	// status request racing shutdown must not register an unjoined live loop.
	retired := &sessionTracker{a: a, dnsProofClosed: true, lifetime: sessionWorkerLifetime{stopped: true}}
	raw, _ := sessionTrackers.LoadOrStore(a, retired)
	t, valid := raw.(*sessionTracker)
	if !valid || t == nil || t.a != a {
		return nil
	}
	t.cancelObservation()
	return t
}

func (t *sessionTracker) cancelObservation() {
	t.lifetime.mu.Lock()
	t.lifetime.stopped = true
	if t.lifetime.cancel != nil {
		t.lifetime.cancel()
	}
	t.lifetime.mu.Unlock()
}

// Keep the retired tracker registered after its exact workers have returned.
// Read-only status requests may still arrive before the controller exits; they
// must not create a new observation loop after terminal cleanup. A separately
// registered replacement is neither cancelled nor modified here.
func joinSessionTracker(a *app, t *sessionTracker) {
	if t == nil || t.a != a {
		return
	}
	t.lifetime.mu.Lock()
	stopped := t.lifetime.stopped
	t.lifetime.mu.Unlock()
	if !stopped {
		return
	}
	t.lifetime.workers.Wait()
	t.lifetime.mu.Lock()
	t.lifetime.joined = true
	t.lifetime.mu.Unlock()
}

// Called only after the original DNS and observation workers have joined and
// controller cleanup has completed. Update this retired snapshot without the
// ordinary observer's app-keyed invalidation or proof admission side effects.
func (t *sessionTracker) publishRetiredObservation(s observedConnection) {
	t.mu.Lock()
	defer t.mu.Unlock()
	owner, present := sessionTrackers.Load(t.a)
	t.lifetime.mu.Lock()
	retired := t.lifetime.stopped && t.lifetime.joined
	t.lifetime.mu.Unlock()
	if !present || owner != t || !t.dnsProofClosed || !retired ||
		t.session == nil || s.Connected || strings.TrimSpace(s.Phase) != "off" {
		return
	}
	if work := t.dnsProofWork; work != nil {
		select {
		case <-work.done:
		default:
			return
		}
	}
	runtimeID := s.RuntimeMode
	if runtimeID == "" && s.Mode != "off" {
		runtimeID = s.Mode
	}
	t.session.Connected = false
	t.session.Phase = "off"
	t.session.RouterID = s.RouterID
	t.session.ActualMode = runtimeID
	t.session.ActualBase = s.Base
	t.session.Engine = sessionEngine(t.a, runtimeID)
	t.session.Error = typedError(s.LastError)
	t.session.ExitIP = ""
	t.session.PathProof = "not-run"
	t.session.DNSProof = dnsProofState{Status: "not-proven", Reason: "controller retired after owned cleanup"}
	t.dnsProofBinding = nil
	if t.session.EndedAt == nil {
		ended := time.Now().UTC()
		t.session.EndedAt = &ended
	}
	t.eventLocked("phase", "off", "controller retired after owned cleanup", false, runtimeID, s.Base)
}
