//go:build linux

package main

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"sync"
	"sync/atomic"

	"router-vpn/internal/desktopnetwork"
)

// This receipt is produced only by the original session's completed retirement.
// It outlives a caller's cancellation but grants no new native admission. All
// non-atomic fields are protected by that original session gate.
type desktopLinuxStopCompletion struct {
	failedConstructor          error // exact failed source; never a successful retirement receipt
	hostReleased               bool
	reverse                    *linuxStandardNodeReverseTransfer
	owner                      *desktopNodeStopCapture
	disconnect                 bool
	retained                   bool
	joined                     atomic.Bool
	published                  atomic.Bool
	commandRetired             atomic.Bool
	predecessor                *desktopLinuxNodeTransaction
	journal                    *desktopLinuxNodeJournal
	dns                        *desktopDNSSlot
	dnsOperation               *desktopDNSOperation
	latency                    *desktopLatencySlot
	latencyOperation, response *desktopLatencyOperation
	registries                 []desktopLinuxStopRegistry
	homeGeneration             uint64
}

type desktopLinuxStopRegistry struct {
	registry *sync.Map
	value    any
	present  bool
}

func (c *desktopNodeStopCapture) retainCompletion(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	if c == nil || c.session == nil || c.completion == nil || c.completion.owner != c {
		return errors.New("Linux Stop completion lost its original capture")
	}
	s, done := c.session, c.completion
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if done.retained {
		if done.disconnect != disconnect || s.stopCompletion != c && !done.published.Load() {
			return errors.New("Linux Stop cannot change its retained retirement intent")
		}
		if done.joined.Load() {
			if err := c.completedSelectionLocked(ctx); err != nil {
				return err
			}
		}
		return c.currentAppContext(ctx, command, done.commandRetired.Load())
	}
	if s.stopCompletion != nil {
		return errors.New("Linux Stop already retains another completion capture")
	}
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if s.active != c.host || s.predecessor != c.predecessor || s.journal != c.journal {
		return errors.New("Linux Stop changed its original captured session selection")
	}
	if err := c.currentAppContext(ctx, command, false); err != nil {
		return err
	}
	a := c.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if a.connectionContext != c.operation || a.cmd != c.command || s.parent.currentAppLocked(false) != nil {
		return errors.New("Linux Stop cannot retain a replacement application")
	}
	done.dns, done.latency = a.dnsMeasurements, a.latencyMeasurements
	if done.dns != nil {
		if err := desktopnetwork.LockContext(ctx, &done.dns.mu); err != nil {
			return err
		}
		done.dnsOperation = done.dns.current
		done.dns.mu.Unlock()
	}
	if done.latency != nil {
		if err := desktopnetwork.LockContext(ctx, &done.latency.mu); err != nil {
			return err
		}
		done.latencyOperation, done.response = done.latency.current, done.latency.response
		done.latency.mu.Unlock()
	}
	done.registries = nil
	for _, registry := range []*sync.Map{&activeDNSRuntimeIdentities, &activeMultihopGraphs, &nativeMultihopOwners, &homeExitProofs.Map} {
		value, present := registry.Load(a)
		if present && (value == nil || !reflect.TypeOf(value).Comparable()) {
			return errors.New("Linux Stop cannot capture an untyped runtime registry owner")
		}
		if registry == &nativeMultihopOwners && present {
			owner, typed := value.(*nativeMultihopRuntime)
			if !typed || owner == nil || c.host == nil || owner.launch != c.host.launch {
				return errors.New("Linux Stop cannot capture another native graph's runtime owner")
			}
		}
		done.registries = append(done.registries, desktopLinuxStopRegistry{registry, value, present})
	}
	done.homeGeneration = homeExitProofs.generation(a)
	if err := ctx.Err(); err != nil {
		return err
	}
	done.disconnect, done.retained, done.reverse = disconnect, true, s.reverse
	s.stopCompletion = c
	return nil
}

// Called under the original session gate only after native/journal/descriptor
// retirement completed. No later failed app lock can erase this receipt.
func (c *desktopNodeStopCapture) joinedLocked() {
	done := c.completion
	done.predecessor, done.journal = c.session.predecessor, c.session.journal
	done.commandRetired.Store(true)
	done.joined.Store(true)
}

func (c *desktopNodeStopCapture) completedSelectionLocked(ctx context.Context) error {
	s, done := c.session, c.completion
	if done == nil || done.owner != c || !done.retained || !done.joined.Load() ||
		s.closed || s.released || s.active != nil || s.off != nil || s.journalErr != nil ||
		s.journal != done.journal || s.predecessor != done.predecessor || s.reverse != done.reverse ||
		s.stopCompletion != c && !(done.published.Load() && s.stopCompletion == nil) || s.parent == nil || s.parent.parent == nil {
		return errors.New("Linux Stop has no exact joined original completion")
	}
	p := s.parent.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	_, retained := p.dependents[s]
	if p.session != s || !retained {
		return errors.New("Linux Stop completion lost its original session registration")
	}
	return ctx.Err()
}

// Invalidate only the original result owners. Acquire every presentation slot
// with the caller's deadline; a partial old-result invalidation is retryable and
// cannot rediscover a successor through the application's current slot.
func (c *desktopNodeStopCapture) publishCompletion(ctx context.Context, command *exec.Cmd) error {
	return c.publishCompletionMode(ctx, command, false)
}

func (c *desktopNodeStopCapture) publishCompletionMode(ctx context.Context, command *exec.Cmd, shutdown bool) error {
	s, done := c.session, c.completion
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if err := c.completedSelectionLocked(ctx); err != nil {
		return err
	}
	if shutdown {
		p := s.parent.parent
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.gate:
		}
		stopping := p.stopping
		p.gate <- struct{}{}
		if !stopping {
			return errors.New("Linux completion cannot invent terminal parent authority")
		}
	}
	if err := c.currentAppModeContext(ctx, command, true, shutdown); err != nil {
		return err
	}
	a := c.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if a.connectionContext != c.operation || a.cmd != nil || s.parent.currentAppLocked(shutdown) != nil ||
		a.dnsMeasurements != done.dns || a.latencyMeasurements != done.latency {
		return errors.New("Linux Stop completion cannot publish over a replacement application or result slot")
	}
	if done.dns != nil {
		if err := desktopnetwork.LockContext(ctx, &done.dns.mu); err != nil {
			return err
		}
		defer done.dns.mu.Unlock()
		if done.dns.current != done.dnsOperation {
			return errors.New("Linux Stop cannot invalidate a replacement DNS request")
		}
	}
	if done.latency != nil {
		if err := desktopnetwork.LockContext(ctx, &done.latency.mu); err != nil {
			return err
		}
		defer done.latency.mu.Unlock()
		if done.latency.current != done.latencyOperation || done.latency.response != done.response {
			return errors.New("Linux Stop cannot invalidate a replacement latency request")
		}
	}
	for _, original := range done.registries {
		if value, present := original.registry.Load(a); present && (!original.present || value != original.value) {
			return errors.New("Linux Stop completion found a replacement runtime or graph owner")
		}
	}
	if done.dnsOperation != nil {
		if err := done.dnsOperation.invalidateContext(ctx); err != nil {
			return err
		}
	}
	if done.latencyOperation != nil {
		if err := done.latencyOperation.invalidateContext(ctx); err != nil {
			return err
		}
	}
	if done.response != nil && done.response != done.latencyOperation {
		if err := done.response.invalidateContext(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, original := range done.registries {
		if value, present := original.registry.Load(a); present {
			if !original.present || value != original.value || !original.registry.CompareAndDelete(a, original.value) {
				return errors.New("Linux Stop runtime changed during original completion publication")
			}
		}
	}
	// Advance only our original home-proof epoch; never invalidate a successor.
	homeExitProofs.counter(a).CompareAndSwap(done.homeGeneration, done.homeGeneration+1)
	if done.dns != nil {
		done.dns.used, done.dns.cancelled = map[string]bool{}, map[string]desktopDNSView{}
	}
	coverCancel := a.daitaCancel
	a.daitaCancel = nil
	a.state.Connected = false
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode, a.state.Base = "off", "", "", ""
	a.state.Phase, a.state.LastError = "off", ""
	done.published.Store(true)
	s.stopCompletion = nil
	// Actual stored DAITA cancellation is a context.CancelFunc. No replacement
	// callback is looked up after releasing application ownership.
	if coverCancel != nil {
		coverCancel()
	}
	return nil
}

// The terminal parent calls this before revoking its lifetime. Only a positive
// already-joined Stop receipt may finish here; ordinary capture/admission stays
// closed, and cancellation retains the receipt plus live parent for retry.
func (p *desktopLinuxNodeParent) finishStopCompletionForShutdown(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	s, stopping := p.session, p.stopping
	p.gate <- struct{}{}
	if !stopping {
		return errors.New("Linux Stop shutdown publication requires its original terminal parent")
	}
	if s == nil {
		return nil
	}
	if err := s.enter(ctx); err != nil {
		return err
	}
	pending := s.stopCompletion
	joined := pending != nil && pending.completion != nil && pending.completion.joined.Load()
	s.gate <- struct{}{}
	if !joined {
		return nil
	} // a partial native Stop remains with original terminal Close
	return pending.publishCompletionMode(ctx, pending.command, true)
}
