//go:build linux

package main

import (
	"context"
	"errors"
	"time"
)

// This comparison consumes the original sealed profile. Presentation fields
// and a resolver receipt cannot construct a retained native session.
func (h *desktopLinuxNodeHost) matchesDNSObservation(observed observedConnection, runtimeID string, selected dnsSelection) error {
	if h == nil || h.launch == nil || !observed.Connected || observed.Phase != "connected" ||
		observed.RouterID != desktopExternalPathProfileID(h.launch) || runtimeID != h.launch.mode ||
		observed.RuntimeMode != "" && observed.RuntimeMode != runtimeID ||
		desktopOwnedNodeProfileToken(observed.Profile) != h.revision ||
		[3]bool{observed.Profile.DAITAEnabled, observed.Profile.JumboTUN, observed.Profile.SocksEnabled} != h.savedOptions {
		return errors.New("selected Linux DNS proof belongs to another observed connection")
	}
	profile, err := h.capturedProofProfile()
	if err != nil {
		return err
	}
	wanted, err := expectedDNSSelection(profile)
	if err != nil || wanted != selected {
		return errors.Join(err, errors.New("selected Linux DNS proof changed its sealed resolver policy"))
	}
	return nil
}

// The native proof is observed under the original session and host gates, but
// presentation and saved-profile changes also need the final app-lock check.
func (h *desktopLinuxNodeHost) currentDNSObservation(ctx context.Context, s *desktopLinuxNodeSession,
	observed observedConnection, runtimeID string) error {
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	a := h.parent.app
	a.mu.Lock()
	current := a.state
	profile, exists := a.profileByIDLocked(desktopExternalPathProfileID(h.launch))
	revision := desktopOwnedNodeProfileToken(profile)
	exactSource := revision == h.revision
	if h.external != nil {
		entry, _ := a.profileByIDLocked(h.launch.external.entry.ID)
		exactSource = (exactSource || revision == h.externalPersistedRevision) && validateDesktopLinuxExternalSource(profile, h.launch, entry) == nil
	}
	_, duplicateOwner := desktopNodeOwners.Load(a)
	currentPath := !duplicateOwner && s.parent.currentAppLocked(false) == nil && a.cmd == h.process.command &&
		current.Connected && current.Phase == "connected" && current.RouterID == observed.RouterID &&
		current.Mode == observed.Mode && current.LogicalMode == observed.LogicalMode && current.RuntimeMode == runtimeID && current.Base == observed.Base &&
		exists && exactSource &&
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} == h.savedOptions &&
		[3]bool{current.DAITA, current.Jumbo, current.Socks} == h.options
	a.mu.Unlock()
	if !currentPath || ctx.Err() != nil {
		return errors.New("selected Linux DNS proof lost its captured active connection during readback")
	}
	return nil
}

// A retained Linux session is deliberately separate from desktopNodeOwners:
// that legacy registry would introduce another Cmd.Wait/Stop owner. Read only
// the existing bootstrap/session chain; DNS observation never creates it.
// The session and host gates keep original retirement joined with this read.
func proveDesktopLinuxNodeDNS(ctx context.Context, a *app, observed observedConnection, runtimeID string, selected dnsSelection) (dnsProofState, bool) {
	result := dnsProofState{Mode: selected.Mode, Host: selected.Host, Status: "failed"}
	fail := func(err error) (dnsProofState, bool) {
		result.Reason = err.Error()
		return result, true
	}
	if a == nil {
		return result, false
	}
	a.mu.Lock()
	controller := a.localController
	a.mu.Unlock()
	if controller == nil || controller.nodeParent == nil {
		return result, false
	}
	p, ok := controller.nodeParent.(*desktopLinuxNodeParent)
	if !ok || p == nil {
		return fail(errors.New("selected Linux DNS proof has another original native parent"))
	}
	if ctx == nil || ctx.Err() != nil || p.gate == nil {
		return fail(errors.New("selected Linux DNS proof has no live bounded original caller"))
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		return fail(ctx.Err())
	case <-p.gate:
	}
	s := p.session
	p.gate <- struct{}{}
	if s == nil {
		return result, false
	}
	if err := s.enter(ctx); err != nil {
		return fail(err)
	}
	defer func() { s.gate <- struct{}{} }()
	h := s.active
	if s.parent == nil || s.parent.app != a || s.parent.controller != controller || s.parent.parent != p {
		return fail(errors.New("selected Linux DNS proof lost its original application session"))
	}
	if err := s.currentLocked(ctx); err != nil {
		return fail(err)
	}
	if h == nil {
		return result, false // Only a current original empty session can defer to another active path.
	}
	if h.parent == nil || !sameDesktopLinuxParentCapture(s.parent, h.parent) {
		return fail(errors.New("selected Linux DNS proof substituted another retained host"))
	}
	if _, exists := desktopNodeOwners.Load(a); exists {
		return fail(errors.New("selected Linux DNS proof has conflicting native process ownership"))
	}
	if err := h.enter(ctx); err != nil {
		return fail(err)
	}
	defer func() { h.gate <- struct{}{} }()
	if h.activation == nil || h.transaction == nil || h.transaction.journal != s.journal {
		return fail(errors.New("selected Linux DNS proof has no original proved active session"))
	}
	if err := h.activation.matches(h); err != nil {
		return fail(err)
	}
	if h.external != nil {
		revision := desktopOwnedNodeProfileToken(observed.Profile)
		if h.launch == nil || h.launch.external == nil || observed.RouterID != desktopExternalPathProfileID(h.launch) ||
			runtimeID != h.launch.mode || observed.RuntimeMode != "" && observed.RuntimeMode != runtimeID ||
			!observed.Connected || observed.Phase != "connected" ||
			revision != h.revision && revision != h.externalPersistedRevision ||
			[3]bool{observed.Profile.DAITAEnabled, observed.Profile.JumboTUN, observed.Profile.SocksEnabled} != h.savedOptions ||
			validateDesktopLinuxExternalSource(observed.Profile, h.launch) != nil {
			return fail(errors.New("selected Linux external DNS proof belongs to another observed path"))
		}
		wanted, err := expectedDNSSelection(h.launch.external.profile)
		if err != nil || wanted != selected {
			return fail(errors.New("selected Linux external DNS policy changed"))
		}
		if _, err := h.readExternalLocked(ctx); err != nil {
			return fail(err)
		}
		if err := h.currentDNSObservation(ctx, s, observed, runtimeID); err != nil {
			return fail(err)
		}
		result.Status = "passed"
		result.Reason = "the captured native DNS router proved this selected resolver before public-exit activation; the original external session, TUN and protection remain current"
		return result, true
	}
	if err := h.matchesDNSObservation(observed, runtimeID, selected); err != nil {
		return fail(err)
	}
	record, _, err := h.readReadyLocked(ctx, false)
	if err != nil {
		return fail(err)
	}
	if err := h.currentDNSObservation(ctx, s, observed, runtimeID); err != nil {
		return fail(err)
	}
	result.Status, result.LatencyMs = "passed", record.DNSMilliseconds
	result.Reason = "a query through the captured Linux native DNS router proved the selected resolver before connection; the original session, process, TUN and protection remain current"
	return result, true
}
