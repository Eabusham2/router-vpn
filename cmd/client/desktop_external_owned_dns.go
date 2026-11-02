package main

import (
	"context"
	"errors"
	"time"
)

// The retained external owner has already proved a query through its selected
// native DNS router. Observing that proof must not start an ordinary resolver
// query or borrow the authenticated Router-node proof/registry.
func proveDesktopWindowsExternalDNS(ctx context.Context, a *app, observed observedConnection, runtimeID string, selected dnsSelection) (dnsProofState, bool) {
	result := dnsProofState{Mode: selected.Mode, Host: selected.Host, Status: "failed"}
	fail := func(err error) (dnsProofState, bool) {
		result.Reason = err.Error()
		return result, true
	}
	if a == nil {
		return result, false
	}
	raw, exists := desktopExternalRetainedLaunches.Load(a)
	if !exists {
		return result, false
	}
	l, ok := raw.(*desktopNodeLaunch)
	if !ok || l == nil || l.external == nil {
		return fail(errors.New("selected external DNS proof lost its retained runtime"))
	}
	owner := l.external.windows
	if owner == nil {
		return result, false // A different typed platform consumes its own retained proof.
	}
	if ctx == nil || ctx.Err() != nil || owner.app != a || owner.launch != l || l.external.retained != owner {
		return fail(errors.New("selected Windows external DNS proof has no original bounded owner"))
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := owner.enter(ctx); err != nil {
		return fail(err)
	}
	defer func() { owner.gate <- struct{}{} }()
	owner.mu.Lock()
	active := owner.activated && owner.proof != nil
	owner.mu.Unlock()
	revision := desktopOwnedNodeProfileToken(observed.Profile)
	if !active || !observed.Connected || observed.Phase != "connected" || observed.RouterID != l.profileID ||
		runtimeID != l.mode || observed.RuntimeMode != runtimeID ||
		revision != owner.profileToken && revision != owner.persistedToken ||
		[3]bool{observed.Profile.DAITAEnabled, observed.Profile.JumboTUN, observed.Profile.SocksEnabled} != owner.savedOptions ||
		validateDesktopWindowsExternalSource(observed.Profile, l) != nil {
		return fail(errors.New("selected Windows external DNS proof belongs to another observed source or path"))
	}
	wanted, err := expectedDNSSelection(l.external.profile)
	if err != nil || wanted != selected {
		return fail(errors.Join(err, errors.New("selected Windows external DNS policy changed")))
	}
	if _, err := a.readDesktopExternalProof(l); err != nil {
		return fail(err)
	}
	if err := owner.current(true); err != nil {
		return fail(err)
	}
	a.mu.Lock()
	current := a.state
	profile, found := a.profileByIDLocked(l.profileID)
	revision = desktopOwnedNodeProfileToken(profile)
	currentPath := found && a.cmd == l.command && current.Connected && current.Phase == "connected" &&
		current.RouterID == observed.RouterID && current.Mode == observed.Mode && current.LogicalMode == observed.LogicalMode &&
		current.RuntimeMode == runtimeID && current.Base == observed.Base &&
		(revision == owner.profileToken || revision == owner.persistedToken) && validateDesktopWindowsExternalSource(profile, l) == nil &&
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} == owner.savedOptions &&
		[3]bool{current.DAITA, current.Jumbo, current.Socks} == owner.options
	a.mu.Unlock()
	if !currentPath || ctx.Err() != nil {
		return fail(errors.New("selected Windows external DNS proof lost its captured connection during readback"))
	}
	result.Status = "passed"
	result.Reason = "the captured native DNS router proved this selected resolver before public-exit activation; the original external process, Windows TUN and protection remain current"
	return result, true
}
