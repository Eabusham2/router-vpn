package main

import (
	"context"
	"errors"
	"runtime"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// The saved view is only a finite source selection. It carries no connected
// session, ready record or permission to measure before native preparation.
type orderedCandidatePreparedView struct {
	token, network string
	scope          string
	expires        time.Time
	position       int
	selection      multihopSelection
	catalog        *desktopNodeChainCandidateCatalog
	candidates     []orderedCandidateChoice
	prefixes       []orderedCandidatePrefix
}

func captureOrderedCandidatePreparedView(ctx context.Context, a *app, position int,
	observe func(context.Context) (string, error)) (*orderedCandidatePreparedView, error) {
	return captureOrderedCandidatePreparedViewScope(ctx, a, position, orderedCandidateSavedCompleteScope, observe)
}

func (view *orderedCandidatePreparedView) scopeValue() string {
	if view == nil {
		return ""
	}
	if view.scope == "" {
		return orderedCandidateSavedCompleteScope
	}
	return view.scope
}

func captureOrderedCandidatePreparedViewScope(ctx context.Context, a *app, position int, scope string,
	observe func(context.Context) (string, error)) (*orderedCandidatePreparedView, error) {
	scope, scopeErr := normalizedOrderedCandidateSavedScope(scope)
	if scopeErr != nil {
		return nil, scopeErr
	}
	if scope == orderedCandidateSavedPrefixScope && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return nil, errors.New("this platform has no accepted closed prefix controller")
	}

	return captureOrderedCandidateNativePreparedViewScope(ctx, a, position, scope, observe)
}

// The tagged installed Darwin fixture uses this complete source-only body below
// the public platform decision. It cannot create a native or Connected owner.
func captureOrderedCandidateNativePreparedViewScope(ctx context.Context, a *app, position int, scope string,
	observe func(context.Context) (string, error)) (*orderedCandidatePreparedView, error) {
	scope, scopeErr := normalizedOrderedCandidateSavedScope(scope)
	if scopeErr != nil {
		return nil, scopeErr
	}
	if ctx == nil || ctx.Err() != nil || a == nil || position < 0 || position > 7 || observe == nil {
		return nil, errors.New("saved candidates require an original idle controller and exact prefix position")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	if !orderedCandidatePreparationIdleLocked(a) {
		a.mu.Unlock()
		return nil, errors.New("saved candidate view requires Home DOWN and no pending temporary owner")
	}
	control, found := a.profileByIDLocked(a.profiles.SelectedID)
	control = cloneRouterProfile(control)
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	revision, err := a.candidateCatalogRevisionLocked()
	initial := a.state
	a.mu.Unlock()
	if err != nil || !found || !control.MultihopEnabled || control.MultihopExecution != "local" || len(control.MultihopNodes) < 2 {
		return nil, errors.Join(err, errors.New("save one complete Local graph before temporary candidate Test"))
	}
	network, err := observe(ctx)
	if err != nil || network == "" {
		return nil, errors.Join(err, errors.New("saved candidate view has no original physical network"))
	}
	selection, err := resolveDesktopNodeChainSelection(control, profiles, control.MultihopNodes, "local")
	if err != nil {
		return nil, err
	}
	selection, err = captureNativeNodeChainSelection(ctx, clientRoot(a), selection, []string{selection.ExitMode}, nil)
	if err != nil {
		return nil, err
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	launch, err := newDesktopNodeChainLaunch(selection, session, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	view := &orderedCandidatePreparedView{scope: scope, token: token, network: network, expires: time.Now().Add(120 * time.Second), position: position, selection: selection}
	for i, member := range selection.Nodes {
		if scope == orderedCandidateSavedPrefixScope && (i == len(selection.Nodes)-1 || !mobilemultihop.NodeChainPrefixMode(member.Mode) || !mobilemultihop.DesktopNodePhysicalGraphSupported(member.Mode, member.Profile.StartLayer)) {
			break
		}
		if mobilemultihop.NodeChainPrefixMode(member.Mode) {
			view.prefixes = append(view.prefixes, orderedCandidatePrefix{i, member.Profile.ID, member.Profile.Name, member.Mode})
		}
	}
	var ids []string
	for _, profile := range profiles {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if _, err := captureDesktopNodeChainCandidateSources(ctx, a, launch, position, []string{profile.ID}); err != nil {
			continue
		}
		choice := orderedCandidateChoice{ID: profile.ID, Name: profile.Name, Kind: "router-vpn"}
		if profile.External != nil {
			choice.Kind = "external"
		}
		_, choice.Proposal, err = orderedCandidateProposal(selection.Nodes, position, profile, profiles)
		if err != nil {
			choice.SaveReason = err.Error()
		}
		view.candidates = append(view.candidates, choice)
		ids = append(ids, profile.ID)
		if len(ids) == hopmeasure.CandidateMaximumTargets {
			break
		}
	}
	if len(ids) == 0 {
		return nil, errors.New("no exact saved SS2022 candidate sources for this packet prefix")
	}
	view.catalog, err = captureDesktopNodeChainCandidateSources(ctx, a, launch, position, ids)
	if err != nil || view.catalog.revision != revision {
		return nil, errors.Join(err, errors.New("saved candidate catalog changed during its view capture"))
	}
	if scope == orderedCandidateSavedPrefixScope {
		if _, err := captureDesktopNodeCandidatePrefixSource(ctx, selection, position, view.catalog.inventory); err != nil {
			return nil, err
		}
	}
	if err := selection.Native.chain.validate(ctx, control, profiles); err != nil {
		return nil, err
	}
	currentNetwork, err := observe(ctx)
	if err != nil || currentNetwork != network {
		return nil, errors.Join(err, errors.New("saved candidate physical network changed during view capture"))
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	currentRevision, err := a.candidateCatalogRevisionLocked()
	if err != nil || currentRevision != revision || a.state != initial || !orderedCandidatePreparationIdleLocked(a) ||
		!selection.Native.chain.profilesCurrent(control, a.profiles.Profiles) {
		return nil, errors.Join(err, errors.New("saved candidate view lost its original idle source"))
	}
	return view, ctx.Err()
}

func (view *orderedCandidatePreparedView) matchesPreparation(p *orderedCandidatePreparation, now time.Time) bool {
	if view == nil || p == nil || !now.Before(view.expires) || view.position != p.request.Position || view.scopeValue() != p.request.Scope || view.catalog == nil ||
		view.selection.Native == nil || p.selection.Native == nil || view.selection.Native.source != p.selection.Native.source ||
		view.network != p.network || view.catalog.revision != p.revision || p.inventory == nil {
		return false
	}
	for id, token := range p.inventory.profiles {
		if view.catalog.profiles[id] != token {
			return false
		}
	}
	for _, asset := range p.inventory.assets {
		matched := false
		for _, original := range view.catalog.assets {
			matched = matched || asset == original
		}
		if !matched {
			return false
		}
	}
	for _, file := range p.inventory.files {
		matched := false
		for _, original := range view.catalog.files {
			matched = matched || sameDesktopCandidateSourceFile(file, original)
		}
		if !matched {
			return false
		}
	}
	return true
}
