package main

import (
	"context"
	"errors"
	"runtime"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// The saved view is only a finite source selection. It carries no connected
// session, ready record or permission to measure before native preparation.
type orderedCandidatePreparedView struct {
	draft          *multihopConnectRequest
	token, network string
	scope          string
	candidateMode  string
	expires        time.Time
	position       int
	selection      multihopSelection
	catalog        *desktopNodeChainCandidateCatalog
	candidates     []orderedCandidateChoice
	prefixes       []orderedCandidatePrefix
	responseNodes  []orderedCandidateResponseSourceNode
	responseOwners []string
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
	if scope == orderedCandidateSavedPrefixScope && !orderedCandidatePrefixPlatformSupported() {
		return nil, errors.New("this platform has no accepted closed prefix controller")
	}

	return captureOrderedCandidateNativePreparedViewScope(ctx, a, position, scope, observe)
}

// The public platform wrapper is the sole caller of this source-only body.
// A captured view cannot create a native or Connected owner.
func captureOrderedCandidateNativePreparedViewScope(ctx context.Context, a *app, position int, scope string,
	observe func(context.Context) (string, error)) (*orderedCandidatePreparedView, error) {
	return captureOrderedCandidatePreparedSelection(ctx, a, position, scope, nil, observe)
}

func captureOrderedCandidatePreparedSelection(ctx context.Context, a *app, position int, scope string, draft *multihopConnectRequest,
	observe func(context.Context) (string, error)) (*orderedCandidatePreparedView, error) {
	scope, scopeErr := normalizedOrderedCandidateSavedScope(scope)
	if scopeErr != nil {
		return nil, scopeErr
	}
	if ctx == nil || ctx.Err() != nil || a == nil || position < 0 || position >= mobilemultihop.NodeChainExtendedLocalMaximumNodes || observe == nil {
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
	nodes, nodesErr := a.candidatePreparationNodesLocked(scope, control, draft)
	control = cloneRouterProfile(control)
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	revision, err := a.candidateCatalogRevisionLocked()
	initial := a.state
	a.mu.Unlock()
	if err != nil || !found || nodesErr != nil {
		return nil, errors.Join(err, nodesErr, errors.New("the original complete graph is unavailable for candidate testing"))
	}
	network, err := observe(ctx)
	if err != nil || network == "" {
		return nil, errors.Join(err, errors.New("saved candidate view has no original physical network"))
	}
	selection, err := resolveDesktopNodeChainSelection(control, profiles, nodes, orderedCandidateDraftExecution(draft))
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
	launch, err := newOrderedCandidateSourceLaunch(selection, session, runtime.GOOS, draft)
	if err != nil {
		return nil, err
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	view := &orderedCandidatePreparedView{draft: draft, scope: scope, token: token, network: network, expires: time.Now().Add(120 * time.Second), position: position, selection: selection}
	view.responseNodes = orderedCandidateResponseSourceNodes(selection, orderedCandidateDraftExecution(draft), position)
	if scope == orderedCandidateSavedPrefixScope {
		view.candidateMode = desktopPreparedCandidateMode(launch, position)
		if view.candidateMode != "" {
			view.responseNodes = originalCandidateResponseNodes(selection)
		}
	}
	if candidateServerRequested(ctx) && launch.chain.execution != nil {
		view.responseOwners = candidateResponseExecutions(launch.chain.execution.preparation, position)
		if len(view.responseOwners) > 0 {
			view.responseNodes = originalCandidateResponseNodes(selection)
		}
	}
	if e := launch.chain.execution; e != nil && len(view.responseOwners) == 0 && e.preparation.Execution() == "auto" && e.preparation.SupportsSelectedFinalResponseCandidate(position) {
		view.responseOwners = []string{"local"}
		view.responseNodes = originalCandidateResponseNodes(selection)
	}
	catalogMetric := desktopCandidateCatalogMetric(launch, candidateServerRequested(ctx))
	if scope == orderedCandidateSavedPrefixScope {
		fallback := catalogMetric
		catalogMetric = func(at int) string {
			if desktopPreparedCandidateMode(launch, at) != "" {
				return hopmeasure.CandidatePrivateResponseMeasurement
			}
			return fallback(at)
		}
	}
	if draft != nil && draft.Execution == "auto" && len(view.responseOwners) == 0 && catalogMetric(position) == hopmeasure.CandidatePublicResponseMeasurement {
		view.responseOwners = []string{"local"}
		view.responseNodes = originalCandidateResponseNodes(selection)
	}
	for i, member := range selection.Nodes {
		metric := catalogMetric(i)
		if scope == orderedCandidateSavedPrefixScope && (i == len(selection.Nodes)-1 || metric == "" || metric == hopmeasure.CandidateTCPMeasurement && !mobilemultihop.DesktopNodePhysicalGraphSupported(member.Mode, member.Profile.StartLayer)) {
			break
		}
		if metric != "" && (scope != orderedCandidateSelectedDraftScope || i < len(selection.Nodes)-1) {
			view.prefixes = append(view.prefixes, orderedPrefixChoice(i, member, metric))
		}
	}
	index := indexOrderedCandidateProposalProfiles(profiles)
	var candidates []*desktopNodeChainCandidateCatalog
	for _, profile := range profiles {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		captured, sourceErr := captureDesktopCandidateViewSource(ctx, a, launch, position, profile, revision, scope, catalogMetric)
		if sourceErr != nil {
			continue
		}
		choice := orderedCandidateChoice{ID: profile.ID, Name: profile.Name, Kind: "router-vpn"}
		if profile.External != nil {
			choice.Kind = "external"
		}
		proposalProfiles := index.members(selection.Nodes, profile.ID)
		if desktopCandidateResponseMetric(candidateViewMetric(view.prefixes, position)) {
			_, choice.Proposal, choice.ProposalAction, err = orderedResponseProfileWithMode(ctx, selection.Native.root, orderedCandidateDraftExecution(draft), selection.Nodes, position, profile, proposalProfiles, view.candidateMode)
			if draft == nil && view.candidateMode == "" && candidateViewMetric(view.prefixes, position) != hopmeasure.CandidatePublicResponseMeasurement {
				choice.ProposalAction = ""
			} else if draft != nil && mobilemultihop.NodeChainPrefixMode(view.candidateMode) && err == nil {
				choice.DraftProposal = append([]common.MultihopNodeSelection(nil), choice.Proposal...)
				choice.DraftAction = orderedCandidateDraftReplaceAction
			} else if draft != nil && view.candidateMode == "" {
				var draftErr error
				_, choice.DraftProposal, draftErr = orderedResponseDraftProposal(ctx, selection.Native.root, draft.Execution, selection.Nodes, position, profile, proposalProfiles)
				if draftErr == nil {
					choice.DraftAction = orderedCandidateDraftInsertAction
				}
			}
		} else if draft == nil {
			_, choice.Proposal, err = orderedCandidateProposal(selection.Nodes, position, profile, proposalProfiles)
		} else {
			_, choice.Proposal, err = orderedDraftProposal(draft.Execution, selection.Nodes, position, profile, proposalProfiles)
		}
		if err != nil {
			if len(view.responseNodes) != 0 && len(choice.DraftProposal) == 0 && candidateViewMetric(view.prefixes, position) == hopmeasure.CandidatePrivateResponseMeasurement {
				continue
			}
			choice.SaveReason = err.Error()
		}
		view.candidates = append(view.candidates, choice)
		candidates = append(candidates, captured)
	}
	candidates, view.candidates, err = filterDesktopPublicCandidateViews(ctx, candidates, view.candidates, position)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, errors.New("no saved candidate supports the measurement available through this prefix")
	}
	view.catalog, err = combineDesktopCandidateViewSources(ctx, candidates, position, scope)
	if err != nil || view.catalog.revision != revision || view.catalog.candidateMode != view.candidateMode {
		return nil, errors.Join(err, errors.New("saved candidate catalog changed during its view capture"))
	}
	if scope == orderedCandidateSavedPrefixScope {
		if view.catalog.prefixPreparation == nil || view.catalog.plan != nil || view.catalog.typedPlan != nil || view.catalog.prefixPreparation.OriginalSourceSHA256() != selection.Native.source {
			return nil, errors.New("saved prefix view lost its original closed source")
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
	if view == nil || p == nil || !now.Before(view.expires) || view.draft != p.request.draft || view.position != p.request.Position || view.scopeValue() != p.request.Scope || view.catalog == nil || view.catalog.serverResponse != p.request.serverResponse ||
		view.selection.Native == nil || p.selection.Native == nil || view.selection.Native.source != p.selection.Native.source ||
		view.network != p.network || view.catalog.revision != p.revision || p.inventory == nil {
		return false
	}
	if view.candidateMode != p.inventory.candidateMode {
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
