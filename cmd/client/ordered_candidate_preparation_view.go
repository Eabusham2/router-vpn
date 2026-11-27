package main

import (
	"context"
	"encoding/json"
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
	append         *orderedCandidateAppendRequest
	appendSource   *orderedCandidateAppendViewSource
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
	originalFinal  *common.MultihopNodeSelection
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
	if scope == orderedCandidateAppendScope {
		return nil, errors.New("an incomplete prefix requires its explicit draft append source")
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
	view.candidateMode = desktopFinalCandidateSourceMode(launch, position)
	if scope == orderedCandidateSavedPrefixScope {
		view.candidateMode = desktopPreparedCandidateMode(launch, position)
	} else if scope == orderedCandidateSelectedDraftScope {
		view.candidateMode = desktopSelectedPacketCandidateMode(launch, position)
	}
	if view.candidateMode != "" && view.candidateMode == desktopFinalCandidateSourceMode(launch, position) {
		final := selection.Nodes[len(selection.Nodes)-1]
		view.originalFinal = &common.MultihopNodeSelection{ID: final.Profile.ID, Mode: final.Mode}
	} else {
		view.responseNodes = orderedCandidateResponseSourceNodes(selection, orderedCandidateDraftExecution(draft), position)
		if scope == orderedCandidateSavedPrefixScope && view.candidateMode != "" {
			view.responseNodes = originalCandidateResponseNodes(selection)
		}
	}
	if candidateServerRequested(ctx) && launch.chain.execution != nil {
		view.responseOwners = candidateResponseExecutions(launch.chain.execution.preparation, position)
		if len(view.responseOwners) > 0 {
			view.responseNodes = originalCandidateResponseNodes(selection)
		}
	}
	if e := launch.chain.execution; e != nil && len(view.responseOwners) == 0 && e.preparation.Execution() == "auto" && (e.preparation.SupportsSelectedFinalResponseCandidate(position) || e.preparation.SupportsCompareLocalPacketResponseCandidate(position)) {
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
			} else if draft != nil && view.originalFinal == nil && mobilemultihop.NodeChainPrefixMode(view.candidateMode) && err == nil {
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
			if (view.candidateMode != "" || len(view.responseNodes) != 0) && len(choice.DraftProposal) == 0 && candidateViewMetric(view.prefixes, position) == hopmeasure.CandidatePrivateResponseMeasurement {
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
	if view == nil || p == nil || !now.Before(view.expires) || view.draft != p.request.draft || view.append != p.request.append || view.position != p.request.Position || view.scopeValue() != p.request.Scope || view.catalog == nil || view.catalog.serverResponse != p.request.serverResponse ||
		view.selection.Native == nil || p.selection.Native == nil || view.selection.Native.source != p.selection.Native.source ||
		view.network != p.network || view.catalog.revision != p.revision || p.inventory == nil || view.candidateMode != p.inventory.candidateMode {
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

func (view *orderedCandidatePreparedView) addResponseSource(response map[string]any) {
	if view != nil {
		publishOrderedCandidateResponseSource(response, view.candidateMode, view.responseNodes, view.originalFinal)
		view.appendSource.publish(response)
	}
}

// Append views are source selections for an incomplete prefix. They never
// acquire a complete graph, original final, selected trial or connected owner.
type orderedCandidateAppendViewSource struct {
	Purpose           string `json:"purpose"`
	SourceSHA         string `json:"source_sha256"`
	ConfigSHA         string `json:"config_sha256"`
	DraftRevision     string `json:"draft_revision"`
	DeviceRevision    string `json:"device_revision"`
	DeviceSourceSHA   string `json:"device_source_sha256"`
	DeviceMTURevision string `json:"device_mtu_revision"`
	CandidateMode     string `json:"candidate_mode"`
	AppendPosition    int    `json:"append_position"`
	PrefixPosition    int    `json:"prefix_position"`
}

func (source *orderedCandidateAppendViewSource) publish(response map[string]any) {
	if source == nil {
		return
	}
	response["purpose"], response["source_sha256"], response["config_sha256"] = source.Purpose, source.SourceSHA, source.ConfigSHA
	response["draft_revision"], response["device_revision"] = source.DraftRevision, source.DeviceRevision
	response["device_source_sha256"], response["device_mtu_revision"] = source.DeviceSourceSHA, source.DeviceMTURevision
	response["append_position"] = source.AppendPosition
	response["origin"], response["requested_execution"] = "editor-draft", "local"
}

func (view *orderedCandidatePreparedView) isDraft() bool {
	return view != nil && (view.draft != nil || view.append != nil)
}
func (view *orderedCandidatePreparedView) requestedExecution() string {
	if view != nil && view.append != nil {
		return "local"
	}
	if view == nil {
		return ""
	}
	return orderedCandidateDraftExecution(view.draft)
}

func captureOrderedCandidateAppendView(ctx context.Context, a *app, position int, q *orderedCandidateAppendRequest,
	observe func(context.Context) (string, error)) (*orderedCandidatePreparedView, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || observe == nil || q.validate() != nil || position != q.AppendPosition-1 ||
		candidateServerRequested(ctx) || !orderedCandidatePrefixPlatformSupported() {
		return nil, errors.New("append view requires its exact incomplete Local prefix")
	}
	mtu, err := captureDeviceMTUPolicy(a)
	if err != nil {
		return nil, err
	}
	if err = desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	if !orderedCandidatePreparationIdleLocked(a) {
		a.mu.Unlock()
		return nil, errors.New("append view requires Home DOWN")
	}
	_, nodesErr := a.candidateAppendNodesLocked(q, orderedCandidateAppendScope)
	control, found := a.profileByIDLocked(a.profiles.SelectedID)
	control = cloneRouterProfile(control)
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	revision, err := a.candidateCatalogRevisionLocked()
	initial := a.state
	a.mu.Unlock()
	if err != nil || nodesErr != nil || !found {
		return nil, errors.Join(err, nodesErr, errors.New("append device and prefix sources changed"))
	}
	network, err := observe(ctx)
	if err != nil || network == "" {
		return nil, errors.Join(err, errors.New("append view has no original physical network"))
	}
	selection, err := captureDesktopCandidateAppendSelection(ctx, clientRoot(a), control, profiles, q, mtu)
	if err != nil {
		return nil, err
	}
	launch, err := newDesktopCandidateAppendSourceLaunch(selection)
	if err != nil {
		return nil, err
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	captured := desktopCandidateAppendCapture(selection)
	metadata := &orderedCandidateAppendViewSource{}
	if captured == nil || json.Unmarshal([]byte(captured.source.Metadata()), metadata) != nil ||
		metadata.Purpose != orderedCandidateAppendScope || metadata.SourceSHA != selection.Native.source || metadata.ConfigSHA != captured.source.ConfigSHA256() ||
		metadata.DraftRevision != q.DraftRevision || metadata.DeviceRevision != q.ExpectedProfileTokens[control.ID] ||
		metadata.DeviceSourceSHA == "" || metadata.DeviceMTURevision != mtu.token || metadata.CandidateMode != q.NextMode ||
		metadata.AppendPosition != q.AppendPosition || metadata.PrefixPosition != position {
		return nil, errors.New("append view lost its exact source metadata")
	}
	view := &orderedCandidatePreparedView{append: q, appendSource: metadata, scope: orderedCandidateAppendScope,
		token: token, network: network, expires: time.Now().Add(120 * time.Second), position: position, selection: selection, candidateMode: q.NextMode,
		responseNodes: originalCandidateResponseNodes(selection)}
	for i, member := range selection.Nodes {
		view.prefixes = append(view.prefixes, orderedPrefixChoice(i, member, hopmeasure.CandidatePrivateResponseMeasurement))
	}
	var candidates []*desktopNodeChainCandidateCatalog
	for _, profile := range profiles {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		candidate, sourceErr := captureDesktopAppendCandidateSourceProfiles(ctx, a, selection, launch, []common.RouterProfile{profile}, revision, true)
		if sourceErr != nil {
			continue
		}
		rows := append(append([]common.MultihopNodeSelection(nil), q.Nodes...), common.MultihopNodeSelection{ID: profile.ID, Mode: q.NextMode})
		view.candidates = append(view.candidates, orderedCandidateChoice{ID: profile.ID, Name: profile.Name, Kind: "router-vpn",
			Proposal: rows, DraftProposal: append([]common.MultihopNodeSelection(nil), rows...), DraftAction: orderedCandidateDraftAppendAction})
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return nil, errors.New("no paired packet candidate preserves this exact prefix and prospective MTU")
	}
	view.catalog, err = combineDesktopCandidateViewSources(ctx, candidates, position, orderedCandidateAppendScope)
	if err != nil || view.catalog == nil || view.catalog.revision != revision || view.catalog.candidateMode != q.NextMode ||
		view.catalog.prefixPreparation == nil || !view.catalog.prefixPreparation.IsAppend() ||
		view.catalog.prefixPreparation.OriginalSourceSHA256() != selection.Native.source || view.catalog.plan != nil ||
		view.catalog.typedPlan != nil || view.catalog.selectedPlan != nil {
		return nil, errors.Join(err, errors.New("append catalog lost its distinct source seal"))
	}
	if err = validateDesktopCandidateSavedSelection(ctx, selection, profiles); err != nil {
		return nil, err
	}
	currentNetwork, err := observe(ctx)
	if err != nil || currentNetwork != network {
		return nil, errors.Join(err, errors.New("append physical network changed during source capture"))
	}
	if err = desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	currentRevision, err := a.candidateCatalogRevisionLocked()
	if err != nil || currentRevision != revision || a.state != initial || !orderedCandidatePreparationIdleLocked(a) ||
		a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, q.requiredIDs(), true) != nil ||
		!desktopCandidateSavedProfilesCurrent(selection, a.profiles.Profiles) || mtu.current() != nil {
		return nil, errors.Join(err, errors.New("append view lost its original idle source"))
	}
	return view, ctx.Err()
}
