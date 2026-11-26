package main

import (
	"context"
	"errors"
)

func orderedCandidateDraftScopeMatches(scope string, draft *multihopConnectRequest) bool {
	return draft != nil && draft.ordered() && (scope == orderedCandidateSavedPrefixScope && draft.Execution == "local" ||
		scope == orderedCandidateSelectedDraftScope && (draft.Execution == "server" || draft.Execution == "auto"))
}

func orderedCandidateDraftExecution(draft *multihopConnectRequest) string {
	if draft == nil {
		return "local"
	}
	return draft.Execution
}

// A view captures a socket-free complete original source. It has no operation,
// process, ready record, trial or epoch. Only the subsequently bound native
// child can issue positional measurement metadata and a chosen graph.
func newOrderedCandidateSourceLaunch(selection multihopSelection, session, target string, draft *multihopConnectRequest) (*desktopNodeLaunch, error) {
	launch, err := newDesktopNodeChainLaunch(selection, session, target)
	if err != nil || draft == nil || draft.Execution == "local" {
		return launch, err
	}
	if !nativeDesktopOrderedExecutionSelectionPlatformSupported(selection.Nodes, draft.Execution) {
		return nil, errors.New("selected draft has no supported native execution host")
	}
	e, err := newDesktopNodeChainExecutionSource(launch.chain, draft.Execution)
	if err != nil {
		return nil, err
	}
	if !desktopSelectedCandidateFamily(e) {
		return nil, errors.New("selected draft has no supported original packet candidate family")
	}
	if err = e.attach(launch); err != nil {
		return nil, err
	}
	return launch, nil
}

func captureSelectedDraftPreview(catalog *desktopNodeChainCandidateCatalog, position int) error {
	launch := catalog.launch
	e := desktopNodeChainLaunchExecution(launch)
	if !desktopSelectedCandidateFamily(e) || e.operation != nil || e.draftPurpose != nil || launch.command != nil || launch.directory != "" || e.original.preparation != nil || e.bound(launch) != nil || !desktopCandidatePositionForIntent(launch, position, catalog.serverResponse) {
		return errors.New("selected preview requires the original unused packet source")
	}
	var err error
	if e.socksPhysical != nil || e.connectPhysical != nil {
		catalog.typedEntryPreview, err = e.preparation.DescribeDesktopTypedEntryCandidate(e.original.socksPolicy, e.original.connectPolicy, position, catalog.inventory)
		return err
	}
	original := e.original.policy.OriginalChain()
	if e.preparation.RequiresDesktopExternalFinalExecutionObserver() {
		source, err := e.preparation.OriginalExternalFinalSource()
		if err != nil || source != original {
			return errors.New("selected draft changed its original public exit source")
		}
		catalog.plan, err = original.NewMultipleImportedCandidatePlan(position, catalog.inventory)
		return err
	}
	if e.multiplePhysical != nil {
		source, err := e.preparation.OriginalMultipleImportedSource()
		if err != nil || source != original {
			return errors.New("selected draft independent imports changed their original source")
		}
		catalog.plan, err = original.NewMultipleImportedCandidatePlan(position, catalog.inventory)
		return err
	}
	catalog.plan, err = original.NewCandidatePlan(position, catalog.inventory)
	return err
}

func prepareDesktopSelectedDraftHost(ctx context.Context, a *app, selection multihopSelection, p *orderedCandidatePreparation) (*desktopNodeLaunch, string, error) {
	if p == nil || p.app != a || p.selection.Native != selection.Native || !orderedCandidateDraftScopeMatches(orderedCandidateSelectedDraftScope, p.request.draft) ||
		p.request.Scope != orderedCandidateSelectedDraftScope {
		return nil, "", errors.New("selected draft host lost its original purpose")
	}
	capture, err := captureDesktopNodeChainHostContext(ctx, a, selection)
	if err != nil {
		return nil, "", err
	}
	request := &desktopNodeChainExecutionRequest{capture: capture, native: selection.Native, requested: p.request.draft.Execution, draftPurpose: p}
	return prepareDesktopNodeChainCapturedHost(ctx, capture, selection, nil, request)
}
