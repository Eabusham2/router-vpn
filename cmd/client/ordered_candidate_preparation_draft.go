package main

import (
	"context"
	"errors"
	"slices"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Resolve public references from the original editor request while holding
// app.mu. Source credentials and the final node's own settings always come
// from the retained store; the draft never substitutes a profile object.
func (a *app) candidatePreparationNodesLocked(scope string, control common.RouterProfile, draft *multihopConnectRequest) ([]common.MultihopNodeSelection, error) {
	if draft == nil {
		if scope == orderedCandidateSelectedDraftScope || !control.MultihopEnabled || control.MultihopExecution != "local" || len(control.MultihopNodes) < 2 {
			return nil, errors.New("temporary candidates require the selected complete saved Local graph")
		}
		return append([]common.MultihopNodeSelection(nil), control.MultihopNodes...), nil
	}
	if !orderedCandidateDraftScopeMatches(scope, draft) {
		return nil, errors.New("editor draft execution and temporary graph scope do not match")
	}
	if err := draft.validateOrdered(); err != nil {
		return nil, err
	}
	ids := nodeChainIDsForDraft(draft.Nodes)
	if err := a.validateDesktopProfileExpectationsLocked(draft.desktopProfileExpectations, ids, true); err != nil {
		return nil, err
	}
	return append([]common.MultihopNodeSelection(nil), draft.Nodes...), nil
}

// A measured paired SS stream can replace the final in a separately named
// future profile. The immutable Home owner still controls this editor draft.
func orderedDraftFinalProfile(execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, error) {
	if execution != "local" || len(members) < 3 || position != len(members)-2 || candidate.External != nil || members[position].Profile.External == nil || members[position].Mode != "shadowsocks" {
		return common.RouterProfile{}, nil, errors.New("this measured response cannot replace the final while preserving every other draft member")
	}
	return orderedCandidateProposalForExecution(members, position, candidate, profiles, execution)
}

// The penultimate response retains the existing final-replacement action.
// An earlier response can add a private SS relay to a separately named path
// only when the complete original suffix and all of its sources still compile.
func orderedDraftResponseProfile(ctx context.Context, root, execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, string, error) {
	if position == len(members)-2 {
		p, rows, err := orderedDraftFinalProfile(execution, members, position, candidate, profiles)
		return p, rows, "save-final-profile", err
	}
	var empty common.RouterProfile
	if execution != "local" || position < 1 || position+2 >= len(members) || len(members) >= common.MultihopMaximumNodes ||
		candidate.External != nil || !desktopNodeChainImportedExecutionMiddle(members[position].Profile) ||
		!desktopNodeChainImportedExecutionMiddle(members[position+1].Profile) {
		return empty, nil, "", errors.New("saving this measured intermediate requires an original Local path with literal Shadowsocks members on both sides")
	}
	for _, m := range members {
		if m.Profile.ID == candidate.ID {
			return empty, nil, "", errors.New("the measured candidate already belongs to this path")
		}
	}
	rows := slices.Insert(nodeChainSelectedReferences(members), position+1, common.MultihopNodeSelection{ID: candidate.ID, Mode: "shadowsocks"})
	p := cloneRouterProfile(members[len(members)-1].Profile)
	p.MultihopEnabled, p.MultihopExecution, p.MultihopNodes = true, execution, rows
	p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = "", "", ""
	proposed := slices.Clone(profiles)
	for i := range proposed {
		if proposed[i].ID == p.ID {
			proposed[i] = p
		}
	}
	if _, err := captureOrderedCandidateProposal(ctx, root, p, proposed, rows); err != nil {
		return empty, nil, "", err
	}
	return p, rows, "save-intermediate-profile", nil
}

// Insert the measured TCP candidate after the chosen prefix, keeping the
// selected final and every original suffix member/mode in their original order.
func orderedDraftProposal(execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, error) {
	var control common.RouterProfile
	if len(members) < 2 || len(members) >= mobilemultihop.NodeChainExtendedLocalMaximumNodes || position < 0 || position >= len(members)-1 {
		return control, nil, errors.New("the measured candidate cannot be inserted at this position")
	}
	rows := nodeChainSelectedReferences(members)
	for _, row := range rows {
		if row.ID == candidate.ID {
			return control, nil, errors.New("this candidate already belongs to the draft")
		}
	}
	// This is the same editable default as Add hop in all three desktop
	// editors. The returned measurement remains explicitly routed TCP
	// establishment to the linked node, not evidence of a WG handshake.
	mode := "wg"
	if candidate.External != nil {
		switch candidate.External.Protocol {
		case "socks5", "http-connect", "https-connect", "openvpn":
			mode = candidate.External.Protocol
		case "shadowsocks":
			mode = "shadowsocks"
		default:
			return control, nil, errors.New("the measured candidate does not expose a supported TCP relay")
		}
	}
	at := position + 1
	rows = append(rows, common.MultihopNodeSelection{})
	copy(rows[at+1:], rows[at:])
	rows[at] = common.MultihopNodeSelection{ID: candidate.ID, Mode: mode}
	control = cloneRouterProfile(members[len(members)-1].Profile)
	control.MultihopEnabled, control.MultihopExecution, control.MultihopNodes = true, execution, rows
	control.MultihopEntryID, control.MultihopExitID, control.MultihopEntryMode = "", "", ""
	proposed := append([]common.RouterProfile(nil), profiles...)
	for i := range proposed {
		if proposed[i].ID == control.ID {
			proposed[i] = control
		}
	}
	if _, err := resolveDesktopNodeChainSelection(control, proposed, rows, execution); err != nil {
		return control, nil, err
	}
	return control, rows, nil
}

func nodeChainIDsForDraft(nodes []common.MultihopNodeSelection) []string {
	ids := make([]string, len(nodes))
	for i, node := range nodes {
		ids[i] = node.ID
	}
	return ids
}

// Caller holds the original owner's closeMu and the application lock after
// retireOriginal joined native work and closed its observer.
func (p *orderedCandidatePreparation) draftDeliveryCurrentLocked() bool {
	a := p.app
	if a.candidatePreparation != p || !p.down || !p.nativeDown || p.invalidated.Load() ||
		a.connectionContext != nil || a.state != p.state || !orderedCandidatePreparationDownLocked(a) {
		return false
	}
	revision, err := a.candidateCatalogRevisionLocked()
	return err == nil && revision == p.revision
}
