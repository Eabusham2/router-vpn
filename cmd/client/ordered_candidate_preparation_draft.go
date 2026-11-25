package main

import (
	"context"
	"errors"
	"net/netip"
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

// Adoption requires a fresh native receipt from the originally selected trial.
func desktopSelectedResponseProposal(members []desktopNodeChainMember, execution string, position int, candidate common.RouterProfile) bool {
	if (execution != "auto" && execution != "server") || len(members) < 3 || candidate.External != nil {
		return false
	}
	if len(members) == 3 {
		if position != 1 || !mobilemultihop.NodeChainPrefixMode(members[0].Mode) || members[0].Profile.External != nil ||
			members[1].Mode != "shadowsocks" || members[1].Profile.External == nil ||
			members[2].Mode != "shadowsocks" || members[2].Profile.External != nil {
			return false
		}
		middle := members[1].Profile.External
		if middle.Protocol != "shadowsocks" || middle.Shadowsocks == nil {
			return false
		}
		address, err := netip.ParseAddr(middle.Shadowsocks.Server)
		if err != nil || address.Zone() != "" || address.IsUnspecified() {
			return false
		}
	} else if !desktopCompareLocalPrivateResponseMembers(members, "auto", position) {
		return false
	}
	for _, m := range members {
		if m.Profile.ID == candidate.ID || candidate.NodeProofID != "" && m.Profile.NodeProofID == candidate.NodeProofID || m.Profile.StartLayer != "" && m.Profile.StartLayer != "off" {
			return false
		}
	}
	return candidate.StartLayer == "" || candidate.StartLayer == "off"
}

// The penultimate response retains the existing final-replacement action.
// An earlier response can add a private SS relay to a separately named path
// only when the complete original suffix and all of its sources still compile.
func orderedResponseProfile(ctx context.Context, root, execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, string, error) {
	var empty common.RouterProfile
	if execution != "local" && !desktopSelectedResponseProposal(members, execution, position, candidate) || position < 1 || position+1 >= len(members) || candidate.External != nil || members[position].Mode != "shadowsocks" {
		return empty, nil, "", errors.New("this measurement has no complete supported stream path")
	}
	p, rows, err := orderedCandidateProposalForExecution(members, position, candidate, profiles, execution)
	if err != nil {
		return empty, nil, "", err
	}
	proposed := slices.Clone(profiles)
	for i := range proposed {
		if proposed[i].ID == p.ID {
			proposed[i] = p
		}
	}
	if _, err := captureOrderedCandidateProposal(ctx, root, p, proposed, rows); err != nil {
		return empty, nil, "", err
	}
	action := "save-intermediate-profile"
	if position == len(members)-2 {
		action = "save-final-profile"
	}
	return p, rows, action, nil
}

const orderedCandidateDraftInsertAction = "insert-measured-hop"

// A draft response choice always inserts the measured relay. In particular,
// the penultimate choice retains the original final even though its separate
// named Save offer replaces that final. Source compilation is repeated at
// adoption; this preview cannot confer a selected-trial or measurement grant.
func orderedResponseDraftProposal(ctx context.Context, root, execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, error) {
	var empty common.RouterProfile
	if execution != "local" && !desktopSelectedResponseProposal(members, execution, position, candidate) ||
		position < 1 || position+1 >= len(members) || candidate.External != nil || members[position].Mode != "shadowsocks" {
		return empty, nil, errors.New("this response has no complete supported draft insertion")
	}
	for _, member := range members {
		if member.Profile.ID == candidate.ID || candidate.NodeProofID != "" && member.Profile.NodeProofID == candidate.NodeProofID {
			return empty, nil, errors.New("the measured candidate aliases an original draft member")
		}
	}
	control, rows, err := orderedDraftProposalWithMode(execution, members, position, candidate, profiles, "shadowsocks")
	if err != nil {
		return empty, nil, err
	}
	proposed := slices.Clone(profiles)
	for i := range proposed {
		if proposed[i].ID == control.ID {
			proposed[i] = control
		}
	}
	if _, err := captureOrderedCandidateProposal(ctx, root, control, proposed, rows); err != nil {
		return empty, nil, err
	}
	return control, rows, nil
}

// Insert the measured TCP candidate after the chosen prefix, keeping the
// selected final and every original suffix member/mode in their original order.
func orderedDraftProposal(execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, error) {
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
			return common.RouterProfile{}, nil, errors.New("the measured candidate does not expose a supported TCP relay")
		}
	}
	return orderedDraftProposalWithMode(execution, members, position, candidate, profiles, mode)
}

func orderedDraftProposalWithMode(execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile, mode string) (common.RouterProfile, []common.MultihopNodeSelection, error) {
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
