package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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

// This is a source-only proposal shape. The captured native classifier and
// original selected receipt still authorize measurement and adoption.
func desktopTypedFinalResponseMembers(members []desktopNodeChainMember, execution string, position int) bool {
	if !validDesktopOrderedExecution(execution) || len(members) < 3 || len(members) > mobilemultihop.NodeChainMaximumNodes || position != len(members)-2 {
		return false
	}
	for i, member := range members {
		if i >= position && member.Profile.StartLayer != "" && member.Profile.StartLayer != "off" {
			return false
		}
		if i == position {
			if !desktopNodeChainSOCKSMiddle(member.Profile, member.Mode) && !desktopNodeChainCONNECTMiddle(member.Profile, member.Mode) && !desktopNodeChainOpenVPNMiddle(member.Profile, member.Mode) {
				return false
			}
		} else if member.Profile.External != nil || i < position && !mobilemultihop.NodeChainPrefixMode(member.Mode) || i > position && member.Mode != "shadowsocks" {
			return false
		}
	}
	return true
}

// This describes a next-connection proposal, not a connected measurement
// grant. Only the retained Local catalog can choose this response protocol.
func desktopFinalResponseMembers(members []desktopNodeChainMember, execution string, position int, candidate common.RouterProfile, mode string) bool {
	if execution != "local" || len(members) < 2 || len(members) > mobilemultihop.NodeChainMaximumNodes || position != len(members)-2 ||
		mode != "hysteria2" && !mobilemultihop.NodeChainPrefixMode(mode) ||
		candidate.External != nil || candidate.NodeKind != "" && candidate.NodeKind != "router-vpn" ||
		candidate.StartLayer != "" && candidate.StartLayer != "off" {
		return false
	}
	for i, member := range members {
		if member.Profile.External != nil || member.Profile.NodeKind != "" && member.Profile.NodeKind != "router-vpn" ||
			member.Profile.StartLayer != "" && member.Profile.StartLayer != "off" || member.Profile.ID == candidate.ID ||
			candidate.NodeProofID != "" && member.Profile.NodeProofID == candidate.NodeProofID {
			return false
		}
		if i < len(members)-1 && !mobilemultihop.NodeChainPrefixMode(member.Mode) || i == len(members)-1 && member.Mode != mode {
			return false
		}
	}
	return true
}

// Packet successor proposals retain every original suffix member. This source
// classifier grants no native or dormant measurement authority.
func desktopConnectedResponseMembers(members []desktopNodeChainMember, execution string, position int, candidate common.RouterProfile, mode string) bool {
	if desktopFinalResponseMembers(members, execution, position, candidate, mode) {
		return true
	}
	return execution == "local" && desktopPacketResponseMembers(members, position, candidate, mode)
}

// This shared public shape carries no Local or selected runtime authority.
func desktopPacketResponseMembers(members []desktopNodeChainMember, position int, candidate common.RouterProfile, mode string) bool {
	if !mobilemultihop.NodeChainPrefixMode(mode) || len(members) < 3 || len(members) > mobilemultihop.NodeChainMaximumNodes && (mode != "wg" || !common.ExtendedPairedLocalMultihopSelection(nodeChainSelectedReferences(members))) || position < 0 || position > len(members)-3 || members[position+1].Mode != mode ||
		candidate.External != nil || candidate.NodeKind != "" && candidate.NodeKind != "router-vpn" || candidate.StartLayer != "" && candidate.StartLayer != "off" {
		return false
	}
	for i, member := range members {
		p := member.Profile
		if p.ID == candidate.ID || candidate.NodeProofID != "" && p.NodeProofID == candidate.NodeProofID {
			return false
		}
		if p.External != nil || p.NodeKind == "external" {
			// Imported credentials remain in the original schema-six registry.
			// This public proposal cannot replace an import or infer UDP authority.
			if len(members) > mobilemultihop.NodeChainMaximumNodes || i == 0 || i == len(members)-1 || i == position+1 ||
				member.Mode != "shadowsocks" || members[len(members)-1].Mode != "shadowsocks" ||
				!desktopNodeChainImportedExecutionMiddle(p) || p.StartLayer != "" && p.StartLayer != "off" {
				return false
			}
			continue
		}
		if p.NodeKind != "" && p.NodeKind != "router-vpn" ||
			(i > position || len(members) > mobilemultihop.NodeChainMaximumNodes) && p.StartLayer != "" && p.StartLayer != "off" ||
			!desktopCONNECTExecutionPairedLayer(p.StartLayer) ||
			i < len(members)-1 && !mobilemultihop.NodeChainPrefixMode(member.Mode) ||
			i == len(members)-1 && member.Mode != "shadowsocks" && member.Mode != "hysteria2" {
			return false
		}
	}
	return true
}

// Selected packet proposals have their own source family. The live selected
// catalog still binds the actual winner and epoch; this only checks the exact
// complete public replacement before the private route is compiled again.
func desktopCandidateResponseMembers(members []desktopNodeChainMember, execution string, position int, candidate common.RouterProfile, mode string) bool {
	if desktopConnectedResponseMembers(members, execution, position, candidate, mode) {
		return true
	}
	return (execution == "auto" || execution == "server") &&
		desktopPacketResponseMembers(members, position, candidate, mode)
}

// Adoption requires a fresh native receipt from the originally selected trial.
func desktopSelectedResponseProposal(members []desktopNodeChainMember, execution string, position int, candidate common.RouterProfile) bool {
	if (execution != "auto" && execution != "server") || len(members) < 3 || candidate.External != nil {
		return false
	}
	typedFinal := desktopTypedFinalResponseMembers(members, execution, position)
	if typedFinal {
		// The complete typed prefix is retained; only its final can change.
	} else if len(members) == 3 {
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
	for i, m := range members {
		if m.Profile.ID == candidate.ID || candidate.NodeProofID != "" && m.Profile.NodeProofID == candidate.NodeProofID || (!typedFinal || i >= position) && m.Profile.StartLayer != "" && m.Profile.StartLayer != "off" {
			return false
		}
	}
	return candidate.StartLayer == "" || candidate.StartLayer == "off"
}

// The penultimate response retains the existing final-replacement action.
// An earlier response can add a private SS relay to a separately named path
// only when the complete original suffix and all of its sources still compile.
func orderedResponseProfile(ctx context.Context, root, execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, string, error) {
	return orderedResponseProfileWithMode(ctx, root, execution, members, position, candidate, profiles, "")
}

func orderedResponseProfileWithMode(ctx context.Context, root, execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile, candidateMode string) (common.RouterProfile, []common.MultihopNodeSelection, string, error) {
	var empty common.RouterProfile
	publicResponse := desktopPublicCandidateMembers(members, execution, position) && desktopNodeChainImportedExecutionMiddle(candidate)
	typedFinal := desktopTypedFinalResponseMembers(members, execution, position)
	if candidateMode != "" {
		if !desktopCandidateResponseMembers(members, execution, position, candidate, candidateMode) {
			return empty, nil, "", errors.New("this response cannot replace the original member while preserving its transport and complete route")
		}
	} else if !publicResponse && (execution != "local" && !desktopSelectedResponseProposal(members, execution, position, candidate) || position < 1 || position+1 >= len(members) || candidate.External != nil || members[position].Mode != "shadowsocks" && !typedFinal) {
		return empty, nil, "", errors.New("this measurement has no complete supported stream path")
	}
	p, rows, err := orderedCandidateProposalForExecutionWithMode(members, position, candidate, profiles, execution, candidateMode)
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
	if position == len(members)-2 && !publicResponse {
		action = "save-final-profile"
	}
	return p, rows, action, nil
}

const (
	orderedCandidateDraftInsertAction  = "insert-measured-hop"
	orderedCandidateDraftReplaceAction = "replace-measured-hop"
	orderedCandidateDraftAppendAction  = "append-measured-hop"
)

// A draft response choice always inserts the measured relay. In particular,
// the penultimate choice retains the original final even though its separate
// named Save offer replaces that final. Source compilation is repeated at
// adoption; this preview cannot confer a selected-trial or measurement grant.
func orderedResponseDraftProposal(ctx context.Context, root, execution string, members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, error) {
	var empty common.RouterProfile
	if desktopTypedFinalResponseMembers(members, execution, position) {
		return empty, nil, errors.New("this imported prefix can replace its final but cannot insert another hop")
	}
	publicResponse := desktopPublicCandidateMembers(members, execution, position) && desktopNodeChainImportedExecutionMiddle(candidate)
	if !publicResponse && (execution != "local" && !desktopSelectedResponseProposal(members, execution, position, candidate) ||
		position < 1 || position+1 >= len(members) || candidate.External != nil || members[position].Mode != "shadowsocks") {
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
	if desktopNodeChainHasExternalFinal(members) && (!validDesktopOrderedExecution(execution) || position != 0 && !desktopPublicCandidateMembers(members, execution, position) || mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(candidate)) {
		return control, nil, errors.New("the external-final draft requires an original literal SS2022 candidate through its captured prefix")
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
	control = cloneRouterProfile(desktopNodeChainControlProfile(members))
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

// An incomplete editor prefix has no selected final and cannot be decoded as
// a complete Connect request. Only the explicit append purpose accepts it.
type orderedCandidateAppendRequest struct {
	Schema         int                            `json:"schema"`
	Purpose        string                         `json:"purpose"`
	Execution      string                         `json:"execution"`
	DraftRevision  string                         `json:"draft_revision"`
	AppendPosition int                            `json:"append_position"`
	NextMode       string                         `json:"next_mode"`
	Nodes          []common.MultihopNodeSelection `json:"nodes"`
	desktopProfileExpectations
}

func (q *orderedCandidateAppendRequest) validate() error {
	bad := errors.New("append measurement requires its exact incomplete Local prefix, next transport mode and original device selection")
	if q == nil || q.Schema != 1 || q.Purpose != orderedCandidateAppendScope || q.Execution != "local" ||
		!validViaEntryRequestID(q.DraftRevision) || len(q.Nodes) < 1 || len(q.Nodes) >= mobilemultihop.NodeChainExtendedLocalMaximumNodes ||
		q.AppendPosition != len(q.Nodes) || !mobilemultihop.NodeChainCandidateAppendNextMode(q.NextMode) ||
		q.ExpectedSelectedNodeID == nil || !validProfileID(*q.ExpectedSelectedNodeID) || q.ExpectedProfileTokens == nil {
		return bad
	}
	seen := map[string]bool{}
	for position, node := range q.Nodes {
		if !validProfileID(node.ID) || seen[node.ID] ||
			!mobilemultihop.NodeChainPrefixMode(node.Mode) && (position == 0 || node.Mode != "shadowsocks") {
			return bad
		}
		seen[node.ID] = true
	}
	required := q.requiredIDs()
	if len(q.ExpectedProfileTokens) != len(required) {
		return bad
	}
	for _, id := range required {
		if !validExternalProfileExpectationToken(q.ExpectedProfileTokens[id]) {
			return bad
		}
	}
	return nil
}

func (q *orderedCandidateAppendRequest) requiredIDs() []string {
	if q == nil {
		return nil
	}
	ids := nodeChainIDsForDraft(q.Nodes)
	if q.ExpectedSelectedNodeID != nil && !slices.Contains(ids, *q.ExpectedSelectedNodeID) {
		ids = append(ids, *q.ExpectedSelectedNodeID)
	}
	return ids
}

func (q *orderedCandidateAppendRequest) digest() string {
	if q.validate() != nil {
		return ""
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func decodeOrderedCandidateAppendRequest(body io.Reader) (*orderedCandidateAppendRequest, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	fields, err := externalConnectJSONObject(raw)
	if err != nil {
		return nil, err
	}
	for name := range fields {
		switch name {
		case "schema", "purpose", "execution", "draft_revision", "append_position", "next_mode", "nodes", "expected_selected_node_id", "expected_profile_tokens":
		default:
			return nil, errors.New("append source cannot mix complete-route, selected or unknown fields")
		}
	}
	if len(fields) != 9 {
		return nil, errors.New("append source requires every original prefix and device field")
	}
	expectations, err := decodeDesktopProfileExpectations(fields)
	if err != nil {
		return nil, err
	}
	var rows []json.RawMessage
	if json.Unmarshal(fields["nodes"], &rows) != nil || len(rows) < 1 || len(rows) >= mobilemultihop.NodeChainExtendedLocalMaximumNodes {
		return nil, errors.New("append source requires bounded real prefix rows")
	}
	for _, raw := range rows {
		row, err := externalConnectJSONObject(raw)
		if err != nil || len(row) != 2 || row["id"] == nil || row["mode"] == nil {
			return nil, errors.New("append rows require only original identity and raw mode")
		}
	}
	var q orderedCandidateAppendRequest
	if err := json.Unmarshal(raw, &q); err != nil {
		return nil, err
	}
	q.desktopProfileExpectations = expectations
	if err := q.validate(); err != nil {
		return nil, err
	}
	return &q, nil
}

func (a *app) candidateAppendNodesLocked(q *orderedCandidateAppendRequest, scope string) ([]common.MultihopNodeSelection, error) {
	if scope != orderedCandidateAppendScope || q.validate() != nil {
		return nil, errors.New("incomplete prefix requires its distinct append purpose")
	}
	if err := a.validateDesktopProfileExpectationsLocked(q.desktopProfileExpectations, q.requiredIDs(), true); err != nil {
		return nil, err
	}
	return slices.Clone(q.Nodes), nil
}
