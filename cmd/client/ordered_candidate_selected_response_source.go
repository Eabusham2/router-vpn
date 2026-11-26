package main

import (
	"context"
	"net/url"
	"slices"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// Only a catalog request can set this opt-in. Subsequent operations inherit
// it from the issued view, together with its source and original owner.
type orderedServerResponseIntent struct{}

func candidateServerIntent(ctx context.Context, enabled bool) context.Context {
	if ctx == nil || candidateServerRequested(ctx) == enabled {
		return ctx
	}
	return context.WithValue(ctx, orderedServerResponseIntent{}, enabled)
}
func candidateServerRequested(ctx context.Context) bool {
	return ctx != nil && ctx.Value(orderedServerResponseIntent{}) == true
}
func takeCandidateServerIntent(query url.Values) (bool, bool) {
	values, ok := query["server_response"]
	if !ok {
		return false, true
	}
	delete(query, "server_response")
	return true, len(values) == 1 && values[0] == "true"
}

func candidateResponseExecutions(prep *mobilemultihop.NodeChainExecutionPreparation, pos int) []string {
	var owners []string
	if prep.SupportsCompareLocalResponseCandidate(pos) || prep.SupportsCompareLocalPublicResponseCandidate(pos) {
		owners = append(owners, "local")
	}
	if prep.SupportsServerResponseCandidate(pos) || prep.SupportsServerPublicResponseCandidate(pos) {
		owners = append(owners, "server")
	}
	return owners
}

func publishCandidateResponseOwners(reply map[string]any, owners []string, selected string) {
	if len(owners) == 0 {
		return
	}
	reply["response_executions"] = owners
	if selected != "" && slices.Contains(owners, selected) {
		reply["required_selected_execution"] = selected
	} else if len(owners) == 1 {
		reply["required_selected_execution"] = owners[0]
	}
}

// The UI receives only the original public identities and roles. This map is
// attached to one immutable candidate view; it grants no measurement authority.
type orderedCandidateResponseSourceNode struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`
	Kind string `json:"kind"`
}

func desktopCompareLocalPrivateResponseMembers(members []desktopNodeChainMember, execution string, position int) bool {
	if execution != "auto" || len(members) < 4 || position < 1 || position > len(members)-2 ||
		!mobilemultihop.NodeChainPrefixMode(members[0].Mode) || members[0].Profile.External != nil ||
		members[len(members)-1].Mode != "shadowsocks" || members[len(members)-1].Profile.External != nil {
		return false
	}
	for i, member := range members {
		if member.Profile.StartLayer != "" && member.Profile.StartLayer != "off" {
			return false
		}
		if i == 0 || i == len(members)-1 {
			continue
		}
		if member.Mode != "shadowsocks" {
			return false
		}
		if member.Profile.External == nil {
			if i == 1 {
				return false
			}
		} else if !desktopNodeChainImportedExecutionMiddle(member.Profile) {
			return false
		}
	}
	// This source-only map retains all original roles. The original captured
	// compiler and selected Local trial still grant the actual response plan.
	return (position == len(members)-2 || len(members) < mobilemultihop.NodeChainExtendedLocalMaximumNodes) &&
		desktopNodeChainMultipleImportedExecutionShape(members)
}

func orderedCandidateResponseSourceNodes(selection multihopSelection, execution string, position int) []orderedCandidateResponseSourceNode {
	if selection.Native == nil || selection.Native.chain == nil {
		return nil
	}
	if execution == "auto" && desktopTypedFinalResponseMembers(selection.Nodes, execution, position) {
		return originalCandidateResponseNodes(selection)
	}
	if selection.Native.chain.chain == nil ||
		!desktopCompareLocalPrivateResponseMembers(selection.Nodes, execution, position) {
		return nil
	}
	return originalCandidateResponseNodes(selection)
}

func originalCandidateResponseNodes(selection multihopSelection) []orderedCandidateResponseSourceNode {
	rows := make([]orderedCandidateResponseSourceNode, len(selection.Nodes))
	for i, member := range selection.Nodes {
		kind := "router-vpn"
		if member.Profile.External != nil {
			kind = "external"
		}
		rows[i] = orderedCandidateResponseSourceNode{member.Profile.ID, member.Mode, kind}
	}
	return rows
}

func publishSelectedResponseSource(response map[string]any, metric string, nodes []orderedCandidateResponseSourceNode) {
	if len(nodes) == 0 {
		return
	}
	if metric == hopmeasure.CandidatePublicResponseMeasurement {
		response["external_final"], response["public_response_source_nodes"] = true, nodes
		return
	}
	response["response_source_nodes"] = nodes
}

func (view *orderedCandidateView) addResponseSource(response map[string]any) {
	if view == nil {
		return
	}
	if view.candidateMode != "" {
		response["candidate_mode"] = view.candidateMode
	}
	if len(view.responseNodes) == 0 {
		return
	}
	publishSelectedResponseSource(response, candidateViewMetric(view.prefixes, view.position), view.responseNodes)
	response["view_token"], response["prefix_position"] = view.token, view.position
	response["requested_execution"], response["required_selected_execution"] = "auto", "local"
	selected := "local"
	if len(view.responseOwners) > 0 {
		selected = view.responseSelected
		response["requested_execution"] = view.responseRequested
		publishCandidateResponseOwners(response, view.responseOwners, selected)
	}
	response["selected_execution"], response["selection_epoch"] = selected, view.responseEpoch
}
