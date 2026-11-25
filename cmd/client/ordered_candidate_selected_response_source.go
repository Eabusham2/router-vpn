package main

import "router-vpn/internal/mobilemultihop"

// The UI receives only the original public identities and roles. This map is
// attached to one immutable candidate view; it grants no measurement authority.
type orderedCandidateResponseSourceNode struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`
	Kind string `json:"kind"`
}

func desktopCompareLocalPrivateResponseMembers(members []desktopNodeChainMember, execution string, position int) bool {
	if execution != "auto" || len(members) < 4 || position < 1 || position > len(members)-2 ||
		members[0].Mode != "wg" || members[0].Profile.External != nil ||
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
	if selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.chain == nil ||
		!desktopCompareLocalPrivateResponseMembers(selection.Nodes, execution, position) {
		return nil
	}
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

func (view *orderedCandidateView) addResponseSource(response map[string]any) {
	if view == nil || len(view.responseNodes) == 0 {
		return
	}
	response["response_source_nodes"] = view.responseNodes
	response["view_token"], response["prefix_position"] = view.token, view.position
	response["requested_execution"], response["required_selected_execution"] = "auto", "local"
	response["selected_execution"], response["selection_epoch"] = "local", view.responseEpoch
}
