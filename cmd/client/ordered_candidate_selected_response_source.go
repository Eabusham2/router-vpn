package main

// The UI receives only the original public identities and roles. This map is
// attached to one immutable candidate view; it grants no measurement authority.
type orderedCandidateResponseSourceNode struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`
	Kind string `json:"kind"`
}

func desktopCompareLocalPrivateResponseMembers(members []desktopNodeChainMember, execution string, position int) bool {
	if execution != "auto" || len(members) < 4 || position != len(members)-2 ||
		members[position].Mode != "shadowsocks" || members[position].Profile.External != nil {
		return false
	}
	return desktopSelectedPrivateStreamRoles(nodeChainSelectedReferences(members), func(i int) bool {
		return members[i].Profile.NodeKind == "external"
	}) && desktopNodeChainMultipleImportedExecutionShape(members)
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
