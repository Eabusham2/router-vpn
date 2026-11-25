package main

import (
	"errors"

	"router-vpn/internal/common"
)

func validateStartupExternalFinalNodeChain(selection startupSelection) error {
	bad := errors.New("ordered external-final Last receipt lost its original entry, exit or complete source")
	capture := selection.NodeChain
	if capture == nil || capture.Schema != 8 || capture.Execution != "local" || capture.SelectedLast != "" ||
		selection.PathKind != startupNodeChainPathKind || selection.External != nil ||
		selection.RuntimeMode != "shadowsocks" || selection.LogicalMode != "multihop" || selection.Base != "wg" ||
		selection.UpdatedAt.IsZero() || !savedNodeChainDigest(capture.RootSHA256) || len(capture.Nodes) < 3 || len(capture.Nodes) > common.MultihopPhysicalTraversalDepth {
		return bad
	}
	first := capture.Nodes[0]
	if selection.RouterID != first.ID || selection.ProfileToken != first.ProfileToken || first.Mode != "wg" ||
		first.NodeKind != "" || !common.ValidNodeProofID(first.NodeProofID) {
		return bad
	}
	refs := make([]common.MultihopNodeSelection, len(capture.Nodes))
	for i, member := range capture.Nodes {
		refs[i] = common.MultihopNodeSelection{ID: member.ID, Mode: member.Mode}
		if member.CompilerHistory != "" || member.StartLayer != "" || !savedNodeChainDigest(member.ProfileToken) ||
			len(member.Sources) != 1 || !savedNodeChainDigest(member.Sources[0].SHA256) {
			return bad
		}
		if i == 0 {
			if member.Sources[0].Mode != "wg" {
				return bad
			}
		} else if member.NodeKind != "external" || member.NodeProofID != "" || member.Mode != "shadowsocks" || member.Sources[0].Mode != "external-shadowsocks" {
			return bad
		}
	}
	if !desktopExternalFinalReferences(refs) {
		return bad
	}
	return nil
}
