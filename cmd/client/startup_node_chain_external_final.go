package main

import (
	"errors"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func validateStartupExternalFinalNodeChain(selection startupSelection) error {
	bad := errors.New("ordered external-final Last receipt lost its original entry, exit or complete source")
	capture := selection.NodeChain
	if capture == nil || capture.Schema != 8 || !validDesktopOrderedExecution(capture.Execution) || capture.Execution == "local" && capture.SelectedLast != "" ||
		selection.PathKind != startupNodeChainPathKind || selection.External != nil ||
		selection.RuntimeMode != "shadowsocks" || selection.LogicalMode != "multihop" ||
		selection.UpdatedAt.IsZero() || !savedNodeChainDigest(capture.RootSHA256) || len(capture.Nodes) < 3 || len(capture.Nodes) > common.MultihopPhysicalTraversalDepth {
		return bad
	}
	first := capture.Nodes[0]
	if selection.RouterID != first.ID || selection.ProfileToken != first.ProfileToken || selection.Base != desktopExternalEntryBase(first.Mode) ||
		first.NodeKind != "" || !common.ValidNodeProofID(first.NodeProofID) {
		return bad
	}
	refs := make([]common.MultihopNodeSelection, len(capture.Nodes))
	ids, modes := make([]string, len(refs)), make([]string, len(refs))
	for i, member := range capture.Nodes {
		ids[i], modes[i] = member.ID, member.Mode
		refs[i] = common.MultihopNodeSelection{ID: member.ID, Mode: member.Mode}
		if capture.Execution == "local" && member.CompilerHistory != "" {
			return bad
		}
		if capture.Execution != "local" {
			if _, err := withStartupCompilerHistory(common.RouterProfile{}, member.CompilerHistory); err != nil {
				return bad
			}
		}
		if i > 0 && member.StartLayer != "" || !savedNodeChainDigest(member.ProfileToken) {
			return bad
		}
		if i == 0 {
			if member.StartLayer == "off" || !externalFinalEntrySources(member.Mode, member.StartLayer, member.Sources) {
				return bad
			}
		} else if member.NodeKind != "external" || member.NodeProofID != "" || member.Mode != "shadowsocks" || len(member.Sources) != 1 || !savedNodeChainDigest(member.Sources[0].SHA256) || member.Sources[0].Mode != "external-shadowsocks" {
			return bad
		}
	}
	if !desktopExternalFinalReferences(refs) || capture.Execution != "local" && mobilemultihop.ValidateStoredDesktopExternalFinalLast(capture.SelectedLast, capture.Execution, first.NodeProofID, first.StartLayer, ids, modes) != nil {
		return bad
	}
	return nil
}
