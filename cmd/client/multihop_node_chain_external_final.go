package main

import (
	"errors"
	"slices"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// The external final has its own public exit and DNS policy. The paired entry
// remains the selected control; it cannot impersonate the final's proof.
func desktopNodeChainExternalFinalSchema(members []desktopNodeChainMember) (int, error) {
	bad := errors.New("ordered external final requires a Local WireGuard or AWG2 entry and independently captured literal SS2022 streams")
	if len(members) < 3 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes ||
		!mobilemultihop.NodeChainPrefixMode(members[0].Mode) || members[0].Profile.External != nil ||
		members[0].Profile.NodeKind != "" && members[0].Profile.NodeKind != "router-vpn" ||
		!common.ValidNodeProofID(members[0].Profile.NodeProofID) {
		return 0, bad
	}
	seen := make(map[string]bool, len(members))
	for i, member := range members {
		p := member.Profile
		if !validProfileID(p.ID) || seen[p.ID] || !mobilemultihop.NodeChainExternalFinalEntryLayer(p.StartLayer) || i > 0 && p.StartLayer != "" && p.StartLayer != "off" {
			return 0, bad
		}
		seen[p.ID] = true
		if i > 0 && (member.Mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(p)) {
			return 0, bad
		}
	}
	return 8, nil
}

func desktopNodeChainHasExternalFinal(members []desktopNodeChainMember) bool {
	_, err := desktopNodeChainExternalFinalSchema(members)
	return err == nil
}

func desktopNodeChainControlCurrent(control common.RouterProfile, members []desktopNodeChainMember) bool {
	if len(members) == 0 {
		return false
	}
	original := desktopNodeChainControlProfile(members)
	return control.ID == original.ID && liveMeasurementProfileToken(control) == liveMeasurementProfileToken(original)
}

// Callers have already established a nonempty member inventory.
func desktopNodeChainControlProfile(members []desktopNodeChainMember) common.RouterProfile {
	if desktopNodeChainHasExternalFinal(members) {
		return members[0].Profile
	}
	return members[len(members)-1].Profile
}

// Requests explicitly name the external-final family. This public shape alone
// grants no source or runtime authority; linked identities are checked next.
func desktopExternalFinalReferences(nodes []common.MultihopNodeSelection) bool {
	if len(nodes) < 3 || len(nodes) > mobilemultihop.NodeChainExtendedLocalMaximumNodes || !mobilemultihop.NodeChainPrefixMode(nodes[0].Mode) || common.ValidateMultihopNodes(nodes) != nil {
		return false
	}
	for _, node := range nodes[1:] {
		if node.Mode != "shadowsocks" {
			return false
		}
	}
	return true
}

func desktopNodeChainMetadataMatchesSelection(meta mobilemultihop.DesktopNodeChainMetadata, selection multihopSelection) bool {
	if !desktopNodeChainControlCurrent(selection.Control, selection.Nodes) || meta.ProfileID != selection.Exit.ID ||
		meta.NodeID != selection.Exit.NodeProofID || meta.Mode != selection.ExitMode {
		return false
	}
	if !desktopNodeChainHasExternalFinal(selection.Nodes) {
		return meta.ExternalFinal == nil
	}
	if meta.ExternalFinal == nil || len(meta.Prefixes) != len(selection.Nodes) || meta.NodeID != "" ||
		meta.ExternalFinal.ProfileID != selection.Exit.ID ||
		meta.ExternalFinal.ExpectedPublicIP != selection.Exit.External.ExpectedPublicIP {
		return false
	}
	entry, final := meta.Prefixes[0], meta.Prefixes[len(meta.Prefixes)-1]
	return entry.ProfileID == selection.Control.ID && entry.NodeID == selection.Control.NodeProofID && entry.NodeKind == "" && entry.Mode == selection.Nodes[0].Mode &&
		final.ProfileID == selection.Exit.ID && final.NodeID == "" && final.NodeKind == "external" && final.Kind == "public-path" &&
		final.Mode == "shadowsocks" && final.Tag == meta.FinalTag && meta.ExternalFinal.SourceSHA256 == final.SourceSHA256
}

// Selected execution routes applications through its selector. The final
// public proof still belongs to the original Local hop and source.
func (owner *desktopNodeChainLaunch) metadataMatchesSelection(meta mobilemultihop.DesktopNodeChainMetadata) bool {
	if owner == nil {
		return false
	}
	if owner.execution != nil && meta.ExternalFinal != nil {
		e := owner.execution
		if e.original != owner || meta.FinalTag != mobilemultihop.SelectorTag || !e.preparation.RequiresDesktopExternalFinalExecutionObserver() || owner.selection.Native == nil || owner.selection.Native.chain == nil {
			return false
		}
		original, err := e.preparation.OriginalExternalFinalSource()
		if err != nil || original != owner.selection.Native.chain.chain || original.SourceSHA256() != meta.OriginalSourceSHA256 {
			return false
		}
		proofs := original.ProofInventory()
		if len(proofs) < 3 || !slices.Equal(meta.Prefixes, proofs) {
			return false
		}
		meta.FinalTag = proofs[len(proofs)-1].Tag
	}
	return desktopNodeChainMetadataMatchesSelection(meta, owner.selection)
}
