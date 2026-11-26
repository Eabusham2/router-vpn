package main

import (
	"errors"
	"reflect"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// externalFinalEntrySources requires the original WG pairing identity and,
// for AWG, the separate selected variant's transport asset.
func externalFinalEntrySources(mode, layer string, sources []connectionProfileNodeSource) bool {
	if !mobilemultihop.NodeChainPrefixMode(mode) || !mobilemultihop.NodeChainExternalFinalEntryLayer(layer) {
		return false
	}
	modes, err := savedNodeChainSourceModes(mode, layer)
	if err != nil || len(sources) != len(modes) {
		return false
	}
	for i, source := range sources {
		if source.Mode != modes[i] || !savedNodeChainDigest(source.SHA256) {
			return false
		}
	}
	return true
}

// These are complete non-secret references. The real catalog and original
// private files are still recompiled before restoration or physical admission.
func validateSavedExternalFinalNodeChain(record connectionProfileRecord) error {
	bad := errors.New("saved ordered external exit lost its original paired entry or independent external sources")
	if record.Prefs == nil || !validDesktopOrderedExecution(record.Prefs.MultihopExecution) ||
		!desktopExternalFinalReferences(record.Prefs.MultihopNodes) || len(record.NodeChain) != len(record.Prefs.MultihopNodes) ||
		record.External != nil || len(record.Hops) != 0 {
		return bad
	}
	first := record.NodeChain[0]
	if record.NodeID != "" && record.NodeID != first.ID || record.NodeProofID != "" && record.NodeProofID != first.NodeProofID {
		return bad
	}
	for i, row := range record.NodeChain {
		if row.ID != record.Prefs.MultihopNodes[i].ID || row.Mode != record.Prefs.MultihopNodes[i].Mode ||
			!savedNodeChainDigest(row.ProfileToken) {
			return bad
		}
		if i == 0 {
			if row.NodeKind != "" || row.External != nil || !common.ValidNodeProofID(row.NodeProofID) || row.Preferences == nil || !externalFinalEntrySources(row.Mode, row.Preferences.StartLayer, row.Sources) ||
				!reflect.DeepEqual(row.Preferences, record.Prefs) {
				return bad
			}
			continue
		}
		if row.NodeKind != "external" || row.NodeProofID != "" || row.Preferences != nil || row.Mode != "shadowsocks" ||
			row.External == nil || row.External.Protocol != "shadowsocks" || row.External.validate() != nil ||
			row.External.StartLayer != "" && row.External.StartLayer != "off" || len(row.Sources) != 1 || !savedNodeChainDigest(row.Sources[0].SHA256) || row.Sources[0].Mode != "external-shadowsocks" {
			return bad
		}
	}
	return nil
}
