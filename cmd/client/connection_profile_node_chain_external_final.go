package main

import (
	"errors"
	"reflect"

	"router-vpn/internal/common"
)

// These are complete non-secret references. The real catalog and original
// private files are still recompiled before restoration or physical admission.
func validateSavedExternalFinalNodeChain(record connectionProfileRecord) error {
	bad := errors.New("saved ordered external exit lost its original paired entry or independent external sources")
	if record.Prefs == nil || record.Prefs.MultihopExecution != "local" ||
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
			!savedNodeChainDigest(row.ProfileToken) || len(row.Sources) != 1 || !savedNodeChainDigest(row.Sources[0].SHA256) {
			return bad
		}
		if i == 0 {
			if row.NodeKind != "" || row.External != nil || !common.ValidNodeProofID(row.NodeProofID) || row.Mode != "wg" ||
				row.Preferences == nil || row.Preferences.StartLayer != "" && row.Preferences.StartLayer != "off" || row.Sources[0].Mode != "wg" ||
				!reflect.DeepEqual(row.Preferences, record.Prefs) {
				return bad
			}
			continue
		}
		if row.NodeKind != "external" || row.NodeProofID != "" || row.Preferences != nil || row.Mode != "shadowsocks" ||
			row.External == nil || row.External.Protocol != "shadowsocks" || row.External.validate() != nil ||
			row.External.StartLayer != "" && row.External.StartLayer != "off" || row.Sources[0].Mode != "external-shadowsocks" {
			return bad
		}
	}
	return nil
}
