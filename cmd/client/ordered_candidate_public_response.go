package main

import (
	"context"
	"encoding/json"
	"errors"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// A Local public source has one immutable class per original prefix. Avoid
// repeatedly validating the same physical policy and complete chain for every
// linked store row. Selected Server/Compare state still follows its live gate.
func desktopCandidateCatalogMetric(launch *desktopNodeLaunch, serverResponse bool) func(int) string {
	if launch != nil && launch.chain != nil && launch.chain.execution == nil && launch.chain.policy != nil &&
		desktopNodeChainHasExternalFinal(launch.chain.selection.Nodes) {
		metrics := launch.chain.policy.OriginalChain().PublicCandidatePrefixMeasurements()
		if len(metrics) == len(launch.chain.selection.Nodes) {
			return func(position int) string {
				if position < 0 || position >= len(metrics) {
					return ""
				}
				return metrics[position]
			}
		}
	}
	return func(position int) string { return desktopCandidateMetricForIntent(launch, position, serverResponse) }
}

// The shared source compiler removes every ambiguous public import before the
// complete inventory is sealed. Preserve each surviving row's exact captured
// input and source files; filtering supplies no measurement or adoption grant.
func filterDesktopPublicCandidateViews(ctx context.Context, parts []*desktopNodeChainCandidateCatalog, choices []orderedCandidateChoice, position int) ([]*desktopNodeChainCandidateCatalog, []orderedCandidateChoice, error) {
	if ctx == nil || ctx.Err() != nil || len(parts) != len(choices) {
		return nil, nil, errors.New("public candidate view lost its captured inventory")
	}
	if len(parts) == 0 {
		return parts, choices, nil
	}
	first := parts[0]
	if first == nil || first.launch == nil || first.launch.chain == nil {
		return nil, nil, errors.New("candidate view lost its original source")
	}
	if desktopCandidateMetricForIntent(first.launch, position, first.serverResponse) != hopmeasure.CandidatePublicResponseMeasurement {
		return parts, choices, nil
	}
	original := first.launch.chain.policy.OriginalChain()
	if original == nil {
		return nil, nil, errors.New("public candidate view lost its original Local chain")
	}
	inventory := mobilemultihop.NodeChainCandidateInventory{Schema: 1, Revision: first.revision}
	for i, part := range parts {
		var source mobilemultihop.NodeChainCandidateInventory
		if part == nil || part.launch != first.launch || part.app != first.app || part.revision != first.revision || part.serverResponse != first.serverResponse ||
			len(part.profiles) != 1 || part.profiles[choices[i].ID] == "" || json.Unmarshal([]byte(part.inventory), &source) != nil ||
			source.Schema != 1 || source.Revision != first.revision || len(source.Inputs) != 1 {
			return nil, nil, errors.New("public candidate view mixed source generations")
		}
		inventory.Inputs = append(inventory.Inputs, source.Inputs[0])
	}
	raw, err := json.Marshal(inventory)
	if err != nil {
		return nil, nil, err
	}
	filtered, err := original.FilterPublicCandidateInventory(position, string(raw))
	clear(raw)
	if err != nil {
		return nil, nil, err
	}
	var accepted mobilemultihop.NodeChainCandidateInventory
	if json.Unmarshal([]byte(filtered), &accepted) != nil || accepted.Schema != 1 || accepted.Revision != inventory.Revision {
		return nil, nil, errors.New("public candidate filter changed its source generation")
	}
	eligible := make(map[string]bool, len(accepted.Inputs))
	for _, input := range accepted.Inputs {
		eligible[input] = true
	}
	kept := make([]*desktopNodeChainCandidateCatalog, 0, len(accepted.Inputs))
	rows := make([]orderedCandidateChoice, 0, len(accepted.Inputs))
	for i, input := range inventory.Inputs {
		if eligible[input] {
			kept, rows = append(kept, parts[i]), append(rows, choices[i])
		}
	}
	return kept, rows, ctx.Err()
}

func desktopCandidateResponseMetric(metric string) bool {
	return metric == hopmeasure.CandidatePrivateResponseMeasurement || metric == hopmeasure.CandidatePublicResponseMeasurement
}

// This public map describes the retained Local source. The original shared
// compiler and native owner independently authorize the actual measurement.
// Public exit responses never acquire a private-agent or selected Server grant.
func desktopPublicCandidateMembers(members []desktopNodeChainMember, execution string, position int) bool {
	if execution != "local" || len(members) < 3 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes ||
		position < 1 || position >= len(members)-1 || !desktopNodeChainHasExternalFinal(members) ||
		members[0].Mode != "wg" || members[0].Profile.External != nil {
		return false
	}
	for i, member := range members {
		if member.Profile.StartLayer != "" && member.Profile.StartLayer != "off" ||
			i > 0 && (member.Mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(member.Profile)) {
			return false
		}
	}
	return true
}

func addOrderedPublicCandidateSource(reply map[string]any, selection multihopSelection, position int, metric string) {
	if metric != hopmeasure.CandidatePublicResponseMeasurement || !desktopPublicCandidateMembers(selection.Nodes, "local", position) ||
		selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.chain == nil ||
		!selection.Native.chain.chain.HasExternalFinal() || selection.Native.chain.chain.CandidatePrefixMeasurement(position) != metric {
		return
	}
	reply["external_final"], reply["requested_execution"] = true, "local"
	reply["public_response_source_nodes"] = originalCandidateResponseNodes(selection)
}
