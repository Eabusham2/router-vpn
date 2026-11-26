package main

import (
	"context"
	"encoding/json"
	"errors"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// Classify each original public member once for this catalog. The selected
// owner still validates its current epoch before Start, status and adoption.
func desktopCandidateCatalogMetric(launch *desktopNodeLaunch, serverResponse bool) func(int) string {
	fallback := func(position int) string { return desktopCandidateMetricForIntent(launch, position, serverResponse) }
	if launch == nil || launch.chain == nil || !desktopNodeChainHasExternalFinal(launch.chain.selection.Nodes) {
		return fallback
	}
	var original *mobilemultihop.NodeChain
	allowPublic := true
	if e := launch.chain.execution; e != nil {
		var err error
		original, err = e.preparation.OriginalExternalFinalSource()
		if err != nil {
			return fallback
		}
		requested := e.preparation.Execution()
		local := requested == "auto"
		server := serverResponse && (requested == "server" || requested == "auto")
		e.mu.Lock()
		allowPublic = (local || server) && (e.ready == nil || local && e.ready.Progress.Execution == "local" || server && e.ready.Progress.Execution == "server")
		e.mu.Unlock()
	} else if launch.chain.policy != nil {
		original = launch.chain.policy.OriginalChain()
	}
	if original == nil {
		return fallback
	}
	metrics := original.PublicCandidatePrefixMeasurements()
	if len(metrics) != len(launch.chain.selection.Nodes) {
		return fallback
	}
	return func(position int) string {
		if position < 0 || position >= len(metrics) || metrics[position] == hopmeasure.CandidatePublicResponseMeasurement && !allowPublic {
			return ""
		}
		return metrics[position]
	}
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
	var original *mobilemultihop.NodeChain
	if e := first.launch.chain.execution; e != nil {
		var err error
		original, err = e.preparation.OriginalExternalFinalSource()
		if err != nil {
			return nil, nil, err
		}
	} else if first.launch.chain.policy != nil {
		original = first.launch.chain.policy.OriginalChain()
	}
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

// The public map retains the full original Local geometry. The shared compiler
// and the selected native owner independently authorize a public response trial.
func desktopPublicCandidateMembers(members []desktopNodeChainMember, execution string, position int) bool {
	if !validDesktopOrderedExecution(execution) || len(members) < 3 || len(members) > mobilemultihop.NodeChainExtendedLocalMaximumNodes ||
		position < 1 || position >= len(members)-1 || !desktopNodeChainHasExternalFinal(members) ||
		!mobilemultihop.NodeChainPrefixMode(members[0].Mode) || members[0].Profile.External != nil {
		return false
	}
	for i, member := range members {
		if i > 0 && (member.Profile.StartLayer != "" && member.Profile.StartLayer != "off" || member.Mode != "shadowsocks" || !desktopNodeChainImportedExecutionMiddle(member.Profile)) {
			return false
		}
	}
	return true
}

func addOrderedPublicCandidateSource(reply map[string]any, selection multihopSelection, position int, metric string) {
	execution := selection.Control.MultihopExecution
	if execution == "" {
		execution = "local"
	}
	if metric != hopmeasure.CandidatePublicResponseMeasurement || !desktopPublicCandidateMembers(selection.Nodes, execution, position) ||
		selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.chain == nil ||
		!selection.Native.chain.chain.HasExternalFinal() || selection.Native.chain.chain.CandidatePrefixMeasurement(position) != metric {
		return
	}
	reply["external_final"], reply["requested_execution"] = true, execution
	reply["public_response_source_nodes"] = originalCandidateResponseNodes(selection)
}
