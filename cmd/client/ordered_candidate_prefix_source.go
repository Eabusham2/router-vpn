package main

import (
	"context"
	"encoding/json"
	"errors"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

const (
	orderedCandidateSavedCompleteScope = "saved-complete-local"
	orderedCandidateSavedPrefixScope   = "saved-prefix-local"
	orderedCandidateSelectedDraftScope = "draft-complete-selected"
)

func normalizedOrderedCandidateSavedScope(scope string) (string, error) {
	if scope == "" {
		return orderedCandidateSavedCompleteScope, nil
	}
	if scope != orderedCandidateSavedCompleteScope && scope != orderedCandidateSavedPrefixScope && scope != orderedCandidateSelectedDraftScope {
		return "", errors.New("saved candidates require an exact captured preparation purpose")
	}
	return scope, nil
}

func captureDesktopNodeCandidatePrefixSource(ctx context.Context, selection multihopSelection, position int, inventory string) (*mobilemultihop.NodeChainCandidatePreparation, error) {
	if ctx == nil || ctx.Err() != nil || selection.Native == nil || selection.Native.chain == nil || selection.Native.validate(selection) != nil || position < 0 || position >= len(selection.Nodes)-1 {
		return nil, errors.New("candidate prefix requires its complete original saved source and a non-final position")
	}
	original := selection.Native.chain.chain
	metric := ""
	if original != nil {
		metric = original.CandidatePrefixMeasurement(position)
	}
	for i, member := range selection.Nodes[:position+1] {
		if i > 0 && (desktopCandidateResponseMetric(metric) || i < position && metric == hopmeasure.CandidateTCPMeasurement && desktopNodeChainImportedExecutionMiddle(member.Profile)) {
			continue
		}
		if !mobilemultihop.NodeChainPrefixMode(member.Mode) || !mobilemultihop.DesktopNodePhysicalGraphSupported(member.Mode, member.Profile.StartLayer) {
			return nil, errors.New("selected candidate prefix contains an unsupported paired native packet member")
		}
	}
	prep, err := captureDesktopNodeCandidatePrefixOriginal(selection.Native.chain, position, inventory)
	if err != nil {
		return nil, err
	}
	if prep.OriginalSourceSHA256() != selection.Native.source || prep.PrefixPosition() != position || prep.CaptureSHA256() == "" {
		return nil, errors.New("candidate prefix changed original saved provenance")
	}
	return prep, ctx.Err()
}

// These are distinct full-source constructors. A typed saved route supplies no
// generic connected path or runnable proxy suffix merely by preparing a prefix.
func captureDesktopNodeCandidatePrefixOriginal(original *desktopNodeChainCapture, position int, inventory string) (*mobilemultihop.NodeChainCandidatePreparation, error) {
	bad := errors.New("candidate prefix lost its exact original full source family")
	if original == nil {
		return nil, bad
	}
	switch {
	case original.socks != nil && original.socks.source != nil && original.chain == nil && original.connect == nil:
		input, err := original.socks.source.Source()
		if err != nil || input != original.input {
			return nil, bad
		}
		return mobilemultihop.NewNodeChainSOCKSCandidatePreparation(input, position, inventory)
	case original.connect != nil && original.connect.source != nil && original.chain == nil && original.socks == nil:
		input, err := original.connect.source.Source()
		if err != nil || input != original.input {
			return nil, bad
		}
		return mobilemultihop.NewNodeChainCONNECTCandidatePreparation(input, position, inventory)
	case original.chain != nil && original.socks == nil && original.connect == nil:
		// The original generic capture has already validated this launch input.
		// Project its typed source fields; never strip an arbitrary envelope.
		input, err := original.chain.LaunchInput()
		if err != nil || input != original.input {
			return nil, bad
		}
		if position > 0 && original.chain.HasExternalFinal() {
			return original.chain.NewPublicCandidatePreparation(position, inventory)
		}
		var source mobilemultihop.NodeChainSource
		if json.Unmarshal([]byte(input), &source) != nil {
			return nil, bad
		}
		raw, err := json.Marshal(source)
		if err != nil {
			return nil, err
		}
		defer clear(raw)
		return mobilemultihop.NewCapturedNodeChainCandidatePreparation(string(raw), position, inventory)
	default:
		return nil, bad
	}
}
