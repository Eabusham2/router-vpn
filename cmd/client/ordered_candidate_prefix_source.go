package main

import (
	"context"
	"encoding/json"
	"errors"

	"router-vpn/internal/mobilemultihop"
)

const (
	orderedCandidateSavedCompleteScope = "saved-complete-local"
	orderedCandidateSavedPrefixScope   = "saved-prefix-local"
)

func normalizedOrderedCandidateSavedScope(scope string) (string, error) {
	if scope == "" {
		return orderedCandidateSavedCompleteScope, nil
	}
	if scope != orderedCandidateSavedCompleteScope && scope != orderedCandidateSavedPrefixScope {
		return "", errors.New("saved candidates require an exact captured preparation purpose")
	}
	return scope, nil
}

func captureDesktopNodeCandidatePrefixSource(ctx context.Context, selection multihopSelection, position int, inventory string) (*mobilemultihop.NodeChainCandidatePreparation, error) {
	if ctx == nil || ctx.Err() != nil || selection.Native == nil || selection.Native.chain == nil || selection.Native.validate(selection) != nil || position < 0 || position >= len(selection.Nodes)-1 {
		return nil, errors.New("candidate prefix requires its complete original saved source and a non-final position")
	}
	for _, member := range selection.Nodes[:position+1] {
		if !mobilemultihop.NodeChainPrefixMode(member.Mode) || !mobilemultihop.DesktopNodePhysicalGraphSupported(member.Mode, member.Profile.StartLayer) {
			return nil, errors.New("selected candidate prefix contains an unsupported paired native packet member")
		}
	}
	// The original capture has already validated this sealed input and all saved
	// assets. Project only its typed source fields into the separate constructor;
	// an arbitrary incoming launch envelope is never stripped and trusted here.
	input, err := selection.Native.chain.chain.LaunchInput()
	if err != nil || input != selection.Native.chain.input {
		return nil, errors.New("candidate prefix lost its exact original full source")
	}
	var source mobilemultihop.NodeChainSource
	if json.Unmarshal([]byte(input), &source) != nil {
		return nil, errors.New("candidate prefix original source is unreadable")
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	prep, err := mobilemultihop.NewNodeChainCandidatePreparation(string(raw), position, inventory)
	if err != nil {
		return nil, err
	}
	if prep.OriginalSourceSHA256() != selection.Native.source || prep.PrefixPosition() != position || prep.CaptureSHA256() == "" {
		return nil, errors.New("candidate prefix changed original saved provenance")
	}
	return prep, ctx.Err()
}
