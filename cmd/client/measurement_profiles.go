package main

import (
	"errors"
	"strings"

	"router-vpn/internal/common"
)

// A measurement depends on every node that owns its dataplane, even when it
// only contacts the exit. Retain hashes rather than mutable profiles or secrets.
// Supplied profiles are the exact snapshots the caller will use for requests.
func captureMeasurementProfiles(a *app, st state, graph activeMultihopGraph, supplied ...common.RouterProfile) (map[string]string, error) {
	ids := []string{st.RouterID}
	if st.Mode == "multihop" {
		ids = []string{graph.EntryID, graph.ExitID}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tokens := make(map[string]string, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return nil, errors.New("measurement path has no node identity")
		}
		p, ok := a.profileByIDLocked(id)
		if !ok {
			return nil, errors.New("measurement node disappeared before the request")
		}
		tokens[id] = asyncMeasurementProfileToken(p)
	}
	for _, p := range supplied {
		current, ok := tokens[p.ID]
		if !ok || current != asyncMeasurementProfileToken(p) {
			return nil, errors.New("captured measurement profile no longer belongs to the current path")
		}
	}
	return tokens, nil
}

// The caller holds app.mu, including when adopting a durable measurement.
func validateMeasurementProfilesLocked(a *app, tokens map[string]string) error {
	if len(tokens) == 0 {
		return errors.New("measurement has no captured node profiles")
	}
	for id, token := range tokens {
		p, ok := a.profileByIDLocked(id)
		if !ok || asyncMeasurementProfileToken(p) != token {
			return errors.New("measurement node credentials or path policy changed; stale result was discarded")
		}
	}
	return nil
}

func validateMeasurementProfiles(a *app, tokens map[string]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return validateMeasurementProfilesLocked(a, tokens)
}
