package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"router-vpn/internal/common"
)

// The Connect-screen endpoints are older callers of the same measurement
// engines. They must observe the same immutable path as Speed Lab rather than
// reintroducing an OS-route fallback for a multihop private address.
func connectionTelemetryPathContext(parent context.Context, a *app, p common.RouterProfile, st state, sessionID string, additionalProfiles ...common.RouterProfile) (context.Context, func(), func() error, error) {
	graph, graphOK := getActiveMultihopGraph(a)
	if st.Mode == "multihop" {
		if err := validateActiveMultihopSpeedGraph(st, graph, graphOK, graph.EntryID, graph.ExitID); err != nil {
			return nil, nil, nil, err
		}
	}
	profiles, err := captureMeasurementProfiles(a, st, graph, append([]common.RouterProfile{p}, additionalProfiles...)...)
	if err != nil {
		return nil, nil, nil, err
	}
	validate := func() error {
		if err := validateActiveTelemetryPath(a, p, st, sessionID); err != nil {
			return err
		}
		if st.Mode == "multihop" {
			if err := validateCurrentMultihopSpeedGraph(a, st, graph, sessionID); err != nil {
				return err
			}
		}
		return validateMeasurementProfiles(a, profiles)
	}
	ctx, stop, err := speedLabPathContext(parent, validate)
	return ctx, stop, validate, err
}

// Keep the legacy entry/exit JSON shape for the native clients. The values are
// measured independently through each reserved lane, never by adding or
// subtracting TCP samples from an unrelated configured graph.
func hopLatencyForNativeUI(p common.RouterProfile, value connectionLatencyResult) liveLatencyResult {
	return liveLatencyResult{
		ID: p.ID, Name: p.Name, NodeKind: p.NodeKind, Endpoint: p.Endpoint,
		Samples: value.Samples, Failed: value.Failed, MinMs: value.MinMs,
		MedianMs: value.MedianMs, AverageMs: value.AverageMs, P90Ms: value.P90Ms,
		MaxMs: value.MaxMs, MeasuredAt: value.MeasuredAt, Description: value.Proof,
	}
}

func (a *app) connectedMultihopLiveLatency(w http.ResponseWriter, r *http.Request, entry, exit common.RouterProfile, st state, samples int) {
	graph, ok := getActiveMultihopGraph(a)
	if err := validateActiveMultihopSpeedGraph(st, graph, ok, entry.ID, exit.ID); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	sessionID := sessionTrackerFor(a).snapshot(0).ID
	measured, stop, validate, err := connectionTelemetryPathContext(r.Context(), a, exit, st, sessionID, entry)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), r.Context(), "multihop latency") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer stop()
	payload := map[string]any{
		"entry_id": entry.ID, "exit_id": exit.ID, "measured_at": time.Now().UTC(),
		"note": "independent cryptographic node-identity HTTP RTTs through the actual entry and exit proof lanes; current_path is the measured exit path, never an arithmetic hop estimate",
	}
	entryValue, entryErr := measureRoutedProfileLatencyViaProxyContext(measured, entry, samples, multihopEntryProofProxy)
	if asyncMeasurementRequestError(w, r.Context(), measured, "multihop latency") {
		return
	}
	if err := validate(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if entryErr == nil {
		payload["entry"] = hopLatencyForNativeUI(entry, entryValue)
	} else {
		payload["entry_error"] = entryErr.Error()
	}
	exitValue, exitErr := measureRoutedProfileLatencyViaProxyContext(measured, exit, samples, multihopProofProxy)
	if asyncMeasurementRequestError(w, r.Context(), measured, "multihop latency") {
		return
	}
	if err := validate(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if exitErr == nil {
		payload["exit"] = hopLatencyForNativeUI(exit, exitValue)
		payload["current_path"] = exitValue
	} else {
		payload["exit_error"] = exitErr.Error()
		payload["current_path_error"] = exitErr.Error()
	}
	if entryErr != nil && exitErr != nil {
		http.Error(w, "both exact multihop node latency probes failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}
