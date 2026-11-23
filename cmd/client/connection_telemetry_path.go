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
type connectionTelemetryPath struct {
	context.Context
	graph activeMultihopGraph
}

func connectionTelemetryPathContext(parent context.Context, a *app, p common.RouterProfile, st state, sessionID string, additionalProfiles ...common.RouterProfile) (*connectionTelemetryPath, func(), func() error, error) {
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
	paired, err := captureDesktopPairedMeasurement(parent, a, p, st)
	if err != nil {
		return nil, nil, nil, err
	}
	validateContext := func(ctx context.Context) error {
		if err := paired.current(ctx); err != nil {
			return err
		}
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
	ctx, stop, err := speedLabPathContextWithCaller(parent, validateContext)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx = withDesktopPairedMeasurement(ctx, paired)
	return &connectionTelemetryPath{Context: ctx, graph: graph}, stop, func() error { return validateContext(ctx) }, nil
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
	sessionID := sessionTrackerFor(a).snapshot(0).ID
	measured, stop, validate, err := connectionTelemetryPathContext(r.Context(), a, exit, st, sessionID, entry)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), r.Context(), "multihop latency") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer stop()
	graph := measured.graph
	if err := validateActiveMultihopSpeedGraph(st, graph, true, entry.ID, exit.ID); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err := validate(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	payload := map[string]any{
		"entry_id": entry.ID, "exit_id": exit.ID, "measured_at": time.Now().UTC(),
		"note": "independent cryptographic node-identity HTTP RTTs through the actual entry and exit proof lanes; current_path is the measured exit path, never an arithmetic hop estimate",
	}
	if graph.ChainNodes > 0 {
		measuredEndpoints, err := a.orderedLiveResponse(measured, graph, entry, exit, samples)
		if err != nil || validate() != nil {
			if !asyncMeasurementRequestError(w, r.Context(), measured, "ordered private path latency") {
				http.Error(w, "The original ordered private response is unavailable.", http.StatusConflict)
			}
			return
		}
		current, ok := getActiveMultihopGraph(a)
		if !ok || !sameActiveMultihopGraph(current, graph) {
			http.Error(w, "The ordered path changed during measurement.", http.StatusConflict)
			return
		}
		if measuredEndpoints[0].Connected {
			payload["entry"] = hopLatencyForNativeUI(entry, measuredEndpoints[0])
		}
		payload["exit"], payload["current_path"] = hopLatencyForNativeUI(exit, measuredEndpoints[1]), measuredEndpoints[1]
		payload["measured_at"], payload["active_route_id"] = measuredEndpoints[1].MeasuredAt, graph.mapRouteID()
		payload["note"] = "Fresh private HTTP responses through the retained ordered route."
		w.Header().Set("content-type", "application/json")
		w.Header().Set("cache-control", "no-store")
		_ = json.NewEncoder(w).Encode(payload)
		return
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
	if current, ok := getActiveMultihopGraph(a); !ok || !sameActiveMultihopGraph(current, graph) {
		http.Error(w, "multihop route changed during latency measurement", http.StatusConflict)
		return
	}
	payload["active_route_id"] = graph.mapRouteID()
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}
