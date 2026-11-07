package main

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"router-vpn/internal/common"
)

const savedNodeLatencyMeasurement = "disconnected-direct-tcp-handshake"

func savedNodeLatencyKind(p common.RouterProfile) string {
	if p.LatencyReceipt == nil {
		return ""
	}
	return p.LatencyReceipt.Measurement
}

// Historical statistics remain displayable. Only a complete source-bound
// benchmark can enter saved ranking; absence of provenance is not evidence of
// fifty successes. No age is invented: the original time remains visible.
func savedNodeLatencyEligible(p common.RouterProfile) bool {
	r := p.LatencyReceipt
	kind := strings.ToLower(strings.TrimSpace(p.NodeKind))
	if (kind != "" && kind != "router-vpn") || p.External != nil || p.MultihopEnabled || r == nil ||
		r.Schema != 1 || r.Measurement != savedNodeLatencyMeasurement || r.Attempts < 50 || r.Attempts > 200 ||
		r.Failed != 0 || p.LatencySamples != r.Attempts || r.NetworkMetadata == "" ||
		r.SourceToken != liveMeasurementProfileToken(p) {
		return false
	}
	measured, err := time.Parse(time.RFC3339, p.LatencyLastTest)
	if err != nil || measured.IsZero() || measured.After(time.Now().Add(30*time.Second)) {
		return false
	}
	for _, n := range []float64{p.LatencyMinMs, p.LatencyMedianMs, p.LatencyTrimmedMeanMs, p.LatencyAverageMs, p.LatencyP90Ms, p.LatencyMaxMs} {
		if math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 || n > 60000 {
			return false
		}
	}
	return p.LatencyMinMs <= p.LatencyMedianMs && p.LatencyMedianMs <= p.LatencyP90Ms && p.LatencyP90Ms <= p.LatencyMaxMs &&
		p.LatencyMinMs <= p.LatencyTrimmedMeanMs && p.LatencyTrimmedMeanMs <= p.LatencyMaxMs &&
		p.LatencyMinMs <= p.LatencyAverageMs && p.LatencyAverageMs <= p.LatencyMaxMs
}

// Selection and ranking share one mutation transaction. The native client never
// does GET(old rows) -> unconditional select(id). This selects historical saved
// statistics, not a claim of current physical-network fastest performance.
func (a *app) selectSavedLowestLatency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q struct{}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&q); err != nil {
		http.Error(w, "empty selection object required", http.StatusBadRequest)
		return
	}
	if err := d.Decode(new(any)); err != io.EOF {
		http.Error(w, "one selection object required", http.StatusBadRequest)
		return
	}
	release, err := a.beginMutationOperation(r)
	if err != nil {
		if r.Context().Err() != nil {
			http.Error(w, "saved selection cancelled", http.StatusRequestTimeout)
		} else {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer release()
	a.mu.Lock()
	if r.Context().Err() != nil {
		a.mu.Unlock()
		http.Error(w, "saved selection cancelled", http.StatusRequestTimeout)
		return
	}
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "disconnect before selecting saved lowest latency", http.StatusConflict)
		return
	}
	ranked := sortPublicProfileStore(a.profiles, "latency")
	var eligible []common.RouterProfile
	for _, p := range ranked.Profiles {
		if savedNodeLatencyEligible(p) {
			eligible = append(eligible, p)
		}
	}
	// Preserve the existing native action's two-measured-node requirement.
	if len(eligible) < 2 {
		a.mu.Unlock()
		http.Error(w, "saved selection requires complete source-bound benchmarks on at least two Router nodes; retest legacy or incomplete measurements", http.StatusConflict)
		return
	}
	winner := eligible[0]
	previous := cloneRouterProfileStore(a.profiles)
	previousRouter := a.state.RouterID
	a.profiles.SelectedID = winner.ID
	a.state.RouterID = winner.ID
	if err = a.persistProfilesLocked(); err != nil {
		a.rollbackProfilesLocked(previous)
		a.state.RouterID = previousRouter
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"selected": true, "selected_id": winner.ID, "winner": publicProfileFor(winner), "scope": "saved", "note": "Selected lowest saved 10% trimmed mean; saved measurements may come from different networks and times. Retest Fastest for a current comparison."})
}
