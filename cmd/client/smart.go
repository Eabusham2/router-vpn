package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type smartResult struct {
	OK        bool     `json:"ok"`
	Mode      string   `json:"mode"`
	LatencyMS float64  `json:"latency_ms"`
	Tested    []string `json:"tested"`
	Note      string   `json:"note"`
}

// smartAuto deliberately takes longer than normal AUTO. It first finds a working
// ceiling using the same light-to-heavy order, then tests declared simplifications.
func (a *app) smartAuto(w http.ResponseWriter, _ *http.Request) {
	if _, err := a.activeProfile(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var best common.Mode
	var bestLatency time.Duration
	found := false
	tested := []string{}
	for _, m := range a.modes {
		if !m.AutoEligible {
			continue
		}
		tested = append(tested, m.ID)
		if err := a.startMode(m.ID); err != nil {
			continue
		}
		lat, err := a.testHealth()
		if err == nil {
			best, bestLatency, found = m, lat, true
			break
		}
		_ = a.stopMode()
	}
	if !found {
		http.Error(w, "no working mode", http.StatusServiceUnavailable)
		return
	}

	visited := map[string]bool{best.ID: true}
	for {
		changed := false
		for _, candidateID := range best.SmartSimplify {
			if visited[candidateID] {
				continue
			}
			visited[candidateID] = true
			candidate, err := a.mode(candidateID)
			if err != nil {
				continue
			}
			tested = append(tested, candidate.ID)
			if ok, _ := a.checkMode(candidate); !ok {
				continue
			}
			lastGood := best
			if err = a.startMode(candidate.ID); err == nil {
				if lat, healthErr := a.testHealth(); healthErr == nil {
					best, bestLatency, changed = candidate, lat, true
					break
				}
			}
			_ = a.stopMode()
			// A failed reduction must never strand SMART AUTO offline.
			if err = a.startMode(lastGood.ID); err != nil {
				http.Error(w, "SMART AUTO lost its last-known-good mode while restoring: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
			if _, err = a.testHealth(); err != nil {
				_ = a.stopMode()
				http.Error(w, "SMART AUTO could not restore its last-known-good mode", http.StatusServiceUnavailable)
				return
			}
			best = lastGood
		}
		if !changed {
			break
		}
	}

	_ = json.NewEncoder(w).Encode(smartResult{
		OK:        true,
		Mode:      best.ID,
		LatencyMS: float64(bestLatency.Microseconds()) / 1000,
		Tested:    tested,
		Note:      "SMART AUTO takes longer because it verifies simplifications after finding connectivity.",
	})
}

type customRequest struct {
	Layers []string `json:"layers"`
}

type customCandidate struct {
	mode   common.Mode
	extras int
}

func hasAllLayers(m common.Mode, requested []string) bool {
	set := make(map[string]bool, len(m.Layers))
	for _, layer := range m.Layers {
		set[strings.ToLower(strings.TrimSpace(layer))] = true
	}
	for _, layer := range requested {
		if !set[strings.ToLower(strings.TrimSpace(layer))] {
			return false
		}
	}
	return true
}

func (a *app) customConnect(w http.ResponseWriter, r *http.Request) {
	var q customRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&q); err != nil {
		http.Error(w, "bad custom stack request", http.StatusBadRequest)
		return
	}
	clean := make([]string, 0, len(q.Layers))
	seen := map[string]bool{}
	for _, raw := range q.Layers {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v != "" && !seen[v] {
			seen[v] = true
			clean = append(clean, v)
		}
	}
	if len(clean) == 0 {
		http.Error(w, "select at least one layer", http.StatusBadRequest)
		return
	}

	candidates := []customCandidate{}
	for _, m := range a.modes {
		if m.ID == "all" || len(m.Layers) == 0 || !hasAllLayers(m, clean) {
			continue
		}
		if ok, _ := a.checkMode(m); !ok {
			continue
		}
		candidates = append(candidates, customCandidate{mode: m, extras: len(m.Layers) - len(clean)})
	}
	if len(candidates) == 0 {
		http.Error(w, "no validated compatible stack contains that layer combination", http.StatusBadRequest)
		return
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].extras != candidates[j].extras {
			return candidates[i].extras < candidates[j].extras
		}
		if candidates[i].mode.TrafficMinPct != candidates[j].mode.TrafficMinPct {
			return candidates[i].mode.TrafficMinPct < candidates[j].mode.TrafficMinPct
		}
		return candidates[i].mode.PingMinMs < candidates[j].mode.PingMinMs
	})

	chosen := candidates[0].mode
	if err := a.startMode(chosen.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lat, err := a.testHealth()
	if err != nil {
		_ = a.stopMode()
		http.Error(w, "custom stack launched but failed connectivity check", http.StatusServiceUnavailable)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":         true,
		"mode":       chosen.ID,
		"layers":     chosen.Layers,
		"requested":  clean,
		"latency_ms": float64(lat.Microseconds()) / 1000,
	})
}

var _ = errors.New
var _ = fmt.Sprintf
