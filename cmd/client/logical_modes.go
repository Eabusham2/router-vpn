package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"router-vpn/internal/common"
)

type logicalMode struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	BaseSelector bool              `json:"base_selector"`
	Fallback     bool              `json:"fallback"`
	Variants     map[string]string `json:"variants"`
}

type logicalVariantStatus struct {
	Base       string      `json:"base"`
	RuntimeID  string      `json:"runtime_id"`
	Available  bool        `json:"available"`
	Reason     string      `json:"reason,omitempty"`
	Mode       common.Mode `json:"mode"`
}

type logicalModeStatus struct {
	ID           string                          `json:"id"`
	Name         string                          `json:"name"`
	Description  string                          `json:"description"`
	BaseSelector bool                            `json:"base_selector"`
	Fallback     bool                            `json:"fallback"`
	Available    bool                            `json:"available"`
	Reason       string                          `json:"reason,omitempty"`
	PreferredBase string                         `json:"preferred_base,omitempty"`
	ReadyBases   []string                        `json:"ready_bases,omitempty"`
	Variants     map[string]logicalVariantStatus `json:"variants"`
	PingMinMs       float64                      `json:"ping_min_ms"`
	PingMaxMs       float64                      `json:"ping_max_ms"`
	TrafficMinPct   float64                      `json:"traffic_min_pct"`
	TrafficMaxPct   float64                      `json:"traffic_max_pct"`
	SpeedLossMinPct float64                      `json:"speed_loss_min_pct"`
	SpeedLossMaxPct float64                      `json:"speed_loss_max_pct"`
	DAITASupported  bool                         `json:"daita_supported"`
	JumboSupported  bool                         `json:"jumbo_supported"`
}

type runtimeCandidate struct {
	RuntimeID string
	Base      string
}

func loadLogicalModes(path string) ([]logicalMode, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var modes []logicalMode
	if err := json.Unmarshal(b, &modes); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, mode := range modes {
		if strings.TrimSpace(mode.ID) == "" || strings.TrimSpace(mode.Name) == "" {
			return nil, errors.New("logical mode id/name cannot be blank")
		}
		if seen[mode.ID] {
			return nil, fmt.Errorf("duplicate logical mode %q", mode.ID)
		}
		seen[mode.ID] = true
		if len(mode.Variants) == 0 {
			return nil, fmt.Errorf("logical mode %q has no variants", mode.ID)
		}
	}
	return modes, nil
}

func normalizeBase(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "awg", "amnezia", "amneziawg", "amneziawg2":
		return "awg"
	case "wg", "wireguard":
		return "wg"
	default:
		return "auto"
	}
}

func (a *app) logicalModeByID(id string) (logicalMode, bool) {
	for _, mode := range a.logicalModes {
		if mode.ID == id {
			return mode, true
		}
	}
	return logicalMode{}, false
}

func (a *app) preferredBase(requested string) string {
	base := normalizeBase(requested)
	if base != "auto" {
		return base
	}
	p, err := a.activeProfile()
	if err == nil {
		if saved := normalizeBase(p.BaseTunnel); saved != "auto" {
			return saved
		}
	}
	return "wg"
}

func (a *app) candidatesForLogical(mode logicalMode, requestedBase string) []runtimeCandidate {
	if runtime, ok := mode.Variants["native"]; ok && runtime != "" {
		return []runtimeCandidate{{RuntimeID: runtime, Base: "native"}}
	}
	preferred := a.preferredBase(requestedBase)
	order := []string{preferred}
	other := "awg"
	if preferred == "awg" {
		other = "wg"
	}
	if mode.Fallback {
		order = append(order, other)
	}
	out := make([]runtimeCandidate, 0, len(order))
	seen := map[string]bool{}
	for _, base := range order {
		runtime := mode.Variants[base]
		if runtime == "" {
			continue
		}
		key := runtime + "\x00" + base
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, runtimeCandidate{RuntimeID: runtime, Base: base})
	}
	return out
}

func (a *app) logicalStatuses() []logicalModeStatus {
	preferred := a.preferredBase("auto")
	out := make([]logicalModeStatus, 0, len(a.logicalModes))
	for _, logical := range a.logicalModes {
		status := logicalModeStatus{
			ID: logical.ID, Name: logical.Name, Description: logical.Description,
			BaseSelector: logical.BaseSelector, Fallback: logical.Fallback,
			PreferredBase: preferred,
			Variants: map[string]logicalVariantStatus{},
			DAITASupported: true, JumboSupported: true,
		}
		firstMetric := true
		reasons := make([]string, 0, len(logical.Variants))
		bases := make([]string, 0, len(logical.Variants))
		for base, runtimeID := range logical.Variants {
			raw, err := a.mode(runtimeID)
			if err != nil {
				status.Variants[base] = logicalVariantStatus{Base: base, RuntimeID: runtimeID, Reason: "runtime mode missing from catalog"}
				reasons = append(reasons, strings.ToUpper(base)+": runtime mode missing")
				continue
			}
			ok, reason := a.checkMode(raw)
			status.Variants[base] = logicalVariantStatus{Base: base, RuntimeID: runtimeID, Available: ok, Reason: reason, Mode: raw}
			if ok {
				status.Available = true
				bases = append(bases, base)
			} else {
				reasons = append(reasons, strings.ToUpper(base)+": "+reason)
			}
			if firstMetric {
				status.PingMinMs, status.PingMaxMs = raw.PingMinMs, raw.PingMaxMs
				status.TrafficMinPct, status.TrafficMaxPct = raw.TrafficMinPct, raw.TrafficMaxPct
				status.SpeedLossMinPct, status.SpeedLossMaxPct = raw.SpeedLossMinPct, raw.SpeedLossMaxPct
				status.DAITASupported, status.JumboSupported = raw.DAITASupported, raw.JumboSupported
				firstMetric = false
			} else {
				if raw.PingMinMs < status.PingMinMs { status.PingMinMs = raw.PingMinMs }
				if raw.PingMaxMs > status.PingMaxMs { status.PingMaxMs = raw.PingMaxMs }
				if raw.TrafficMinPct < status.TrafficMinPct { status.TrafficMinPct = raw.TrafficMinPct }
				if raw.TrafficMaxPct > status.TrafficMaxPct { status.TrafficMaxPct = raw.TrafficMaxPct }
				if raw.SpeedLossMinPct < status.SpeedLossMinPct { status.SpeedLossMinPct = raw.SpeedLossMinPct }
				if raw.SpeedLossMaxPct > status.SpeedLossMaxPct { status.SpeedLossMaxPct = raw.SpeedLossMaxPct }
				status.DAITASupported = status.DAITASupported && raw.DAITASupported
				status.JumboSupported = status.JumboSupported && raw.JumboSupported
			}
		}
		sort.Strings(bases)
		status.ReadyBases = bases
		if !status.Available {
			status.Reason = strings.Join(reasons, " • ")
		} else if logical.BaseSelector {
			want := logical.Variants[preferred]
			if v, ok := status.Variants[preferred]; want != "" && ok && !v.Available && logical.Fallback {
				other := "awg"
				if preferred == "awg" { other = "wg" }
				if ov, ok := status.Variants[other]; ok && ov.Available {
					status.Reason = strings.ToUpper(preferred)+" unavailable; "+strings.ToUpper(other)+" fallback ready"
				}
			}
		}
		out = append(out, status)
	}
	return out
}

func (a *app) startLogicalMode(id, requestedBase string) (runtimeCandidate, error) {
	logical, ok := a.logicalModeByID(id)
	if !ok {
		// Backward compatibility for existing callers/configs that still send a raw
		// 20-mode ID. New UI surfaces use logical IDs.
		if _, err := a.mode(id); err != nil {
			return runtimeCandidate{}, err
		}
		candidate := runtimeCandidate{RuntimeID: id, Base: normalizeBase(requestedBase)}
		if err := a.startModeWithBase(candidate.RuntimeID, candidate.Base, id); err != nil {
			return runtimeCandidate{}, err
		}
		return candidate, nil
	}

	candidates := a.candidatesForLogical(logical, requestedBase)
	if len(candidates) == 0 {
		return runtimeCandidate{}, fmt.Errorf("logical mode %s has no runnable variant", id)
	}
	var failures []string
	for _, candidate := range candidates {
		if err := a.startModeWithBase(candidate.RuntimeID, candidate.Base, logical.ID); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", candidate.Base, err))
			continue
		}
		return candidate, nil
	}
	return runtimeCandidate{}, fmt.Errorf("%s unavailable: %s", logical.Name, strings.Join(failures, " • "))
}
