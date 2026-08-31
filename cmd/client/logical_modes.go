package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
)

var logicalLaunchEnvMu sync.Mutex

type logicalMode struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	BaseSelector bool              `json:"base_selector"`
	Fallback     bool              `json:"fallback"`
	Variants     map[string]string `json:"variants"`
}

type logicalVariantStatus struct {
	Base      string      `json:"base"`
	RuntimeID string      `json:"runtime_id"`
	Available bool        `json:"available"`
	Reason    string      `json:"reason,omitempty"`
	Mode      common.Mode `json:"mode"`
}

type logicalModeStatus struct {
	ID              string                          `json:"id"`
	Name            string                          `json:"name"`
	Description     string                          `json:"description"`
	BaseSelector    bool                            `json:"base_selector"`
	Fallback        bool                            `json:"fallback"`
	Available       bool                            `json:"available"`
	Reason          string                          `json:"reason,omitempty"`
	PreferredBase   string                          `json:"preferred_base,omitempty"`
	ReadyBases      []string                        `json:"ready_bases,omitempty"`
	Variants        map[string]logicalVariantStatus `json:"variants"`
	PingMinMs       float64                         `json:"ping_min_ms"`
	PingMaxMs       float64                         `json:"ping_max_ms"`
	TrafficMinPct   float64                         `json:"traffic_min_pct"`
	TrafficMaxPct   float64                         `json:"traffic_max_pct"`
	SpeedLossMinPct float64                         `json:"speed_loss_min_pct"`
	SpeedLossMaxPct float64                         `json:"speed_loss_max_pct"`
	DAITASupported  bool                            `json:"daita_supported"`
	JumboSupported  bool                            `json:"jumbo_supported"`
}

type runtimeCandidate struct {
	RuntimeID string `json:"runtime_mode"`
	Base      string `json:"base"`
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

func (a *app) logicalCatalog() []logicalMode {
	path := filepath.Join(filepath.Dir(a.cfg.ModesFile), "logical-modes.json")
	modes, err := loadLogicalModes(path)
	if err == nil && len(modes) > 0 {
		return modes
	}
	out := make([]logicalMode, 0, len(a.modes))
	for _, raw := range a.modes {
		if raw.ID == "smart-auto" || raw.ID == "custom" {
			continue
		}
		out = append(out, logicalMode{
			ID: raw.ID, Name: raw.Name, Description: raw.Protection,
			Variants: map[string]string{"native": raw.ID},
		})
	}
	return out
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
	for _, mode := range a.logicalCatalog() {
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
	catalog := a.logicalCatalog()
	out := make([]logicalModeStatus, 0, len(catalog))
	for _, logical := range catalog {
		status := logicalModeStatus{
			ID: logical.ID, Name: logical.Name, Description: logical.Description,
			BaseSelector: logical.BaseSelector, Fallback: logical.Fallback,
			PreferredBase:  preferred,
			Variants:       map[string]logicalVariantStatus{},
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
				if raw.PingMinMs < status.PingMinMs {
					status.PingMinMs = raw.PingMinMs
				}
				if raw.PingMaxMs > status.PingMaxMs {
					status.PingMaxMs = raw.PingMaxMs
				}
				if raw.TrafficMinPct < status.TrafficMinPct {
					status.TrafficMinPct = raw.TrafficMinPct
				}
				if raw.TrafficMaxPct > status.TrafficMaxPct {
					status.TrafficMaxPct = raw.TrafficMaxPct
				}
				if raw.SpeedLossMinPct < status.SpeedLossMinPct {
					status.SpeedLossMinPct = raw.SpeedLossMinPct
				}
				if raw.SpeedLossMaxPct > status.SpeedLossMaxPct {
					status.SpeedLossMaxPct = raw.SpeedLossMaxPct
				}
				status.DAITASupported = status.DAITASupported && raw.DAITASupported
				status.JumboSupported = status.JumboSupported && raw.JumboSupported
			}
		}
		sort.Strings(bases)
		status.ReadyBases = bases
		if !status.Available {
			status.Reason = strings.Join(reasons, " • ")
		} else if logical.BaseSelector {
			if v, ok := status.Variants[preferred]; ok && !v.Available && logical.Fallback {
				other := "awg"
				if preferred == "awg" {
					other = "wg"
				}
				if ov, ok := status.Variants[other]; ok && ov.Available {
					status.Reason = strings.ToUpper(preferred) + " unavailable; " + strings.ToUpper(other) + " fallback ready"
				}
			}
		}
		out = append(out, status)
	}
	return out
}

func (a *app) persistBasePreference(base string) error {
	base = normalizeBase(base)
	if base == "auto" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == a.profiles.SelectedID {
			previous := a.profiles.Profiles[i].BaseTunnel
			a.profiles.Profiles[i].BaseTunnel = base
			if err := a.persistProfilesLocked(); err != nil {
				a.profiles.Profiles[i].BaseTunnel = previous
				return err
			}
			return nil
		}
	}
	return errors.New("no selected router profile")
}

func allRuntimeCandidate(runtimeID string) (runtimeCandidate, error) {
	switch strings.TrimSpace(runtimeID) {
	case "max-tls-wg", "max-quic-wg":
		return runtimeCandidate{RuntimeID: strings.TrimSpace(runtimeID), Base: "wg"}, nil
	case "max-tls-awg", "max-quic-awg":
		return runtimeCandidate{RuntimeID: strings.TrimSpace(runtimeID), Base: "awg"}, nil
	default:
		return runtimeCandidate{}, fmt.Errorf("ALL reported unknown runtime branch %q", strings.TrimSpace(runtimeID))
	}
}

func safeProfileIDForRuntimeFile(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "router"
	}
	return b.String()
}

func restoreEnv(key, old string, existed bool) {
	if existed {
		_ = os.Setenv(key, old)
	} else {
		_ = os.Unsetenv(key)
	}
}

func (a *app) startAllLogical(requestedBase string) (runtimeCandidate, error) {
	p, err := a.activeProfile()
	if err != nil {
		return runtimeCandidate{}, err
	}
	stateDir := filepath.Dir(a.cfg.StateFile)
	if stateDir == "" {
		stateDir = "."
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return runtimeCandidate{}, fmt.Errorf("prepare ALL runtime state: %w", err)
	}
	resultFile := filepath.Join(stateDir, ".router-vpn-all-"+safeProfileIDForRuntimeFile(p.ID)+".selected")
	_ = os.Remove(resultFile)

	preferred := a.preferredBase(requestedBase)
	logicalLaunchEnvMu.Lock()
	oldResult, hadResult := os.LookupEnv("HOMEVPN_ALL_RESULT_FILE")
	oldBase, hadBase := os.LookupEnv("HOMEVPN_BASE")
	_ = os.Setenv("HOMEVPN_ALL_RESULT_FILE", resultFile)
	_ = os.Setenv("HOMEVPN_BASE", preferred)
	err = a.startMode("all")
	restoreEnv("HOMEVPN_BASE", oldBase, hadBase)
	restoreEnv("HOMEVPN_ALL_RESULT_FILE", oldResult, hadResult)
	logicalLaunchEnvMu.Unlock()
	if err != nil {
		return runtimeCandidate{}, err
	}

	ctx := a.connectionOperationContextOrBackground()
	seconds := 4*(a.cfg.AutoTestSeconds+3) + 5
	if seconds < 25 {
		seconds = 25
	}
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for {
		if ctx.Err() != nil {
			_ = os.Remove(resultFile)
			_ = a.stopMode()
			return runtimeCandidate{}, errConnectionOperationCancelled
		}
		b, readErr := os.ReadFile(resultFile)
		if readErr == nil {
			_ = os.Remove(resultFile)
			if err := a.checkConnectionOperation(); err != nil {
				_ = a.stopMode()
				return runtimeCandidate{}, err
			}
			actual, parseErr := allRuntimeCandidate(string(b))
			if parseErr != nil {
				_ = a.stopMode()
				return runtimeCandidate{}, parseErr
			}
			return actual, nil
		}
		if !errors.Is(readErr, os.ErrNotExist) {
			_ = a.stopMode()
			return runtimeCandidate{}, fmt.Errorf("read ALL runtime selection: %w", readErr)
		}
		if time.Now().After(deadline) {
			_ = a.stopMode()
			return runtimeCandidate{}, errors.New("ALL did not establish a healthy MAX TLS/QUIC branch before timeout")
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = os.Remove(resultFile)
			_ = a.stopMode()
			return runtimeCandidate{}, errConnectionOperationCancelled
		case <-timer.C:
		}
	}
}

func (a *app) startLogicalMode(id, requestedBase string) (runtimeCandidate, error) {
	logical, ok := a.logicalModeByID(id)
	if !ok {
		if _, err := a.mode(id); err != nil {
			return runtimeCandidate{}, err
		}
		candidate := runtimeCandidate{RuntimeID: id, Base: normalizeBase(requestedBase)}
		if err := a.startMode(candidate.RuntimeID); err != nil {
			return runtimeCandidate{}, err
		}
		if err := a.checkConnectionOperation(); err != nil {
			_ = a.stopMode()
			return runtimeCandidate{}, a.finalizeCancelledFallback("LOGICAL "+id)
		}
		return candidate, nil
	}

	if id == "all" {
		candidate, err := a.startAllLogical(requestedBase)
		if errors.Is(err, errConnectionOperationCancelled) {
			return runtimeCandidate{}, a.finalizeCancelledFallback("ALL")
		}
		return candidate, err
	}

	candidates := a.candidatesForLogical(logical, requestedBase)
	if len(candidates) == 0 {
		return runtimeCandidate{}, fmt.Errorf("logical mode %s has no runnable variant", id)
	}
	var failures []string
	for _, candidate := range candidates {
		if err := a.checkConnectionOperation(); errors.Is(err, errConnectionOperationCancelled) {
			return runtimeCandidate{}, a.finalizeCancelledFallback("LOGICAL "+logical.Name)
		}
		if err := a.startModeAttempt(candidate.RuntimeID, true); err != nil {
			if errors.Is(err, errConnectionOperationCancelled) {
				return runtimeCandidate{}, a.finalizeCancelledFallback("LOGICAL "+logical.Name)
			}
			failures = append(failures, fmt.Sprintf("%s: %v", candidate.Base, err))
			continue
		}
		if err := a.checkConnectionOperation(); err != nil {
			_ = a.stopMode()
			return runtimeCandidate{}, a.finalizeCancelledFallback("LOGICAL "+logical.Name)
		}
		return candidate, nil
	}
	if err := a.releaseTransitionKillSwitch(); err != nil {
		failures = append(failures, err.Error())
	}
	return runtimeCandidate{}, fmt.Errorf("%s unavailable: %s", logical.Name, strings.Join(failures, " • "))
}

func (a *app) listLogicalModes(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(a.logicalStatuses())
}

func (a *app) connectLogical(w http.ResponseWriter, r *http.Request) {
	_, finish, guardErr := a.beginConnectionOperation()
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer finish()

	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q struct {
		Mode string `json:"mode"`
		Base string `json:"base"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	q.Mode = strings.TrimSpace(q.Mode)
	if q.Mode == "" {
		http.Error(w, "mode is required", http.StatusBadRequest)
		return
	}
	preferred := a.preferredBase(q.Base)
	if normalizeBase(q.Base) != "auto" {
		if err := a.persistBasePreference(q.Base); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}
	used, err := a.startLogicalMode(q.Mode, q.Base)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, errConnectionOperationCancelled) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	if err := a.checkConnectionOperation(); err != nil {
		_ = a.stopMode()
		http.Error(w, a.finalizeCancelledFallback("LOGICAL "+q.Mode).Error(), http.StatusConflict)
		return
	}
	fallbackUsed := used.Base != "native" && used.Base != "auto" && used.Base != preferred
	a.mu.Lock()
	a.state.LogicalMode = q.Mode
	a.state.RuntimeMode = used.RuntimeID
	a.state.Base = used.Base
	a.mu.Unlock()
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":            true,
		"logical_mode":  q.Mode,
		"runtime_mode":  used.RuntimeID,
		"base":          used.Base,
		"fallback_used": fallbackUsed,
	})
}
