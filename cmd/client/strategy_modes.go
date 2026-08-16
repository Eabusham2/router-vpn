package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
)

type strategyAttempt struct {
	Mode    string `json:"mode"`
	Action  string `json:"action,omitempty"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type strategyResult struct {
	OK           bool              `json:"ok"`
	Strategy     string            `json:"strategy"`
	RuntimeMode  string            `json:"runtime_mode,omitempty"`
	LogicalMode  string            `json:"logical_mode,omitempty"`
	Requested    []string          `json:"requested_layers,omitempty"`
	Attempts     []strategyAttempt `json:"attempts"`
	RestoredMode string            `json:"restored_mode,omitempty"`
}

type startupSelection struct {
	RouterID    string    `json:"router_id"`
	RuntimeMode string    `json:"runtime_mode"`
	LogicalMode string    `json:"logical_mode,omitempty"`
	Base        string    `json:"base,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var strategyLocks sync.Map

func strategyLockFor(a *app) *sync.Mutex {
	lock, _ := strategyLocks.LoadOrStore(a, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func registerStrategyRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/strategy/auto", a.strategyAuto)
	h.HandleFunc("/api/strategy/smart-auto", a.strategySmartAuto)
	h.HandleFunc("/api/strategy/custom", a.strategyCustom)
	go a.recordLastSuccessfulRuntime()
	go func() {
		time.Sleep(1200 * time.Millisecond)
		a.applyStartupPolicy()
	}()
}

func (t *sessionTracker) strategyEvent(kind, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == nil || t.session.EndedAt != nil {
		return
	}
	t.eventLocked(kind, t.session.Phase, message, t.session.Connected, t.session.ActualMode, t.session.ActualBase)
}

func (a *app) strategyAuto(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	result, err := a.runAutoStrategy("auto")
	writeStrategyResult(w, result, err)
}

func (a *app) strategySmartAuto(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	result, err := a.runSmartStrategy()
	writeStrategyResult(w, result, err)
}

func (a *app) strategyCustom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Layers []string `json:"layers"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	result, err := a.runCustomStrategy(request.Layers)
	writeStrategyResult(w, result, err)
}

func writeStrategyResult(w http.ResponseWriter, result strategyResult, err error) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error(), "strategy": result.Strategy, "requested_layers": result.Requested, "attempts": result.Attempts, "restored_mode": result.RestoredMode})
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (a *app) strategyProfile() (common.RouterProfile, error) {
	p, err := a.activeProfile()
	if err != nil {
		return common.RouterProfile{}, err
	}
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil {
		return common.RouterProfile{}, errors.New("AUTO/SMART/CUSTOM Router VPN mode strategies require a Router VPN node; use the external direct/hop controls for external nodes")
	}
	return p, nil
}

func (a *app) declareStrategy(strategy string, p common.RouterProfile) {
	sessionTrackerFor(a).declareRequest(strategy, p.BaseTunnel)
	sessionTrackerFor(a).strategyEvent("strategy-start", strings.ToUpper(strategy)+" requested")
}

func (a *app) setStrategyWinner(strategy string, mode common.Mode) {
	a.mu.Lock()
	a.state.Mode = mode.ID
	a.state.LogicalMode = strategy
	a.state.RuntimeMode = mode.ID
	a.state.Phase = "connected"
	a.state.LastError = ""
	a.mu.Unlock()
	sessionTrackerFor(a).strategyEvent("strategy-winner", fmt.Sprintf("%s selected proven runtime %s", strings.ToUpper(strategy), mode.ID))
}

func (a *app) failStrategy(strategy string, failures []string) error {
	if err := a.releaseTransitionKillSwitch(); err != nil {
		failures = append(failures, "kill-switch transition release: "+err.Error())
	}
	message := strings.Join(failures, " • ")
	if message == "" {
		message = strategy + " found no working candidate"
	}
	a.mu.Lock()
	a.state.Connected = false
	a.state.Phase = "failed"
	a.state.LastError = message
	a.mu.Unlock()
	sessionTrackerFor(a).strategyEvent("strategy-failed", message)
	sessionTrackerFor(a).markRequestFailure(message)
	return errors.New(message)
}

func (a *app) firstWorkingAuto(strategy string, result *strategyResult) (common.Mode, error) {
	var failures []string
	for _, mode := range a.modes {
		if !mode.AutoEligible {
			continue
		}
		sessionTrackerFor(a).strategyEvent("strategy-attempt", fmt.Sprintf("%s trying %s", strings.ToUpper(strategy), mode.ID))
		a.mu.Lock()
		a.state.Phase = strategy + ":trying:" + mode.ID
		a.mu.Unlock()
		err := a.startModeAttempt(mode.ID, true)
		attempt := strategyAttempt{Mode: mode.ID, Action: "candidate", Success: err == nil}
		if err != nil {
			attempt.Error = err.Error()
			failures = append(failures, mode.ID+": "+err.Error())
			result.Attempts = append(result.Attempts, attempt)
			continue
		}
		result.Attempts = append(result.Attempts, attempt)
		return mode, nil
	}
	return common.Mode{}, a.failStrategy(strategy, failures)
}

func (a *app) runAutoStrategy(strategy string) (strategyResult, error) {
	result := strategyResult{Strategy: strategy, LogicalMode: strategy, Attempts: []strategyAttempt{}}
	lock := strategyLockFor(a)
	lock.Lock()
	defer lock.Unlock()
	p, err := a.strategyProfile()
	if err != nil {
		return result, err
	}
	a.declareStrategy(strategy, p)
	winner, err := a.firstWorkingAuto(strategy, &result)
	if err != nil {
		return result, err
	}
	a.setStrategyWinner(strategy, winner)
	result.OK = true
	result.RuntimeMode = winner.ID
	return result, nil
}

func (a *app) runSmartStrategy() (strategyResult, error) {
	const strategy = "smart-auto"
	result := strategyResult{Strategy: strategy, LogicalMode: strategy, Attempts: []strategyAttempt{}}
	lock := strategyLockFor(a)
	lock.Lock()
	defer lock.Unlock()
	p, err := a.strategyProfile()
	if err != nil {
		return result, err
	}
	a.declareStrategy(strategy, p)
	best, err := a.firstWorkingAuto(strategy, &result)
	if err != nil {
		return result, err
	}
	visited := map[string]bool{best.ID: true}
	for {
		changed := false
		for _, candidateID := range best.SmartSimplify {
			candidateID = strings.TrimSpace(candidateID)
			if candidateID == "" || visited[candidateID] {
				continue
			}
			visited[candidateID] = true
			candidate, modeErr := a.mode(candidateID)
			if modeErr != nil {
				result.Attempts = append(result.Attempts, strategyAttempt{Mode: candidateID, Action: "simplify", Success: false, Error: "unknown simplification runtime"})
				continue
			}
			if ok, reason := a.checkMode(candidate); !ok {
				result.Attempts = append(result.Attempts, strategyAttempt{Mode: candidateID, Action: "simplify", Success: false, Error: reason})
				continue
			}
			lastGood := best
			sessionTrackerFor(a).strategyEvent("strategy-simplify", fmt.Sprintf("SMART trying %s -> %s", lastGood.ID, candidate.ID))
			a.mu.Lock()
			a.state.Phase = "smart:simplify:" + candidate.ID
			a.mu.Unlock()
			tryErr := a.startModeAttempt(candidate.ID, true)
			attempt := strategyAttempt{Mode: candidate.ID, Action: "simplify", Success: tryErr == nil}
			if tryErr == nil {
				result.Attempts = append(result.Attempts, attempt)
				sessionTrackerFor(a).strategyEvent("strategy-simplified", fmt.Sprintf("SMART validated %s -> %s", lastGood.ID, candidate.ID))
				best = candidate
				changed = true
				break
			}
			attempt.Error = tryErr.Error()
			result.Attempts = append(result.Attempts, attempt)
			sessionTrackerFor(a).strategyEvent("strategy-restore", fmt.Sprintf("SMART simplification %s failed; restoring %s", candidate.ID, lastGood.ID))
			restoreErr := a.startModeAttempt(lastGood.ID, true)
			if restoreErr != nil {
				message := fmt.Sprintf("SMART could not restore last-known-good runtime %s after %s failed: %v", lastGood.ID, candidate.ID, restoreErr)
				result.Attempts = append(result.Attempts, strategyAttempt{Mode: lastGood.ID, Action: "restore", Success: false, Error: restoreErr.Error()})
				return result, a.failStrategy(strategy, []string{message})
			}
			result.Attempts = append(result.Attempts, strategyAttempt{Mode: lastGood.ID, Action: "restore", Success: true})
			result.RestoredMode = lastGood.ID
			best = lastGood
		}
		if !changed {
			break
		}
	}
	a.setStrategyWinner(strategy, best)
	result.OK = true
	result.RuntimeMode = best.ID
	return result, nil
}

type rankedCustomMode struct {
	Mode        common.Mode
	ExtraLayers int
	BasePenalty int
}

func normalizeRequestedLayers(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func hasEveryLayer(mode common.Mode, requested []string) bool {
	if len(mode.Layers) == 0 {
		return false
	}
	set := map[string]bool{}
	for _, layer := range mode.Layers {
		set[strings.ToLower(strings.TrimSpace(layer))] = true
	}
	for _, layer := range requested {
		if !set[layer] {
			return false
		}
	}
	return true
}

func customBasePenalty(mode common.Mode, preferred string) int {
	hasWG, hasAWG := false, false
	for _, layer := range mode.Layers {
		switch strings.ToLower(strings.TrimSpace(layer)) {
		case "wireguard":
			hasWG = true
		case "amneziawg2", "amneziawg":
			hasAWG = true
		}
	}
	wantAWG := strings.HasPrefix(strings.ToLower(strings.TrimSpace(preferred)), "awg") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(preferred)), "amnezia")
	if wantAWG {
		if hasAWG { return 0 }
		if hasWG { return 1 }
		return 0
	}
	if hasWG { return 0 }
	if hasAWG { return 1 }
	return 0
}

func (a *app) rankCustomModes(requested []string, preferred string) []rankedCustomMode {
	candidates := []rankedCustomMode{}
	for _, mode := range a.modes {
		if mode.ID == "smart-auto" || mode.ID == "custom" || mode.ID == "all" {
			continue
		}
		if !hasEveryLayer(mode, requested) {
			continue
		}
		if ok, _ := a.checkMode(mode); !ok {
			continue
		}
		candidates = append(candidates, rankedCustomMode{Mode: mode, ExtraLayers: len(mode.Layers) - len(requested), BasePenalty: customBasePenalty(mode, preferred)})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.ExtraLayers != b.ExtraLayers { return a.ExtraLayers < b.ExtraLayers }
		if a.BasePenalty != b.BasePenalty { return a.BasePenalty < b.BasePenalty }
		if a.Mode.TrafficMinPct != b.Mode.TrafficMinPct { return a.Mode.TrafficMinPct < b.Mode.TrafficMinPct }
		if a.Mode.PingMinMs != b.Mode.PingMinMs { return a.Mode.PingMinMs < b.Mode.PingMinMs }
		return a.Mode.ID < b.Mode.ID
	})
	return candidates
}

func (a *app) runCustomStrategy(requested []string) (strategyResult, error) {
	const strategy = "custom"
	result := strategyResult{Strategy: strategy, LogicalMode: strategy, Attempts: []strategyAttempt{}}
	lock := strategyLockFor(a)
	lock.Lock()
	defer lock.Unlock()
	p, err := a.strategyProfile()
	if err != nil {
		return result, err
	}
	requested = normalizeRequestedLayers(requested)
	if len(requested) == 0 {
		requested = normalizeRequestedLayers(p.CustomLayers)
	}
	result.Requested = requested
	if len(requested) == 0 {
		return result, errors.New("CUSTOM requires at least one requested layer")
	}
	a.declareStrategy(strategy, p)
	candidates := a.rankCustomModes(requested, p.BaseTunnel)
	if len(candidates) == 0 {
		message := "CUSTOM found no validated compatible stack containing every requested layer: " + strings.Join(requested, ", ")
		return result, a.failStrategy(strategy, []string{message})
	}
	failures := []string{}
	for _, ranked := range candidates {
		mode := ranked.Mode
		sessionTrackerFor(a).strategyEvent("strategy-attempt", fmt.Sprintf("CUSTOM trying %s for layers %s", mode.ID, strings.Join(requested, ", ")))
		a.mu.Lock()
		a.state.Phase = "custom:trying:" + mode.ID
		a.mu.Unlock()
		tryErr := a.startModeAttempt(mode.ID, true)
		attempt := strategyAttempt{Mode: mode.ID, Action: "compatible-stack", Success: tryErr == nil}
		if tryErr != nil {
			attempt.Error = tryErr.Error()
			failures = append(failures, mode.ID+": "+tryErr.Error())
			result.Attempts = append(result.Attempts, attempt)
			continue
		}
		result.Attempts = append(result.Attempts, attempt)
		a.setStrategyWinner(strategy, mode)
		result.OK = true
		result.RuntimeMode = mode.ID
		return result, nil
	}
	return result, a.failStrategy(strategy, append([]string{"CUSTOM matching stacks existed but none passed selected-node path proof"}, failures...))
}

func (a *app) startupStatePath() string {
	path := strings.TrimSpace(a.cfg.StateFile)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func (a *app) saveStartupSelection(selection startupSelection) error {
	path := a.startupStatePath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return err
	}
	body, err := json.MarshalIndent(selection, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *app) loadStartupSelection() (startupSelection, error) {
	path := a.startupStatePath()
	if path == "" {
		return startupSelection{}, errors.New("startup state path is not configured")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return startupSelection{}, err
	}
	var selection startupSelection
	if err = json.Unmarshal(body, &selection); err != nil {
		return startupSelection{}, err
	}
	return selection, nil
}

func (a *app) recordLastSuccessfulRuntime() {
	ticker := time.NewTicker(750 * time.Millisecond)
	defer ticker.Stop()
	lastKey := ""
	for range ticker.C {
		a.mu.Lock()
		st := a.state
		a.mu.Unlock()
		if !st.Connected || strings.TrimSpace(st.RuntimeMode) == "" || strings.TrimSpace(st.RouterID) == "" {
			continue
		}
		if _, err := a.mode(st.RuntimeMode); err != nil {
			continue
		}
		key := st.RouterID + "\x00" + st.RuntimeMode + "\x00" + st.LogicalMode + "\x00" + st.Base
		if key == lastKey {
			continue
		}
		selection := startupSelection{RouterID: st.RouterID, RuntimeMode: st.RuntimeMode, LogicalMode: st.LogicalMode, Base: st.Base, UpdatedAt: time.Now().UTC()}
		if err := a.saveStartupSelection(selection); err != nil {
			log.Printf("Router VPN could not persist last successful runtime: %v", err)
			continue
		}
		lastKey = key
	}
}

func (a *app) applyStartupPolicy() {
	a.mu.Lock()
	selectedID := a.profiles.SelectedID
	profile, ok := a.profileByIDLocked(selectedID)
	a.mu.Unlock()
	if !ok || !profile.AutoConnect || strings.EqualFold(strings.TrimSpace(profile.NodeKind), "external") || profile.External != nil {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(profile.StartupMode))
	if mode == "" || mode == "manual" {
		log.Printf("Router VPN auto-connect is enabled but startup mode is Manual; leaving the app disconnected")
		return
	}
	var err error
	switch mode {
	case "auto":
		_, err = a.runAutoStrategy("auto")
	case "smart-auto":
		_, err = a.runSmartStrategy()
	case "last":
		selection, loadErr := a.loadStartupSelection()
		if loadErr == nil && selection.RouterID == profile.ID && selection.RuntimeMode != "" {
			sessionTrackerFor(a).declareRequest("last", selection.Base)
			sessionTrackerFor(a).strategyEvent("startup-last", "restoring last proven runtime "+selection.RuntimeMode)
			if startErr := a.startModeAttempt(selection.RuntimeMode, false); startErr == nil {
				a.mu.Lock()
				a.state.LogicalMode = selection.LogicalMode
				a.state.RuntimeMode = selection.RuntimeMode
				a.state.Base = selection.Base
				a.mu.Unlock()
				return
			}
		}
		log.Printf("Router VPN last-mode auto-connect had no restorable proven runtime; falling back to AUTO")
		_, err = a.runAutoStrategy("auto")
	default:
		err = fmt.Errorf("unsupported startup mode %q", mode)
	}
	if err != nil {
		log.Printf("Router VPN startup auto-connect failed closed: %v", err)
	}
}
