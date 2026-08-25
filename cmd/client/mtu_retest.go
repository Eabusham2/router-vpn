package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
)

const mtuRetestTimeout = 2 * time.Minute

type mtuRetestSnapshot struct {
	SessionID    string
	SelectedID   string
	ProfileToken string
	StateToken   string
	Profile      common.RouterProfile
	State        state
	Mode         string
}

type mtuWinner struct {
	MTU          int     `json:"mtu"`
	Working      bool    `json:"working"`
	SuccessRatio float64 `json:"success_ratio"`
	Mbps         float64 `json:"mbps"`
	MedianRTTMs  float64 `json:"median_rtt_ms"`
}

type mtuMeasurementResult struct {
	OK                 bool        `json:"ok"`
	Interface          string      `json:"interface"`
	Family             int         `json:"family"`
	OriginalMTU        int         `json:"original_mtu"`
	Winner             mtuWinner   `json:"winner"`
	Results            []mtuWinner `json:"results"`
	PathKey            string      `json:"path_key"`
	NetworkFingerprint string      `json:"network_fingerprint"`
	ProfileFingerprint string      `json:"profile_fingerprint"`
	Adopted            bool        `json:"adopted"`
}

var mtuRetestLocks sync.Map

func mtuRetestLockFor(a *app) *sync.Mutex {
	lock := &sync.Mutex{}
	actual, _ := mtuRetestLocks.LoadOrStore(a, lock)
	return actual.(*sync.Mutex)
}

func registerMTURetestRoute(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/mtu/retest", a.retestMTU)
	registerDNSPolicyRoute(h, a)
	registerHomeSummaryRoute(h, a)
	registerProfileSettingsRoute(h, a)
	registerStrategyRoutes(h, a)
	registerTelemetryRoutes(h, a)
	registerHopTelemetryRoutes(h, a)
	registerForwardingMasterRoute(h, a)
	registerConnectionProfileRoutes(h, a)
	registerConnectionProfileSetupRoutes(h, a)
}

func (a *app) retestMTU(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	lock := mtuRetestLockFor(a)
	if !lock.TryLock() {
		http.Error(w, "an MTU Retest is already running for this client", http.StatusConflict)
		return
	}
	defer lock.Unlock()

	snapshot, err := captureMTURetestSnapshot(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	root := filepath.Clean(getenv("HOMEVPN_ROOT", filepath.Dir(a.cfg.ProfilesFile)))
	if _, err := mtuRetestCommand(a.cfg.ScriptsDir, "measure"); err != nil {
		http.Error(w, err.Error(), http.StatusNotImplemented)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), mtuRetestTimeout)
	defer cancel()
	baseEnv := mtuRetestEnvironment(root, snapshot.Profile, snapshot.State, snapshot.Mode, snapshot)
	out, runErr := runMTURetestAction(ctx, a.cfg.ScriptsDir, "measure", baseEnv)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		http.Error(w, "MTU Retest exceeded its bounded two-minute budget and was stopped", http.StatusGatewayTimeout)
		return
	}
	if runErr != nil {
		http.Error(w, "MTU Retest failed closed: "+boundedMTUDetail(out), http.StatusBadGateway)
		return
	}
	measurement, rawResult, err := decodeMTUMeasurement(out)
	if err != nil {
		http.Error(w, "MTU Retest returned an invalid measurement: "+err.Error(), http.StatusBadGateway)
		return
	}
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	applyEnv := append(append([]string{}, baseEnv...),
		"HOMEVPN_MTU_EXPECTED_PATH_KEY="+measurement.PathKey,
		"HOMEVPN_MTU_APPLY_INTERFACE="+measurement.Interface,
		"HOMEVPN_MTU_APPLY_FAMILY="+strconv.Itoa(measurement.Family),
		"HOMEVPN_MTU_APPLY_VALUE="+strconv.Itoa(measurement.Winner.MTU),
	)
	applyOut, applyErr := runMTURetestAction(ctx, a.cfg.ScriptsDir, "apply", applyEnv)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		http.Error(w, "MTU Retest exceeded its bounded two-minute budget before result adoption", http.StatusGatewayTimeout)
		return
	}
	if applyErr != nil {
		http.Error(w, "MTU Retest measured a winner but refused to adopt it: "+boundedMTUDetail(applyOut), http.StatusConflict)
		return
	}
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		rollbackMTULiveResult(a, root, snapshot, measurement)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	updated, persistErr := persistMTUMeasurement(a, snapshot, measurement)
	if persistErr != nil {
		rollbackMTULiveResult(a, root, snapshot, measurement)
		http.Error(w, "MTU Retest could not persist the fresh measured result: "+persistErr.Error(), http.StatusInternalServerError)
		return
	}
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		rollbackMTULiveResult(a, root, snapshot, measurement)
		if restoreErr := restoreMTUMeasurementFields(a, snapshot); restoreErr != nil {
			http.Error(w, "MTU result became stale and durable rollback was incomplete: "+err.Error()+"; "+restoreErr.Error(), http.StatusInternalServerError)
			return
		}
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "mode": snapshot.Mode,
		"effective_mtu":           updated.EffectiveMTU,
		"effective_mtu_source":    updated.EffectiveMTUSource,
		"effective_mtu_tested_at": updated.EffectiveMTUTestedAt,
		"result":                  rawResult,
		"note":                    "bounded private-node loss/RTT/throughput comparison; measurement is restored first, then adopted only after the same session/profile/path is re-proved; the result is cached by network/path context and does not claim MTU caused any earlier cellular regression",
	})
}

func captureMTURetestSnapshot(a *app) (mtuRetestSnapshot, error) {
	a.mu.Lock()
	selectedID := a.profiles.SelectedID
	p, ok := a.profileByIDLocked(selectedID)
	st := a.state
	a.mu.Unlock()
	if !ok {
		return mtuRetestSnapshot{}, errors.New("add and select your home router first")
	}
	if p.Endpoint == "" {
		return mtuRetestSnapshot{}, errors.New("selected router has no public IP or hostname")
	}
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil {
		return mtuRetestSnapshot{}, errors.New("MTU retest currently requires a connected Router VPN node with private path proof")
	}
	if !st.Connected {
		return mtuRetestSnapshot{}, errors.New("connect the selected Router VPN node first; MTU Retest benchmarks only the proven private tunnel path")
	}
	if st.Mode == "multihop" || st.LogicalMode == "multihop" {
		return mtuRetestSnapshot{}, errors.New("disconnect multihop and retest each single-hop path separately; one MTU result must not be mislabeled as both hops")
	}
	if st.RouterID != "" && st.RouterID != p.ID {
		return mtuRetestSnapshot{}, errors.New("active Router VPN path does not match the selected node; refusing MTU Retest")
	}
	if strings.ToLower(strings.TrimSpace(p.MTUPolicy)) != "auto" {
		return mtuRetestSnapshot{}, errors.New("set this node MTU policy to Auto before Retest")
	}
	if strings.TrimSpace(st.Phase) != "connected" {
		return mtuRetestSnapshot{}, errors.New("current Router VPN session is still transitioning; MTU Retest requires a stable connected path")
	}
	mode := strings.TrimSpace(st.RuntimeMode)
	if mode == "" {
		mode = strings.TrimSpace(st.Mode)
	}
	if mode == "" || mode == "off" {
		return mtuRetestSnapshot{}, errors.New("connected runtime mode is unknown; refusing an unkeyed MTU retest")
	}
	session := sessionTrackerFor(a).snapshot(0)
	if session.ID == "" || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" {
		return mtuRetestSnapshot{}, errors.New("current Router VPN session has not proved the selected private path; refusing MTU Retest")
	}
	if session.RouterID != "" && session.RouterID != p.ID {
		return mtuRetestSnapshot{}, errors.New("current Router VPN session identity does not match the selected node; refusing MTU Retest")
	}
	if session.ActualMode != "" && session.ActualMode != mode {
		return mtuRetestSnapshot{}, errors.New("current Router VPN runtime changed before MTU Retest could start")
	}
	return mtuRetestSnapshot{
		SessionID: session.ID, SelectedID: selectedID,
		ProfileToken: mtuProfileSnapshotToken(p), StateToken: mtuStateSnapshotToken(st),
		Profile: p, State: st, Mode: mode,
	}, nil
}

func validateMTURetestSnapshot(a *app, snapshot mtuRetestSnapshot) error {
	if sessionTrackerFor(a).snapshot(0).ID != snapshot.SessionID {
		return errors.New("VPN session changed while MTU Retest was running; stale result was not adopted")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.profiles.SelectedID != snapshot.SelectedID {
		return errors.New("selected Router VPN node changed while MTU Retest was running; stale result was not adopted")
	}
	current, ok := a.profileByIDLocked(snapshot.SelectedID)
	if !ok || mtuProfileSnapshotToken(current) != snapshot.ProfileToken {
		return errors.New("Router VPN profile identity/path policy changed while MTU Retest was running; stale result was not adopted")
	}
	if strings.ToLower(strings.TrimSpace(current.MTUPolicy)) != "auto" {
		return errors.New("MTU policy changed from Auto while MTU Retest was running; stale result was not adopted")
	}
	if mtuStateSnapshotToken(a.state) != snapshot.StateToken {
		return errors.New("active Router VPN mode/base/path changed while MTU Retest was running; stale result was not adopted")
	}
	return nil
}

func mtuProfileSnapshotToken(p common.RouterProfile) string {
	// Identity/path-policy fields only: measurement-owned EffectiveMTU* fields are
	// deliberately excluded so the controller can verify its own final write.
	v := struct {
		ID, NodeKind, Endpoint, RouterAPI, NodeProofID, PathProbeURL string
		DAITAHost, MTUPolicy, BaseTunnel                             string
		DAITAPort, ManualMTU                                         int
		JumboTUN                                                     bool
	}{p.ID, p.NodeKind, p.Endpoint, p.RouterAPI, p.NodeProofID, p.PathProbeURL, p.DAITAHost, p.MTUPolicy, p.BaseTunnel, p.DAITAPort, p.ManualMTU, p.JumboTUN}
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}

func mtuStateSnapshotToken(st state) string {
	raw := fmt.Sprintf("%t\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", st.Connected, st.Phase, st.Mode, st.LogicalMode, st.RuntimeMode, st.Base, st.RouterID)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

func decodeMTUMeasurement(out []byte) (mtuMeasurementResult, map[string]any, error) {
	trimmed := strings.TrimSpace(string(out))
	start, end := strings.Index(trimmed, "{"), strings.LastIndex(trimmed, "}")
	if start < 0 || end < start {
		return mtuMeasurementResult{}, nil, errors.New("optimizer emitted no JSON result")
	}
	payload := []byte(trimmed[start : end+1])
	var result mtuMeasurementResult
	var raw map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		return mtuMeasurementResult{}, nil, err
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return mtuMeasurementResult{}, nil, err
	}
	if !result.OK || result.Adopted || result.Interface == "" || strings.ContainsAny(result.Interface, "\r\n\x00") {
		return mtuMeasurementResult{}, nil, errors.New("optimizer did not return a safe deferred measurement")
	}
	if result.Family != 4 && result.Family != 6 {
		return mtuMeasurementResult{}, nil, errors.New("optimizer returned an invalid IP family")
	}
	if result.OriginalMTU < 576 || result.OriginalMTU > 9000 || result.Winner.MTU < 1200 || result.Winner.MTU > 9000 || !result.Winner.Working || result.Winner.SuccessRatio < 0.90 {
		return mtuMeasurementResult{}, nil, errors.New("optimizer returned an invalid MTU winner")
	}
	if len(result.PathKey) < 16 || len(result.PathKey) > 128 {
		return mtuMeasurementResult{}, nil, errors.New("optimizer returned an invalid path fingerprint")
	}
	return result, raw, nil
}

func persistMTUMeasurement(a *app, snapshot mtuRetestSnapshot, measurement mtuMeasurementResult) (common.RouterProfile, error) {
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		return common.RouterProfile{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != snapshot.SelectedID {
			continue
		}
		x := &a.profiles.Profiles[i]
		previous := *x
		if mtuProfileSnapshotToken(*x) != snapshot.ProfileToken || strings.ToLower(strings.TrimSpace(x.MTUPolicy)) != "auto" {
			return common.RouterProfile{}, errors.New("Router VPN profile changed before MTU result persistence")
		}
		x.EffectiveMTU = measurement.Winner.MTU
		x.EffectiveMTUSource = "auto-throughput"
		x.EffectiveMTUPathKey = measurement.PathKey
		x.EffectiveMTUNetworkFingerprint = measurement.NetworkFingerprint
		x.EffectiveMTUProfileFingerprint = measurement.ProfileFingerprint
		x.EffectiveMTUTestedAt = time.Now().UTC().Format(time.RFC3339Nano)
		x.EffectiveMTUMbps = measurement.Winner.Mbps
		x.EffectiveMTUMedianRTTMs = measurement.Winner.MedianRTTMs
		x.EffectiveMTUSuccessRatio = measurement.Winner.SuccessRatio
		if err := a.persistProfilesLocked(); err != nil {
			*x = previous
			return common.RouterProfile{}, err
		}
		return *x, nil
	}
	return common.RouterProfile{}, errors.New("selected Router VPN node disappeared before MTU result persistence")
}

func restoreMTUMeasurementFields(a *app, snapshot mtuRetestSnapshot) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != snapshot.SelectedID {
			continue
		}
		x := &a.profiles.Profiles[i]
		if mtuProfileSnapshotToken(*x) != snapshot.ProfileToken {
			return errors.New("profile identity changed; refusing to overwrite newer profile state during MTU rollback")
		}
		x.EffectiveMTU = snapshot.Profile.EffectiveMTU
		x.EffectiveMTUSource = snapshot.Profile.EffectiveMTUSource
		x.EffectiveMTUPathKey = snapshot.Profile.EffectiveMTUPathKey
		x.EffectiveMTUNetworkFingerprint = snapshot.Profile.EffectiveMTUNetworkFingerprint
		x.EffectiveMTUProfileFingerprint = snapshot.Profile.EffectiveMTUProfileFingerprint
		x.EffectiveMTUTestedAt = snapshot.Profile.EffectiveMTUTestedAt
		x.EffectiveMTUMbps = snapshot.Profile.EffectiveMTUMbps
		x.EffectiveMTUMedianRTTMs = snapshot.Profile.EffectiveMTUMedianRTTMs
		x.EffectiveMTUSuccessRatio = snapshot.Profile.EffectiveMTUSuccessRatio
		return a.persistProfilesLocked()
	}
	return nil
}

func rollbackMTULiveResult(a *app, root string, snapshot mtuRetestSnapshot, measurement mtuMeasurementResult) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	env := mtuRetestEnvironment(root, snapshot.Profile, snapshot.State, snapshot.Mode, snapshot)
	env = append(env,
		"HOMEVPN_MTU_APPLY_INTERFACE="+measurement.Interface,
		"HOMEVPN_MTU_APPLY_FAMILY="+strconv.Itoa(measurement.Family),
		"HOMEVPN_MTU_APPLY_VALUE="+strconv.Itoa(measurement.OriginalMTU),
	)
	_, _ = runMTURetestAction(ctx, a.cfg.ScriptsDir, "restore", env)
}

func boundedMTUDetail(out []byte) string {
	detail := strings.TrimSpace(string(out))
	if len(detail) > 4096 {
		detail = detail[len(detail)-4096:]
	}
	if detail == "" {
		return "optimizer exited without a diagnostic"
	}
	return detail
}

func mtuRetestScriptPath(scriptsDir, goos string) (string, string, error) {
	scriptsDir = filepath.Clean(scriptsDir)
	if scriptsDir == "." || scriptsDir == string(filepath.Separator) {
		return "", "", errors.New("invalid MTU scripts directory")
	}
	immutableRoot := filepath.Dir(scriptsDir)
	if goos == "windows" {
		script := filepath.Join(immutableRoot, "client", "Optimize-RouterVPN-MTU.ps1")
		if !safeMTUScriptPath(immutableRoot, script) {
			return "", "", errors.New("unsafe Windows MTU optimizer path")
		}
		return script, "powershell", nil
	}
	name := "mtu-throughput-tuner.py"
	if goos == "darwin" {
		name = "mtu-throughput-tuner-platform.py"
	}
	script := filepath.Join(scriptsDir, name)
	if !safeMTUScriptPath(immutableRoot, script) {
		return "", "", errors.New("unsafe MTU optimizer path")
	}
	return script, "python", nil
}

func mtuRetestCommand(scriptsDir, action string) (*exec.Cmd, error) {
	if action != "optimize" && action != "measure" && action != "apply" && action != "restore" {
		return nil, errors.New("invalid MTU optimizer action")
	}
	script, runner, err := mtuRetestScriptPath(scriptsDir, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Stat(script); statErr != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("MTU optimizer is not installed in the packaged runtime: %s", filepath.Base(script))
	}
	if runner == "powershell" {
		return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Action", action), nil
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		return nil, errors.New("python3 is required for MTU Retest on this desktop runtime")
	}
	return exec.Command(python, script, action), nil
}

func runMTURetestAction(ctx context.Context, scriptsDir, action string, env []string) ([]byte, error) {
	cmd, err := mtuRetestCommand(scriptsDir, action)
	if err != nil {
		return nil, err
	}
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	cmd.Env = append(os.Environ(), env...)
	return cmd.CombinedOutput()
}

func safeMTUScriptPath(root, script string) bool {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return false
	}
	scriptAbs, err := filepath.Abs(filepath.Clean(script))
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, scriptAbs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func mtuRetestEnvironment(root string, p common.RouterProfile, st state, mode string, snapshots ...mtuRetestSnapshot) []string {
	family := ""
	if ip := net.ParseIP(strings.Trim(strings.TrimSpace(p.Endpoint), "[]")); ip != nil {
		if ip.To4() != nil {
			family = "4"
		} else {
			family = "6"
		}
	}
	env := []string{
		"HOMEVPN_ROOT=" + root,
		"HOMEVPN_PROFILE_ID=" + p.ID,
		"HOMEVPN_ENDPOINT=" + p.Endpoint,
		"HOMEVPN_MODE=" + mode,
		"HOMEVPN_LOGICAL_MODE=" + st.LogicalMode,
		"HOMEVPN_BASE=" + st.Base,
		"HOMEVPN_IP_FAMILY=" + family,
	}
	if len(snapshots) > 0 {
		s := snapshots[0]
		env = append(env,
			"HOMEVPN_MTU_OPERATION_SESSION_ID="+s.SessionID,
			"HOMEVPN_MTU_OPERATION_PROFILE_TOKEN="+s.ProfileToken,
			"HOMEVPN_MTU_OPERATION_STATE_TOKEN="+s.StateToken,
		)
	}
	return env
}
