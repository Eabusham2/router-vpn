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
	Multihop     *mtuMultihopSnapshot
	persistence  *mtuMeasurementPersistence
}

type mtuLiveSnapshot struct {
	Interface   string
	Family      int
	OriginalMTU int
	Owner       *mtuLiveOwner
}

type mtuWinner struct {
	MTU          int     `json:"mtu"`
	Working      bool    `json:"working"`
	SuccessRatio float64 `json:"success_ratio"`
	Mbps         float64 `json:"mbps"`
	MedianRTTMs  float64 `json:"median_rtt_ms"`
}

type mtuMeasurementResult struct {
	OwnerToken         string      `json:"owner_token"`
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
	h.HandleFunc("/api/mtu/status", a.desktopMTUStatus)
	h.HandleFunc("/api/mtu/cancel", a.cancelDesktopMTURoute)
	registerDNSPolicyRoute(h, a)
	registerHomeSummaryRoute(h, a)
	registerProfileSettingsRoute(h, a)
	registerStrategyRoutes(h, a)
	registerTelemetryRoutes(h, a)
	registerHopTelemetryRoutes(h, a)
	registerSpeedLabRoutes(h, a)
	registerForwardingMasterRoute(h, a)
	registerConnectionProfileRoutes(h, a)
	registerConnectionProfileSetupRoutes(h, a)
}

func (a *app) retestMTU(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	request, err := readMTUViewRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	lock := mtuRetestLockFor(a)
	if !lock.TryLock() {
		if mtuSuspended(a) {
			retryHeldAutomaticMTU(r.Context())
		}
		http.Error(w, "an MTU Retest is already running for this client", http.StatusConflict)
		return
	}
	defer lock.Unlock()
	if mtuSuspended(a) {
		retryHeldAutomaticMTU(r.Context())
		http.Error(w, "MTU is held by a captured measurement or connection transition", http.StatusConflict)
		return
	}
	if launch := desktopExternalMTULaunch(a); launch != nil {
		identity, err := desktopMeasurementViewIdentity(launch)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		ctx, operation, err := beginMTUViewOperation(a, r.Context(), request, identity)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writer := &mtuViewResponse{ResponseWriter: w, operation: operation}
		defer writer.finish()
		w, r = writer, r.WithContext(ctx)
		a.retestDesktopExternalMTU(w, r, launch)
		return
	}

	snapshot, err := captureMTURetestSnapshot(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	viewContext, operation, err := beginMTUViewOperation(a, r.Context(), request, mtuViewIdentity{Session: snapshot.SessionID, Profile: snapshot.Profile.ID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writer := &mtuViewResponse{ResponseWriter: w, operation: operation}
	defer writer.finish()
	w, r = writer, r.WithContext(viewContext)
	root := filepath.Clean(getenv("HOMEVPN_ROOT", filepath.Dir(a.cfg.ProfilesFile)))
	if _, err := mtuRetestCommand(a.cfg.ScriptsDir, "measure"); err != nil {
		http.Error(w, err.Error(), http.StatusNotImplemented)
		return
	}
	baseEnv := mtuRetestEnvironment(root, snapshot.Profile, snapshot.State, snapshot.Mode, snapshot)
	liveSnapshot, err := captureMTULiveSnapshot(snapshot.Profile)
	if err != nil {
		http.Error(w, "MTU Retest could not snapshot the live tunnel MTU before measurement: "+err.Error(), http.StatusConflict)
		return
	}
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	liveSnapshot.Owner, err = captureMTULiveOwner(a, snapshot, liveSnapshot)
	if liveSnapshot.Owner != nil {
		defer finishMTULiveOwner(w, liveSnapshot.Owner)
	}
	if err != nil {
		http.Error(w, "MTU Retest could not capture its kernel interface owner: "+err.Error(), http.StatusConflict)
		return
	}
	baseEnv = append(baseEnv, liveSnapshot.Owner.Environment()...)

	ctx, cancel := context.WithTimeout(r.Context(), mtuRetestTimeout)
	defer cancel()
	updateMTUViewPhase(ctx, "measuring", liveSnapshot.OriginalMTU)
	out, runErr := runMTURetestAction(ctx, a.cfg.ScriptsDir, "measure", baseEnv)
	if ctx.Err() != nil {
		status := http.StatusRequestTimeout
		message := "MTU Retest was canceled before measurement completed"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
			message = "MTU Retest exceeded its bounded two-minute budget and was stopped"
		}
		failMTURetestWithLiveRollback(w, status, message, liveSnapshot)
		return
	}
	if runErr != nil {
		failMTURetestWithLiveRollback(w, http.StatusBadGateway, "MTU Retest failed closed: "+boundedMTUDetail(out), liveSnapshot)
		return
	}
	updateMTUViewPhase(ctx, "validating", 0)
	measurement, rawResult, err := decodeMTUMeasurement(out)
	if err != nil {
		failMTURetestWithLiveRollback(w, http.StatusBadGateway, "MTU Retest returned an invalid measurement: "+err.Error(), liveSnapshot)
		return
	}
	if err := validateMTUMeasurementAgainstLiveSnapshot(measurement, liveSnapshot); err != nil {
		failMTURetestWithLiveRollback(w, http.StatusConflict, err.Error(), liveSnapshot)
		return
	}
	if err := liveSnapshot.Owner.ValidateMTU(liveSnapshot.OriginalMTU); err != nil {
		failMTURetestWithLiveRollback(w, http.StatusConflict, err.Error(), liveSnapshot)
		return
	}
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		failMTURetestWithLiveRollback(w, http.StatusConflict, err.Error(), liveSnapshot)
		return
	}

	applyEnv := append(append([]string{}, baseEnv...),
		"HOMEVPN_MTU_EXPECTED_PATH_KEY="+measurement.PathKey,
		"HOMEVPN_MTU_APPLY_INTERFACE="+measurement.Interface,
		"HOMEVPN_MTU_APPLY_FAMILY="+strconv.Itoa(measurement.Family),
		"HOMEVPN_MTU_APPLY_VALUE="+strconv.Itoa(measurement.Winner.MTU),
	)
	updateMTUViewPhase(ctx, "applying", 0)
	applyOut, applyErr := runMTURetestAction(ctx, a.cfg.ScriptsDir, "apply", applyEnv)
	if ctx.Err() != nil {
		status := http.StatusRequestTimeout
		message := "MTU Retest was canceled before result adoption completed"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
			message = "MTU Retest exceeded its bounded two-minute budget before result adoption"
		}
		failMTURetestWithLiveRollback(w, status, message, liveSnapshot)
		return
	}
	if applyErr != nil {
		failMTURetestWithLiveRollback(w, http.StatusConflict, "MTU Retest measured a winner but refused to adopt it: "+boundedMTUDetail(applyOut), liveSnapshot)
		return
	}
	if err := liveSnapshot.Owner.ValidateMTU(measurement.Winner.MTU); err != nil {
		failMTURetestWithLiveRollback(w, http.StatusConflict, err.Error(), liveSnapshot)
		return
	}
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		failMTURetestWithLiveRollback(w, http.StatusConflict, err.Error(), liveSnapshot)
		return
	}
	updateMTUViewPhase(ctx, "saving", 0)
	updated, persistErr := persistMTUMeasurement(a, snapshot, measurement)
	if persistErr != nil {
		failMTURetestWithLiveRollback(w, http.StatusInternalServerError, "MTU Retest could not persist the fresh measured result: "+persistErr.Error(), liveSnapshot)
		return
	}
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		liveRollbackErr := restoreMTULiveSnapshot(liveSnapshot)
		recordMTUViewRollback(w, liveSnapshot, liveRollbackErr)
		durableRollbackErr := restoreMTUMeasurementFields(a, snapshot)
		if liveRollbackErr != nil || durableRollbackErr != nil {
			detail := err.Error()
			if liveRollbackErr != nil {
				detail += "; live MTU rollback failed: " + liveRollbackErr.Error()
			}
			if durableRollbackErr != nil {
				detail += "; durable MTU rollback failed: " + durableRollbackErr.Error()
			}
			http.Error(w, "MTU result became stale and rollback was incomplete: "+detail, http.StatusInternalServerError)
			return
		}
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	if ctx.Err() != nil || liveSnapshot.Owner.ValidateMTU(measurement.Winner.MTU) != nil || liveSnapshot.Owner.Commit() != nil {
		liveRollbackErr := restoreMTULiveSnapshot(liveSnapshot)
		recordMTUViewRollback(w, liveSnapshot, liveRollbackErr)
		durableRollbackErr := restoreMTUMeasurementFields(a, snapshot)
		if liveRollbackErr != nil || durableRollbackErr != nil {
			http.Error(w, "MTU result could not commit and its rollback was incomplete", http.StatusInternalServerError)
		} else {
			http.Error(w, "MTU operation was canceled or its captured interface retired before commit", http.StatusConflict)
		}
		return
	}
	if err := liveSnapshot.Owner.Close(); err != nil {
		http.Error(w, "MTU operation completed but its captured owner did not close", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "mode": snapshot.Mode,
		"effective_mtu":           updated.EffectiveMTU,
		"effective_mtu_source":    updated.EffectiveMTUSource,
		"effective_mtu_tested_at": updated.EffectiveMTUTestedAt,
		"result":                  rawResult,
		"note":                    "bounded private-node loss/RTT/throughput comparison; the exact pre-test live MTU is snapshotted before any mutation, measurement is restored first, and adoption occurs only after the same session/profile/path is re-proved; cancellation, timeout, stale output, malformed output, apply failure, or persistence failure restores that exact live snapshot",
	})
}

func captureMTURetestSnapshot(a *app) (mtuRetestSnapshot, error) {
	a.mu.Lock()
	selectedID := a.profiles.SelectedID
	p, ok := a.profileByIDLocked(selectedID)
	p = common.CloneRouterProfile(p)
	st := a.state
	command := a.cmd
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
		return captureMTUMultihopSnapshot(a, p, st, command)
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
		Profile: p, State: st, Mode: mode, persistence: &mtuMeasurementPersistence{},
	}, nil
}

func captureMTULiveSnapshot(p common.RouterProfile) (mtuLiveSnapshot, error) {
	host := strings.Trim(strings.TrimSpace(p.DAITAHost), "[]")
	if host == "" {
		host = "10.77.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return mtuLiveSnapshot{}, errors.New("MTU live snapshot requires a literal private tunnel benchmark address")
	}
	family := 6
	if ip.To4() != nil {
		family = 4
	}
	iface, err := mtuRouteInterface(host)
	if err != nil {
		return mtuLiveSnapshot{}, err
	}
	mtu, err := readMTULiveValue(iface, family)
	if err != nil {
		return mtuLiveSnapshot{}, err
	}
	if mtu < 576 || mtu > 9000 {
		return mtuLiveSnapshot{}, fmt.Errorf("live tunnel interface returned unsafe MTU %d", mtu)
	}
	return mtuLiveSnapshot{Interface: iface, Family: family, OriginalMTU: mtu}, nil
}

func validateMTURetestSnapshot(a *app, snapshot mtuRetestSnapshot) error {
	if sessionTrackerFor(a).snapshot(0).ID != snapshot.SessionID {
		return errors.New("VPN session changed while MTU Retest was running; stale result was not adopted")
	}
	if err := validateMTUMultihopSource(a, snapshot); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.profiles.SelectedID != snapshot.SelectedID {
		return errors.New("selected Router VPN node changed while MTU Retest was running; stale result was not adopted")
	}
	if err := validateMTUMultihopLocked(a, snapshot); err != nil {
		return err
	}
	current, ok := a.profileByIDLocked(snapshot.Profile.ID)
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
	// Freeze the same credential, route, DNS and protection identity as other
	// live measurements. Adoption changes EffectiveMTU itself; omit only that
	// measured value so persisting our result does not invalidate our capture.
	p.EffectiveMTU = 0
	return liveMeasurementProfileToken(p)
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

func validateMTUMeasurementAgainstLiveSnapshot(measurement mtuMeasurementResult, live mtuLiveSnapshot) error {
	if live.Owner != nil && measurement.OwnerToken != live.Owner.token {
		return errors.New("MTU result belongs to a different captured interface operation")
	}
	if measurement.Interface != live.Interface || measurement.Family != live.Family || measurement.OriginalMTU != live.OriginalMTU {
		return errors.New("MTU measurement live interface/family/original value changed after the controller snapshot; stale result was not adopted")
	}
	return nil
}

func persistMTUMeasurement(a *app, snapshot mtuRetestSnapshot, measurement mtuMeasurementResult) (common.RouterProfile, error) {
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		return common.RouterProfile{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := validateMTUMultihopLocked(a, snapshot); err != nil {
		return common.RouterProfile{}, err
	}
	if snapshot.persistence == nil {
		return common.RouterProfile{}, errors.New("MTU persistence has no captured operation owner")
	}
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != snapshot.Profile.ID {
			continue
		}
		x := &a.profiles.Profiles[i]
		previous := *x
		if mtuProfileSnapshotToken(*x) != snapshot.ProfileToken || strings.ToLower(strings.TrimSpace(x.MTUPolicy)) != "auto" {
			return common.RouterProfile{}, errors.New("Router VPN profile changed before MTU result persistence")
		}
		x.EffectiveMTU = measurement.Winner.MTU
		x.EffectiveMTUSource = "auto-throughput"
		if snapshot.Multihop != nil {
			x.EffectiveMTUSource = "auto-throughput-multihop-exit-path"
			x.EffectiveUnderlayPMTU = 0
		}
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
		snapshot.persistence.applied = mtuMeasurementFieldsDigest(*x)
		return common.CloneRouterProfile(*x), nil
	}
	return common.RouterProfile{}, errors.New("selected Router VPN node disappeared before MTU result persistence")
}

func restoreMTUMeasurementFields(a *app, snapshot mtuRetestSnapshot) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if snapshot.persistence == nil || snapshot.persistence.applied == "" {
		return nil
	}
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != snapshot.Profile.ID {
			continue
		}
		x := &a.profiles.Profiles[i]
		if mtuProfileSnapshotToken(*x) != snapshot.ProfileToken {
			return errors.New("profile identity changed; refusing to overwrite newer profile state during MTU rollback")
		}
		if mtuMeasurementFieldsDigest(*x) != snapshot.persistence.applied {
			return errors.New("MTU rollback would replace another operation's saved measurement")
		}
		previous := common.CloneRouterProfile(*x)
		x.EffectiveMTU = snapshot.Profile.EffectiveMTU
		x.EffectiveMTUSource = snapshot.Profile.EffectiveMTUSource
		x.EffectiveMTUPathKey = snapshot.Profile.EffectiveMTUPathKey
		x.EffectiveUnderlayPMTU = snapshot.Profile.EffectiveUnderlayPMTU
		x.EffectiveMTUNetworkFingerprint = snapshot.Profile.EffectiveMTUNetworkFingerprint
		x.EffectiveMTUProfileFingerprint = snapshot.Profile.EffectiveMTUProfileFingerprint
		x.EffectiveMTUTestedAt = snapshot.Profile.EffectiveMTUTestedAt
		x.EffectiveMTUMbps = snapshot.Profile.EffectiveMTUMbps
		x.EffectiveMTUMedianRTTMs = snapshot.Profile.EffectiveMTUMedianRTTMs
		x.EffectiveMTUSuccessRatio = snapshot.Profile.EffectiveMTUSuccessRatio
		if err := a.persistProfilesLocked(); err != nil {
			*x = previous
			return err
		}
		snapshot.persistence.applied = ""
		return nil
	}
	return nil
}

func failMTURetestWithLiveRollback(w http.ResponseWriter, status int, message string, live mtuLiveSnapshot) {
	err := restoreMTULiveSnapshot(live)
	recordMTUViewRollback(w, live, err)
	if err != nil {
		http.Error(w, message+"; live MTU rollback failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Error(w, message, status)
}

func restoreMTULiveSnapshot(live mtuLiveSnapshot) error {
	if live.Owner == nil {
		return errors.New("MTU rollback requires its retained kernel owner")
	}
	return live.Owner.Restore()
}

func mtuRouteInterface(host string) (string, error) {
	if override := strings.TrimSpace(os.Getenv("HOMEVPN_TUN_IFACE")); override != "" {
		if err := validateMTULiveInterface(override); err != nil {
			return "", err
		}
		return override, nil
	}
	if override := strings.TrimSpace(os.Getenv("HOMEVPN_TUN_ALIAS")); override != "" {
		if err := validateMTULiveInterface(override); err != nil {
			return "", err
		}
		return override, nil
	}
	var iface string
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "get", host).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("could not resolve MTU route interface: %s", boundedMTUDetail(out))
		}
		fields := strings.Fields(string(out))
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				iface = fields[i+1]
				break
			}
		}
	case "darwin":
		out, err := exec.Command("route", "-n", "get", host).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("could not resolve MTU route interface: %s", boundedMTUDetail(out))
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "interface:") {
				iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
				break
			}
		}
	case "windows":
		escaped := strings.ReplaceAll(host, "'", "''")
		ps := fmt.Sprintf("$r=Find-NetRoute -RemoteIPAddress '%s' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; if($r){$r.InterfaceAlias}", escaped)
		out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("could not resolve MTU route interface: %s", boundedMTUDetail(out))
		}
		iface = strings.TrimSpace(string(out))
	default:
		return "", errors.New("live MTU route inspection is not implemented on this platform")
	}
	if err := validateMTULiveInterface(iface); err != nil {
		return "", err
	}
	return iface, nil
}

func validateMTULiveInterface(iface string) error {
	if iface == "" || len(iface) > 256 || iface != strings.TrimSpace(iface) || strings.ContainsAny(iface, "\r\n\x00") {
		return errors.New("invalid live MTU interface identity")
	}
	if runtime.GOOS == "linux" && (filepath.Base(iface) != iface || iface == "." || iface == "..") {
		return errors.New("unsafe Linux live MTU interface identity")
	}
	return nil
}

func readMTULiveValue(iface string, family int) (int, error) {
	if err := validateMTULiveInterface(iface); err != nil {
		return 0, err
	}
	var raw string
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "mtu"))
		if err != nil {
			return 0, fmt.Errorf("could not read live tunnel MTU: %w", err)
		}
		raw = strings.TrimSpace(string(data))
	case "darwin":
		out, err := exec.Command("ifconfig", iface).CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("could not read live tunnel MTU: %s", boundedMTUDetail(out))
		}
		fields := strings.Fields(string(out))
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "mtu" {
				raw = fields[i+1]
				break
			}
		}
	case "windows":
		familyName := "IPv4"
		if family == 6 {
			familyName = "IPv6"
		}
		escaped := strings.ReplaceAll(iface, "'", "''")
		ps := fmt.Sprintf("(Get-NetIPInterface -InterfaceAlias '%s' -AddressFamily %s | Sort-Object InterfaceMetric | Select-Object -First 1).NlMtuBytes", escaped, familyName)
		out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("could not read live tunnel MTU: %s", boundedMTUDetail(out))
		}
		raw = strings.TrimSpace(string(out))
	default:
		return 0, errors.New("live MTU inspection is not implemented on this platform")
	}
	mtu, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, errors.New("live tunnel interface returned a non-numeric MTU")
	}
	return mtu, nil
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
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		upper := strings.ToUpper(name)
		if !strings.HasPrefix(upper, "HOMEVPN_MTU_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, env...)
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
		if path := s.Multihop; path != nil {
			env = append(env,
				"HOMEVPN_MTU_GRAPH_TOKEN="+path.Token,
				"HOMEVPN_MTU_GRAPH_SCOPE=multihop-exit-path",
				"HOMEVPN_MTU_CONTROL_PROFILE_ID="+s.SelectedID,
				"HOMEVPN_MTU_PHYSICAL_ENTRY_ID="+path.Entry.ID,
				"HOMEVPN_MTU_PHYSICAL_ENTRY_ENDPOINT="+path.PhysicalEntry,
			)
		}
	}
	return env
}
