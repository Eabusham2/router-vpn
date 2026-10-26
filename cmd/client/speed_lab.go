package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

func registerSpeedLabRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/speed-lab/options", a.speedLabOptions)
	h.HandleFunc("/api/speed-lab/run", a.speedLabRun)
	registerTorBridgeRoutes(h, a)
}

func (a *app) speedLabOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	selectedID := a.profiles.SelectedID
	st := a.state
	command := a.cmd
	a.mu.Unlock()

	nodes := make([]map[string]any, 0, len(profiles))
	for _, p := range profiles {
		kind := strings.ToLower(strings.TrimSpace(p.NodeKind))
		if kind == "" {
			kind = "router-vpn"
		}
		protocol := ""
		if p.External != nil {
			protocol = p.External.Protocol
		}
		endpoint := p.Endpoint
		if kind == "external" && strings.EqualFold(strings.TrimSpace(protocol), "tor-bridge") {
			endpoint = ""
		}
		node := map[string]any{
			"id": p.ID, "profile_token": publicProfileToken(p), "name": p.Name, "node_kind": kind, "external_protocol": protocol,
			"endpoint": endpoint, "location": p.Location, "base_tunnel": p.BaseTunnel,
			"latitude": p.Latitude, "longitude": p.Longitude,
			"latency_median_ms": p.LatencyMedianMs, "latency_trimmed_mean_ms": p.LatencyTrimmedMeanMs,
			"selected":         p.ID == selectedID,
			"multihop_enabled": p.MultihopEnabled, "multihop_exit_id": p.MultihopExitID,
			"multihop_entry_id": p.MultihopEntryID, "multihop_entry_mode": p.MultihopEntryMode,
			"multihop_execution": p.MultihopExecution,
		}
		if p.External != nil {
			node["has_response_probe"] = p.External.ResponseProbe != nil || len(p.External.OpenVPNResponseProbes) != 0
			node["has_server_peer"] = p.External.ServerPeer != nil
			node["has_openvpn_pairing"] = p.External.OpenVPNPairing != nil
		}
		nodes = append(nodes, node)
	}

	logical := a.logicalStatuses()
	logicalModes := make([]map[string]any, 0, len(logical)+3)
	logicalModes = append(logicalModes,
		map[string]any{"id": "smart-auto", "name": "SMART AUTO", "available": true, "description": "first proven path, then safe simplification with last-good restore"},
		map[string]any{"id": "auto", "name": "AUTO", "available": true, "description": "first proven candidate that passes active AUTO filters"},
		map[string]any{"id": "custom", "name": "CUSTOM", "available": true, "description": "explicit requested layer composition"},
	)
	for _, mode := range logical {
		logicalModes = append(logicalModes, map[string]any{
			"id": mode.ID, "name": mode.Name, "available": mode.Available, "reason": mode.Reason,
			"preferred_base": mode.PreferredBase, "ready_bases": mode.ReadyBases,
		})
	}

	rawModes := make([]map[string]any, 0, len(a.modes))
	for _, mode := range a.modes {
		available, reason := a.checkMode(mode)
		rawModes = append(rawModes, map[string]any{
			"id": mode.ID, "name": mode.Name, "available": available, "reason": reason,
			"auto_eligible": mode.AutoEligible, "daita_supported": mode.DAITASupported, "jumbo_supported": mode.JumboSupported,
		})
	}

	current := map[string]any{"connected": st.Connected, "phase": st.Phase, "router_id": st.RouterID, "mode": st.Mode, "logical_mode": st.LogicalMode, "runtime_mode": st.RuntimeMode, "base": st.Base}
	if graph, ok := getActiveMultihopGraph(a); ok && st.Connected && st.Mode == "multihop" {
		current["entry_id"], current["exit_id"], current["exit_mode"] = graph.EntryID, graph.ExitID, graph.ExitMode
		current["entry_mode"], current["execution"] = graph.EntryMode, graph.Execution
	}
	if raw, exists := desktopNodeOwners.Load(a); exists && st.Connected && st.Mode == "external-node" {
		if launch, ok := raw.(*desktopNodeLaunch); ok && launch != nil && launch.command == command && launch.profileID == st.RouterID && launch.external != nil {
			current["exit_id"] = launch.profileID
			if !launch.external.direct {
				current["entry_id"] = launch.external.entry.ID
			}
		}
	}

	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                     true,
		"name":                   "Router VPN Speed Lab",
		"provider":               "Cloudflare Speed Test edge",
		"current":                current,
		"nodes":                  nodes,
		"logical_modes":          logicalModes,
		"raw_modes":              rawModes,
		"router_vpn_entry_modes": a.externalRouterEntryModes(),
		"supported_entry_modes":  desktopMultihopEntryModes(),
		"supported_exit_modes":   desktopMultihopExitModes(),
		"execution_choices": []map[string]string{
			{"id": "local", "name": "Local"}, {"id": "server", "name": "Server"}, {"id": "auto", "name": "Compare both"},
		},
		"topologies": []map[string]any{
			{"id": "system-direct", "name": "System direct / no Router VPN", "temporary": true},
			{"id": "router", "name": "Direct Router VPN node", "temporary": true},
			{"id": "multihop", "name": "Router VPN multihop", "temporary": true},
			{"id": "external", "name": "External direct or hopped exit", "temporary": true},
		},
		"duration": map[string]any{
			"default_mode": "auto", "auto_min_seconds": speedLabAutoMin.Seconds(), "auto_max_seconds": speedLabAutoMax.Seconds(),
			"custom_min_seconds": 1, "custom_max_seconds": 60,
		},
		"platform": map[string]any{
			"goos":               runtime.GOOS,
			"temporary_router":   runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux",
			"temporary_multihop": runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux",
			"temporary_external": runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux",
			"external_protocols": externalProfileProtocolCapabilities(),
		},
		"semantics": "current tests follow the captured runtime and physical network; temporary tests capture the complete previous connection, prove the requested path, suppress durable side effects, and restore the previous private configuration with a fresh path proof and the already-proved execution choice; explicit Disconnect suppresses reconnection",
	})
}

func (a *app) speedLabSystemDirect(r *http.Request, q speedLabRequest, duration speedLabDuration, minDuration, maxDuration time.Duration, scope string) (speedLabPath, speedLabMeasurement, error) {
	release, err := a.beginNodeBoundOperation()
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, err
	}
	defer release()
	if err := a.validateSpeedLabExpectedProfiles(q, nil); err != nil {
		return speedLabPath{}, speedLabMeasurement{}, err
	}
	a.mu.Lock()
	connected, phase := a.state.Connected, a.state.Phase
	a.mu.Unlock()
	if connected || profileSettingsBusy(connected, phase) {
		return speedLabPath{}, speedLabMeasurement{}, errors.New("disconnect before a system-direct Speed Lab test")
	}
	path := speedLabPath{Scope: scope, Topology: "system-direct", Temporary: scope == "temporary", Description: "raw system Internet path with Router VPN disconnected"}
	measurement, err := measureSpeedLab(r.Context(), duration, minDuration, maxDuration, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.state.Connected || profileSettingsBusy(a.state.Connected, a.state.Phase) {
			return errors.New("Router VPN state changed during the system-direct Speed Lab test")
		}
		return nil
	})
	return path, measurement, err
}

func (a *app) speedLabCurrent(r *http.Request, duration speedLabDuration, minDuration, maxDuration time.Duration) (speedLabPath, speedLabMeasurement, []speedLabHopMeasurement, error) {
	return a.speedLabCurrentExpected(r, speedLabRequest{}, duration, minDuration, maxDuration)
}

func (a *app) speedLabCurrentExpected(r *http.Request, q speedLabRequest, duration speedLabDuration, minDuration, maxDuration time.Duration) (speedLabPath, speedLabMeasurement, []speedLabHopMeasurement, error) {
	a.mu.Lock()
	connected := a.state.Connected
	a.mu.Unlock()
	if !connected {
		path, measurement, err := a.speedLabSystemDirect(r, q, duration, minDuration, maxDuration, "current")
		return path, measurement, nil, err
	}
	identity, path, err := a.captureExpectedSpeedLabIdentity(q)
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, err
	}
	pathCtx, stopPath, err := speedLabPathContext(r.Context(), func() error { return validateSpeedLabIdentity(a, identity) })
	if err != nil {
		return path, speedLabMeasurement{}, nil, err
	}
	defer stopPath()
	r = r.WithContext(pathCtx)
	measurement, err := measureSpeedLab(r.Context(), duration, minDuration, maxDuration, func() error { return verifySpeedLabPath(r.Context(), a, identity) })
	if err != nil {
		return path, measurement, nil, speedLabPathResultError(pathCtx, err)
	}
	var hops []speedLabHopMeasurement
	if path.Topology == "multihop" {
		hops, err = measureSpeedLabMultihopHopsContext(r.Context(), a, identity)
		if err != nil {
			return path, measurement, nil, speedLabPathResultError(pathCtx, err)
		}
	}
	if err := speedLabPathResultError(pathCtx, verifySpeedLabPath(pathCtx, a, identity)); err != nil {
		return path, measurement, nil, err
	}
	return path, measurement, hops, nil
}

func speedLabRestoreAfterFailure(a *app, snapshot speedLabTemporarySnapshot, cause error) error {
	cleanupErr := a.speedLabRestoreTemporary(snapshot)
	if cleanupErr == nil {
		return cause
	}
	if cause == nil {
		return errors.New("temporary Speed Lab rollback failed: " + cleanupErr.Error())
	}
	return errors.Join(cause, errors.New("temporary-path rollback also failed: "+cleanupErr.Error()))
}

// Link request cancellation and Disconnect to this operation only. Capturing
// its cancel function prevents a delayed HTTP callback from stopping a newer
// session after this temporary test has released operationMu.
func (a *app) speedLabRequestContext(r *http.Request, owner context.Context) (*http.Request, func(), error) {
	a.mu.Lock()
	if owner == nil || a.connectionContext != owner || a.connectionCancel == nil {
		a.mu.Unlock()
		return nil, nil, errors.New("temporary Speed Lab connection owner changed before measurement")
	}
	cancelOwner := a.connectionCancel
	if raw, exists := speedLabTemporaryOwners.Load(a); exists {
		if temporary, ok := raw.(*speedLabTemporaryOwner); ok && temporary.test == owner && a.speedLabOwnerCurrentLocked(temporary) {
			// A cancelled HTTP test requests restoration. Disconnect alone owns
			// the parent intent cancellation that suppresses that restoration.
			cancelOwner = temporary.cancelTest
		}
	}
	a.mu.Unlock()
	ctx, cancel := context.WithCancel(r.Context())
	stopOperation := context.AfterFunc(owner, cancel)
	stopRequest := context.AfterFunc(r.Context(), cancelOwner)
	return r.WithContext(ctx), func() {
		stopRequest()
		stopOperation()
		cancel()
	}, nil
}

func (a *app) speedLabTemporary(r *http.Request, q speedLabRequest, duration speedLabDuration, minDuration, maxDuration time.Duration) (speedLabPath, speedLabMeasurement, []speedLabHopMeasurement, error) {
	switch strings.ToLower(strings.TrimSpace(q.Topology)) {
	case "", "router", "direct", "multihop", "external", "system-direct":
	default:
		return speedLabPath{}, speedLabMeasurement{}, nil, errors.New("unsupported temporary Speed Lab topology")
	}
	operationCtx, snapshot, finish, err := a.beginSpeedLabTemporaryOperationExpected(&q)
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, err
	}
	defer finish()
	endPersistenceGuard, err := beginSpeedLabTemporaryPersistenceGuard(a)
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, err
	}
	defer endPersistenceGuard()
	r, releaseContext, err := a.speedLabRequestContext(r, operationCtx)
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, err
	}
	defer releaseContext()
	if err := r.Context().Err(); err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, err
	}
	if strings.EqualFold(strings.TrimSpace(q.Topology), "external") {
		q.preparedExternal, err = a.prepareSpeedLabExternalPath(q, nil)
		if err != nil {
			return speedLabPath{}, speedLabMeasurement{}, nil, err
		}
		defer q.preparedExternal.releaseUnused()
	}
	if err := a.speedLabSuspendPrevious(snapshot, strings.EqualFold(strings.TrimSpace(q.Topology), "system-direct")); err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, speedLabRestoreAfterFailure(a, snapshot, err)
	}

	var path speedLabPath
	var identity speedLabPathIdentity
	var validate func() error
	if strings.EqualFold(strings.TrimSpace(q.Topology), "system-direct") {
		path = speedLabPath{Scope: "temporary", Topology: "system-direct", Temporary: true, Description: "temporary system Internet path; the captured previous VPN is restored after measurement"}
		validate = func() error {
			if err := a.speedLabCheckOwner(snapshot.Owner); err != nil {
				return err
			}
			a.mu.Lock()
			st, command := a.state, a.cmd
			a.mu.Unlock()
			if command != nil || st.Connected || st.Mode != "off" || st.Phase != "off" || physicalNetworkIdentity() != snapshot.Owner.network {
				return errors.New("system-direct Speed Lab path changed during the temporary test")
			}
			return nil
		}
	} else {
		var startErr error
		path, startErr = a.startSpeedLabTemporaryPath(q)
		if startErr != nil {
			return speedLabPath{}, speedLabMeasurement{}, nil, speedLabRestoreAfterFailure(a, snapshot, startErr)
		}
		identity, _, err = captureSpeedLabIdentity(a)
		if err != nil {
			return speedLabPath{}, speedLabMeasurement{}, nil, speedLabRestoreAfterFailure(a, snapshot, err)
		}
		validate = func() error {
			if err := a.speedLabCheckOwner(snapshot.Owner); err != nil {
				return err
			}
			return validateSpeedLabIdentity(a, identity)
		}
	}
	if err := validate(); err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, speedLabRestoreAfterFailure(a, snapshot, err)
	}
	if err := a.speedLabWriteStore(snapshot.Profiles); err != nil {
		cause := errors.New("temporary path was proven but prior durable profile state could not be restored before measurement: " + err.Error())
		return speedLabPath{}, speedLabMeasurement{}, nil, speedLabRestoreAfterFailure(a, snapshot, cause)
	}
	pathCtx, stopPath, err := speedLabPathContext(r.Context(), validate)
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, speedLabRestoreAfterFailure(a, snapshot, err)
	}
	defer stopPath()
	verify := func() error {
		if err := validate(); err != nil {
			return err
		}
		if identity.External != nil {
			if err := verifySpeedLabPath(pathCtx, a, identity); err != nil {
				return err
			}
		}
		return validate()
	}
	measurement, measureErr := measureSpeedLab(pathCtx, duration, minDuration, maxDuration, verify)
	var hops []speedLabHopMeasurement
	if measureErr == nil && path.Topology == "multihop" {
		hops, measureErr = measureSpeedLabMultihopHopsContext(pathCtx, a, identity)
	}
	measureErr = speedLabPathResultError(pathCtx, errors.Join(measureErr, verify()))
	// Join all requests/observers before intentional teardown. Their cancellation
	// cannot retire a replacement runtime or turn restoration into a stale test.
	stopPath()
	releaseContext()
	cleanupErr := a.speedLabRestoreTemporary(snapshot)
	if measureErr != nil {
		if cleanupErr != nil {
			return speedLabPath{}, speedLabMeasurement{}, nil, errors.Join(measureErr, errors.New("temporary-path cleanup also failed: "+cleanupErr.Error()))
		}
		return speedLabPath{}, speedLabMeasurement{}, nil, measureErr
	}
	if cleanupErr != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, errors.New("Speed Lab measurement completed but previous-path restoration failed: " + cleanupErr.Error())
	}
	return path, measurement, hops, nil
}

func (a *app) speedLabRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q speedLabRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&q); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	duration, minDuration, maxDuration, err := normalizeSpeedLabDuration(q.DurationMode, q.MinSeconds, q.MaxSeconds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	scope := strings.ToLower(strings.TrimSpace(q.Scope))
	if scope == "" {
		scope = "current"
	}
	finishMeasurement, err := beginSpeedLabRun(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer finishMeasurement()
	if err := a.validateSpeedLabExpectedProfiles(q, nil); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	releaseMTU, err := a.holdDesktopMTUForMeasurement(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer releaseMTU()
	var path speedLabPath
	var measurement speedLabMeasurement
	var hops []speedLabHopMeasurement
	switch scope {
	case "current":
		path, measurement, hops, err = a.speedLabCurrentExpected(r, q, duration, minDuration, maxDuration)
	case "temporary":
		path, measurement, hops, err = a.speedLabTemporary(r, q, duration, minDuration, maxDuration)
	default:
		err = errors.New("Speed Lab scope must be current or temporary")
	}
	if err != nil {
		status := http.StatusBadGateway
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "disconnect") || strings.Contains(lower, "changed") || strings.Contains(lower, "transaction") || errors.Is(err, context.Canceled) || errors.Is(err, errConnectionOperationCancelled) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"path":        path,
		"measurement": measurement,
		"hops":        hops,
		"summary": map[string]any{
			"idle_ms":                 measurement.Idle.MedianMs,
			"download_mbps":           measurement.Download.Mbps,
			"download_loaded_ms":      measurement.Download.LoadedLatency.MedianMs,
			"download_bufferbloat_ms": measurement.Download.BufferbloatMs,
			"upload_mbps":             measurement.Upload.Mbps,
			"upload_loaded_ms":        measurement.Upload.LoadedLatency.MedianMs,
			"upload_bufferbloat_ms":   measurement.Upload.BufferbloatMs,
		},
		"note": "throughput and loaded latency are measured independently; multihop entry/exit RTT and Mbps are independently measured on the same proved graph; no Mbps value is derived from RTT or another hop, and temporary path choices are restored after the test",
	})
}
