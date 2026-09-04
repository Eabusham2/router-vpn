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

	"router-vpn/internal/common"
)

func registerSpeedLabRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/speed-lab/options", a.speedLabOptions)
	h.HandleFunc("/api/speed-lab/run", a.speedLabRun)
}

func (a *app) speedLabOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	selectedID := a.profiles.SelectedID
	st := a.state
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
		nodes = append(nodes, map[string]any{
			"id": p.ID, "name": p.Name, "node_kind": kind, "external_protocol": protocol,
			"endpoint": p.Endpoint, "location": p.Location, "base_tunnel": p.BaseTunnel,
			"latitude": p.Latitude, "longitude": p.Longitude,
			"latency_median_ms": p.LatencyMedianMs, "latency_trimmed_mean_ms": p.LatencyTrimmedMeanMs,
			"selected": p.ID == selectedID,
		})
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
	}

	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true,
		"name": "Router VPN Speed Lab",
		"provider": "Cloudflare Speed Test edge",
		"current": current,
		"nodes": nodes,
		"logical_modes": logicalModes,
		"raw_modes": rawModes,
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
			"goos": runtime.GOOS,
			"temporary_router": runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux",
			"temporary_multihop": runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux",
			"temporary_external": runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux",
			"external_protocols": externalProfileProtocolCapabilities(),
		},
		"semantics": "current tests never substitute the mutable selected node; temporary tests hold the connection/settings transaction owner, suppress durable ranking/startup side effects, prove the requested path, restore the prior private profile store before measurement, tear the path down, and restore the prior disconnected state",
	})
}

func (a *app) speedLabSystemDirect(r *http.Request, duration speedLabDuration, minDuration, maxDuration time.Duration, scope string) (speedLabPath, speedLabMeasurement, error) {
	release, err := a.beginNodeBoundOperation()
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, err
	}
	defer release()
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
	a.mu.Lock()
	connected := a.state.Connected
	a.mu.Unlock()
	if !connected {
		path, measurement, err := a.speedLabSystemDirect(r, duration, minDuration, maxDuration, "current")
		return path, measurement, nil, err
	}
	identity, path, err := captureSpeedLabIdentity(a)
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, err
	}
	measurement, err := measureSpeedLab(r.Context(), duration, minDuration, maxDuration, func() error { return validateSpeedLabIdentity(a, identity) })
	if err != nil {
		return path, measurement, nil, err
	}
	var hops []speedLabHopMeasurement
	if path.Topology == "multihop" {
		hops, err = measureSpeedLabMultihopHops(a, identity)
		if err != nil {
			return path, measurement, nil, err
		}
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
	return errors.New(cause.Error() + "; temporary-path rollback also failed: " + cleanupErr.Error())
}

func (a *app) speedLabTemporary(r *http.Request, q speedLabRequest, duration speedLabDuration, minDuration, maxDuration time.Duration) (speedLabPath, speedLabMeasurement, []speedLabHopMeasurement, error) {
	if strings.EqualFold(strings.TrimSpace(q.Topology), "system-direct") {
		path, measurement, err := a.speedLabSystemDirect(r, duration, minDuration, maxDuration, "temporary")
		return path, measurement, nil, err
	}
	_, finish, err := a.beginConnectionOperation()
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, err
	}
	defer finish()
	endPersistenceGuard, err := beginSpeedLabTemporaryPersistenceGuard(a)
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, err
	}
	defer endPersistenceGuard()

	requestDone := make(chan struct{})
	go func() {
		select {
		case <-r.Context().Done():
			a.cancelConnectionOperation()
		case <-requestDone:
		}
	}()
	defer close(requestDone)

	snapshot := a.speedLabSnapshotTemporary()
	path, startErr := a.startSpeedLabTemporaryPath(q)
	if startErr != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, speedLabRestoreAfterFailure(a, snapshot, startErr)
	}
	if err := a.speedLabWriteStore(snapshot.Profiles); err != nil {
		cause := errors.New("temporary path was proven but prior durable profile state could not be restored before measurement: " + err.Error())
		return speedLabPath{}, speedLabMeasurement{}, nil, speedLabRestoreAfterFailure(a, snapshot, cause)
	}
	identity, _, err := captureSpeedLabIdentity(a)
	if err != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, speedLabRestoreAfterFailure(a, snapshot, err)
	}
	measurement, measureErr := measureSpeedLab(r.Context(), duration, minDuration, maxDuration, func() error { return validateSpeedLabIdentity(a, identity) })
	var hops []speedLabHopMeasurement
	if measureErr == nil && path.Topology == "multihop" {
		hops, measureErr = measureSpeedLabMultihopHops(a, identity)
	}
	cleanupErr := a.speedLabRestoreTemporary(snapshot)
	if measureErr != nil {
		if cleanupErr != nil {
			return speedLabPath{}, speedLabMeasurement{}, nil, errors.New(measureErr.Error() + "; temporary-path cleanup also failed: " + cleanupErr.Error())
		}
		return speedLabPath{}, speedLabMeasurement{}, nil, measureErr
	}
	if cleanupErr != nil {
		return speedLabPath{}, speedLabMeasurement{}, nil, errors.New("Speed Lab measurement completed but temporary-path cleanup failed: " + cleanupErr.Error())
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
	var path speedLabPath
	var measurement speedLabMeasurement
	var hops []speedLabHopMeasurement
	switch scope {
	case "current":
		path, measurement, hops, err = a.speedLabCurrent(r, duration, minDuration, maxDuration)
	case "temporary":
		path, measurement, hops, err = a.speedLabTemporary(r, q, duration, minDuration, maxDuration)
	default:
		err = errors.New("Speed Lab scope must be current or temporary")
	}
	if err != nil {
		status := http.StatusBadGateway
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "disconnect") || strings.Contains(lower, "changed") || strings.Contains(lower, "transaction") || errors.Is(err, context.Canceled) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true,
		"path": path,
		"measurement": measurement,
		"hops": hops,
		"summary": map[string]any{
			"idle_ms": measurement.Idle.MedianMs,
			"download_mbps": measurement.Download.Mbps,
			"download_loaded_ms": measurement.Download.LoadedLatency.MedianMs,
			"download_bufferbloat_ms": measurement.Download.BufferbloatMs,
			"upload_mbps": measurement.Upload.Mbps,
			"upload_loaded_ms": measurement.Upload.LoadedLatency.MedianMs,
			"upload_bufferbloat_ms": measurement.Upload.BufferbloatMs,
		},
		"note": "throughput and loaded latency are measured independently; multihop entry/exit RTT and Mbps are independently measured on the same proved graph; no Mbps value is derived from RTT or another hop, and temporary path choices are restored after the test",
	})
}
