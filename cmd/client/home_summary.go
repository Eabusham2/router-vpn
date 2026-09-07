package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type homeExitProof struct {
	Generation uint64
	SessionID  string
	RouterID   string
	Runtime    string
	Base       string
	StateToken string
	Profiles   map[string]string
	Multihop   bool
	Graph      activeMultihopGraph
	IP         string
	At         time.Time
}

var homeExitProofs homeExitProofCache

type homeSummaryResponse struct {
	NodeID             string   `json:"node_id,omitempty"`
	NodeName           string   `json:"node_name,omitempty"`
	NodeKind           string   `json:"node_kind,omitempty"`
	Location           string   `json:"location,omitempty"`
	PublicEndpoint     string   `json:"public_endpoint,omitempty"`
	ActualExitIP       string   `json:"actual_exit_ip,omitempty"`
	ActualExitStatus   string   `json:"actual_exit_status"`
	ActualExitTestedAt string   `json:"actual_exit_tested_at,omitempty"`
	ConnectionPhase    string   `json:"connection_phase"`
	Connected          bool     `json:"connected"`
	PathProof          string   `json:"path_proof"`
	LogicalMode        string   `json:"logical_mode,omitempty"`
	RequestedBase      string   `json:"requested_base,omitempty"`
	ActualRuntime      string   `json:"actual_runtime,omitempty"`
	ActualBase         string   `json:"actual_base,omitempty"`
	Fallback           string   `json:"fallback,omitempty"`
	DNSMode            string   `json:"dns_mode,omitempty"`
	DNSHost            string   `json:"dns_host,omitempty"`
	DNSLatencyMs       float64  `json:"dns_latency_ms,omitempty"`
	DNSStatus          string   `json:"dns_status"`
	NodeLatencyMs      float64  `json:"node_latency_ms,omitempty"`
	NodeLatencySamples int      `json:"node_latency_samples,omitempty"`
	LANAccess          bool     `json:"lan_access"`
	KillSwitch         string   `json:"kill_switch"`
	EffectiveMTU       int      `json:"effective_mtu,omitempty"`
	EffectiveMTUSource string   `json:"effective_mtu_source,omitempty"`
	IPv6Mode           string   `json:"ipv6_mode,omitempty"`
	AutoConnect        bool     `json:"auto_connect,omitempty"`
	Warnings           []string `json:"warnings"`
}

func registerHomeSummaryRoute(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/home-summary", a.homeSummary)
	h.HandleFunc("/api/home-summary/prove-exit", a.proveHomeExit)
}

func (a *app) homeSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	value, err := a.homeSummaryValue()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func (a *app) proveHomeExit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	before := sessionTrackerFor(a).snapshot(0)
	if !before.Connected || before.Phase != "connected" || before.PathProof != "passed" || before.ID == "" {
		http.Error(w, "connect and pass selected-path proof before proving the public VPN exit", http.StatusConflict)
		return
	}
	targetID := strings.TrimSpace(before.RouterID)
	if targetID == "" {
		http.Error(w, "active Router VPN session has no node identity; refusing to substitute the mutable selected node", http.StatusConflict)
		return
	}
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(targetID)
	stateAtStart := a.state
	stateToken := mtuStateSnapshotToken(a.state)
	a.mu.Unlock()
	if !ok {
		http.Error(w, "active Router VPN node disappeared before public-exit proof", http.StatusConflict)
		return
	}

	graph, graphOK := getActiveMultihopGraph(a)
	if stateAtStart.Mode == "multihop" {
		if err := validateActiveMultihopSpeedGraph(stateAtStart, graph, graphOK, graph.EntryID, graph.ExitID); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}
	profiles, err := captureMeasurementProfiles(a, stateAtStart, graph, profile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	binding := homeExitProof{Generation: homeExitProofs.generation(a), SessionID: before.ID, RouterID: targetID, Runtime: before.ActualMode, Base: before.ActualBase,
		StateToken: stateToken, Profiles: profiles, Multihop: stateAtStart.Mode == "multihop", Graph: graph}
	validate := func() error { return a.validateHomeExitBinding(&binding) }
	measured, stop, err := speedLabPathContext(r.Context(), validate)
	if err != nil {
		if !asyncMeasurementRequestError(w, r.Context(), r.Context(), "Home public-exit proof") {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	defer stop()
	client, err := newAsyncMeasurementHTTPClient(stateAtStart, 5*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer client.CloseIdleConnections()
	ip, err := probePublicExitIPContext(measured, client)
	if asyncMeasurementRequestError(w, r.Context(), measured, "Home public-exit proof") {
		return
	}
	if freshnessErr := validate(); freshnessErr != nil {
		http.Error(w, freshnessErr.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	after := sessionTrackerFor(a).snapshot(0)
	if !after.Connected || after.Phase != "connected" || after.PathProof != "passed" || after.ID != before.ID || after.RouterID != before.RouterID || after.ActualMode != before.ActualMode || after.ActualBase != before.ActualBase {
		http.Error(w, "VPN session or runtime changed while public-exit proof was running; result discarded", http.StatusConflict)
		return
	}

	status, persistErr := a.adoptHomeExitProof(measured, binding, ip)
	if persistErr != nil {
		if !asyncMeasurementRequestError(w, r.Context(), measured, "Home public-exit proof") {
			http.Error(w, persistErr.Error(), status)
		}
		return
	}
	value, err := a.homeSummaryValue()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

// Network I/O has already finished. Serialize only adoption with connection and
// settings mutations, and recheck the session under tracker -> app lock order.
func (a *app) adoptHomeExitProof(ctx context.Context, binding homeExitProof, ip string) (int, error) {
	release, err := a.beginNodeBoundOperation()
	if err != nil {
		return http.StatusConflict, err
	}
	defer release()
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return http.StatusConflict, err
	}
	if err := validateHomeExitBindingLocked(a, tracker.session, &binding); err != nil {
		return http.StatusConflict, err
	}
	ip, err = common.NormalizeExpectedPublicIP(ip)
	if err != nil {
		return http.StatusBadGateway, err
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == binding.RouterID {
			a.profiles.Profiles[i].PublicIP = ip
			break
		}
	}
	if persistErr := a.persistProfilesLocked(); persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
		return http.StatusInternalServerError, persistErr
	}
	binding.IP, binding.At = ip, time.Now().UTC()
	homeExitProofs.Store(a, &binding)
	return http.StatusOK, nil
}

func (a *app) homeSummaryValue() (homeSummaryResponse, error) {
	session := sessionTrackerFor(a).snapshot(0)
	a.mu.Lock()
	selectedID := a.profiles.SelectedID
	targetID := selectedID
	busy := profileSettingsBusy(a.state.Connected, a.state.Phase)
	if busy {
		if liveID := strings.TrimSpace(a.state.RouterID); liveID != "" {
			targetID = liveID
		}
	}
	profile, ok := a.profileByIDLocked(targetID)
	if ok && !busy && targetID == selectedID {
		a.syncProfileOptionStateLocked(profile)
	}
	lastError := a.state.LastError
	a.mu.Unlock()
	if !ok {
		if busy && targetID != selectedID {
			return homeSummaryResponse{}, errors.New("active Router VPN node disappeared from the linked profile store")
		}
		return homeSummaryResponse{}, errors.New("add and select a Router VPN node first")
	}
	return buildHomeSummary(a, profile, session, lastError), nil
}

func buildHomeSummary(a *app, profile common.RouterProfile, session connectionSession, lastError string) homeSummaryResponse {
	kind := strings.ToLower(strings.TrimSpace(profile.NodeKind))
	if kind == "" {
		kind = "router-vpn"
	}
	logical := strings.TrimSpace(session.RequestedMode)
	if logical == "" {
		logical = strings.TrimSpace(session.ActualMode)
	}
	fallback := ""
	if session.RequestedBase != "" && session.ActualBase != "" && session.RequestedBase != "auto" && session.RequestedBase != session.ActualBase {
		fallback = session.RequestedBase + " -> " + session.ActualBase
	} else if profile.BaseFallback && session.ActualBase != "" {
		fallback = "fallback enabled; actual base " + session.ActualBase
	}
	dnsMode, dnsHost, dnsStatus, dnsLatency := session.DNSProof.Mode, session.DNSProof.Host, session.DNSProof.Status, session.DNSProof.LatencyMs
	if dnsMode == "" {
		dnsMode = profile.DNSMode
	}
	if dnsHost == "" {
		dnsHost = profile.DNSHost
	}
	if dnsStatus == "" {
		dnsStatus = "not-proven"
	}
	actualExitStatus, actualExit, actualExitTested := "not-connected", "", ""
	if session.Connected {
		actualExitStatus = "unproven"
		if raw, found := homeExitProofs.Load(a); found {
			if proof, valid := raw.(*homeExitProof); valid && a.homeExitProofCurrent(proof, profile, session) && proof.SessionID == session.ID {
				actualExit = proof.IP
				actualExitStatus = "proved"
				actualExitTested = proof.At.Format(time.RFC3339)
			}
		}
	} else if raw, found := homeExitProofs.Load(a); found {
		if proof, valid := raw.(*homeExitProof); valid {
			a.homeExitProofCurrent(proof, profile, session)
		}
	}
	warnings := make([]string, 0, 4)
	if strings.TrimSpace(lastError) != "" {
		warnings = append(warnings, strings.TrimSpace(lastError))
	}
	if session.Connected && actualExitStatus != "proved" {
		warnings = append(warnings, "actual public exit is not proven for this live session")
	}
	if session.Connected && dnsStatus != "passed" {
		warnings = append(warnings, "selected DNS is not yet proven for this live session")
	}
	if fallback != "" {
		warnings = append(warnings, "fallback: "+fallback)
	}
	return homeSummaryResponse{NodeID: profile.ID, NodeName: profile.Name, NodeKind: kind, Location: profile.Location, PublicEndpoint: profile.Endpoint, ActualExitIP: actualExit, ActualExitStatus: actualExitStatus, ActualExitTestedAt: actualExitTested, ConnectionPhase: session.Phase, Connected: session.Connected, PathProof: session.PathProof, LogicalMode: logical, RequestedBase: session.RequestedBase, ActualRuntime: session.ActualMode, ActualBase: session.ActualBase, Fallback: fallback, DNSMode: dnsMode, DNSHost: dnsHost, DNSLatencyMs: dnsLatency, DNSStatus: dnsStatus, NodeLatencyMs: profile.LatencyMedianMs, NodeLatencySamples: profile.LatencySamples, LANAccess: profile.HomeLANAccess, KillSwitch: profile.KillSwitchPolicy, EffectiveMTU: profile.EffectiveMTU, EffectiveMTUSource: profile.EffectiveMTUSource, IPv6Mode: profile.IPv6Mode, AutoConnect: profile.AutoConnect, Warnings: warnings}
}
