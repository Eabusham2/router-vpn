package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
)

type homeExitProof struct { SessionID string; IP string; At time.Time }
var homeExitProofs sync.Map

type homeSummaryResponse struct {
	NodeID string `json:"node_id,omitempty"`; NodeName string `json:"node_name,omitempty"`; NodeKind string `json:"node_kind,omitempty"`; Location string `json:"location,omitempty"`; PublicEndpoint string `json:"public_endpoint,omitempty"`
	ActualExitIP string `json:"actual_exit_ip,omitempty"`; ActualExitStatus string `json:"actual_exit_status"`; ActualExitTestedAt string `json:"actual_exit_tested_at,omitempty"`
	ConnectionPhase string `json:"connection_phase"`; Connected bool `json:"connected"`; PathProof string `json:"path_proof"`; LogicalMode string `json:"logical_mode,omitempty"`; RequestedBase string `json:"requested_base,omitempty"`; ActualRuntime string `json:"actual_runtime,omitempty"`; ActualBase string `json:"actual_base,omitempty"`; Fallback string `json:"fallback,omitempty"`
	DNSMode string `json:"dns_mode,omitempty"`; DNSHost string `json:"dns_host,omitempty"`; DNSLatencyMs float64 `json:"dns_latency_ms,omitempty"`; DNSStatus string `json:"dns_status"`
	NodeLatencyMs float64 `json:"node_latency_ms,omitempty"`; NodeLatencySamples int `json:"node_latency_samples,omitempty"`; LANAccess bool `json:"lan_access"`; KillSwitch string `json:"kill_switch"`; EffectiveMTU int `json:"effective_mtu,omitempty"`; EffectiveMTUSource string `json:"effective_mtu_source,omitempty"`; IPv6Mode string `json:"ipv6_mode,omitempty"`; AutoConnect bool `json:"auto_connect,omitempty"`; Warnings []string `json:"warnings"`
}

func registerHomeSummaryRoute(h *http.ServeMux, a *app) { h.HandleFunc("/api/home-summary", a.homeSummary); h.HandleFunc("/api/home-summary/prove-exit", a.proveHomeExit) }

func (a *app) homeSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "GET only", http.StatusMethodNotAllowed); return }
	value, err := a.homeSummaryValue(); if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
	w.Header().Set("content-type", "application/json"); w.Header().Set("cache-control", "no-store"); _ = json.NewEncoder(w).Encode(value)
}

func (a *app) proveHomeExit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	before := sessionTrackerFor(a).snapshot(0)
	if !before.Connected || before.Phase != "connected" || before.PathProof != "passed" || before.ID == "" { http.Error(w, "connect and pass selected-path proof before proving the public VPN exit", http.StatusConflict); return }
	ip, err := probePublicExitIP(); if err != nil { http.Error(w, err.Error(), http.StatusBadGateway); return }
	after := sessionTrackerFor(a).snapshot(0)
	if !after.Connected || after.Phase != "connected" || after.PathProof != "passed" || after.ID != before.ID { http.Error(w, "VPN session changed while public-exit proof was running; result discarded", http.StatusConflict); return }
	homeExitProofs.Store(a, homeExitProof{SessionID: after.ID, IP: ip, At: time.Now().UTC()})
	a.mu.Lock()
	for i := range a.profiles.Profiles { if a.profiles.Profiles[i].ID == after.RouterID || (after.RouterID == "" && a.profiles.Profiles[i].ID == a.profiles.SelectedID) { a.profiles.Profiles[i].PublicIP = ip; break } }
	_ = a.persistProfilesLocked(); a.mu.Unlock()
	value, err := a.homeSummaryValue(); if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	w.Header().Set("content-type", "application/json"); _ = json.NewEncoder(w).Encode(value)
}

func probePublicExitIP() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, endpoint := range []string{"https://api64.ipify.org", "https://api.ipify.org"} {
		resp, err := client.Get(endpoint); if err != nil { continue }
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256)); _ = resp.Body.Close()
		if readErr != nil || resp.StatusCode/100 != 2 { continue }
		candidate := strings.TrimSpace(string(body)); if net.ParseIP(candidate) != nil { return candidate, nil }
	}
	return "", errors.New("could not determine the public VPN exit address through the current selected path")
}

func (a *app) homeSummaryValue() (homeSummaryResponse, error) {
	a.mu.Lock()
	selectedID := a.profiles.SelectedID
	profile, ok := a.profileByIDLocked(selectedID)
	if ok && !a.state.Connected && a.state.Phase != "starting" && a.state.Phase != "checking" && !strings.HasPrefix(a.state.Phase, "auto:") { a.syncProfileOptionStateLocked(profile) }
	lastError := a.state.LastError
	a.mu.Unlock()
	if !ok { return homeSummaryResponse{}, errors.New("add and select a Router VPN node first") }
	return buildHomeSummary(a, profile, sessionTrackerFor(a).snapshot(0), lastError), nil
}

func buildHomeSummary(a *app, profile common.RouterProfile, session connectionSession, lastError string) homeSummaryResponse {
	kind := strings.ToLower(strings.TrimSpace(profile.NodeKind)); if kind == "" { kind = "router-vpn" }
	logical := strings.TrimSpace(session.RequestedMode); if logical == "" { logical = strings.TrimSpace(session.ActualMode) }
	fallback := ""
	if session.RequestedBase != "" && session.ActualBase != "" && session.RequestedBase != "auto" && session.RequestedBase != session.ActualBase { fallback = session.RequestedBase + " -> " + session.ActualBase } else if profile.BaseFallback && session.ActualBase != "" { fallback = "fallback enabled; actual base " + session.ActualBase }
	dnsMode, dnsHost, dnsStatus, dnsLatency := session.DNSProof.Mode, session.DNSProof.Host, session.DNSProof.Status, session.DNSProof.LatencyMs
	if dnsMode == "" { dnsMode = profile.DNSMode }; if dnsHost == "" { dnsHost = profile.DNSHost }; if dnsStatus == "" { dnsStatus = "not-proven" }
	actualExitStatus, actualExit, actualExitTested := "not-connected", "", ""
	if session.Connected {
		actualExitStatus = "unproven"
		if raw, found := homeExitProofs.Load(a); found { if proof, valid := raw.(homeExitProof); valid && proof.SessionID == session.ID && proof.IP != "" { actualExit = proof.IP; actualExitStatus = "proved"; actualExitTested = proof.At.Format(time.RFC3339) } }
	}
	warnings := make([]string, 0, 4)
	if strings.TrimSpace(lastError) != "" { warnings = append(warnings, strings.TrimSpace(lastError)) }
	if session.Connected && actualExitStatus != "proved" { warnings = append(warnings, "actual public exit is not proven for this live session") }
	if session.Connected && dnsStatus != "passed" { warnings = append(warnings, "selected DNS is not yet proven for this live session") }
	if fallback != "" { warnings = append(warnings, "fallback: "+fallback) }
	return homeSummaryResponse{NodeID:profile.ID,NodeName:profile.Name,NodeKind:kind,Location:profile.Location,PublicEndpoint:profile.Endpoint,ActualExitIP:actualExit,ActualExitStatus:actualExitStatus,ActualExitTestedAt:actualExitTested,ConnectionPhase:session.Phase,Connected:session.Connected,PathProof:session.PathProof,LogicalMode:logical,RequestedBase:session.RequestedBase,ActualRuntime:session.ActualMode,ActualBase:session.ActualBase,Fallback:fallback,DNSMode:dnsMode,DNSHost:dnsHost,DNSLatencyMs:dnsLatency,DNSStatus:dnsStatus,NodeLatencyMs:profile.LatencyMedianMs,NodeLatencySamples:profile.LatencySamples,LANAccess:profile.HomeLANAccess,KillSwitch:profile.KillSwitchPolicy,EffectiveMTU:profile.EffectiveMTU,EffectiveMTUSource:profile.EffectiveMTUSource,IPv6Mode:profile.IPv6Mode,AutoConnect:profile.AutoConnect,Warnings:warnings}
}
