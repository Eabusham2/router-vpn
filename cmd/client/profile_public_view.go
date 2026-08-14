package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"router-vpn/internal/common"
)

type publicExternalNode struct {
	Protocol         string `json:"protocol"`
	ExpectedPublicIP string `json:"expected_public_ip,omitempty"`
}

type publicProfile struct {
	SchemaVersion int    `json:"schema_version"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	NodeKind      string `json:"node_kind"`
	External      *publicExternalNode `json:"external,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	RouterAPI     string `json:"router_api,omitempty"`
	AdGuardIPv4   string `json:"adguard_ipv4,omitempty"`
	AdGuardIPv6   string `json:"adguard_ipv6,omitempty"`
	SocksHost     string `json:"socks_host,omitempty"`
	SocksPort     int    `json:"socks_port,omitempty"`
	BaseTunnel    string `json:"base_tunnel,omitempty"`
	BaseFallback  bool   `json:"base_fallback,omitempty"`
	CustomLayers  []string `json:"custom_layers,omitempty"`
	HomeLANAccess bool     `json:"home_lan_access"`
	HomeLANCIDRs  []string `json:"home_lan_cidrs,omitempty"`
	KillSwitchPolicy string `json:"kill_switch_policy,omitempty"`
	IPv6Mode      string `json:"ipv6_mode,omitempty"`
	StartupMode   string `json:"startup_mode,omitempty"`
	AutoConnect   bool   `json:"auto_connect,omitempty"`
	MultihopEnabled bool   `json:"multihop_enabled,omitempty"`
	MultihopEntryID string `json:"multihop_entry_id,omitempty"`
	MultihopExitID  string `json:"multihop_exit_id,omitempty"`
	MTUPolicy       string `json:"mtu_policy,omitempty"`
	ManualMTU       int    `json:"manual_mtu,omitempty"`
	EffectiveMTU    int    `json:"effective_mtu,omitempty"`
	EffectiveMTUSource string `json:"effective_mtu_source,omitempty"`
	EffectiveMTUPathKey string `json:"effective_mtu_path_key,omitempty"`
	EffectiveUnderlayPMTU int `json:"effective_underlay_pmtu,omitempty"`
	EffectiveMTUTestedAt string `json:"effective_mtu_tested_at,omitempty"`
	DiagnosticsEnabled bool `json:"diagnostics_enabled,omitempty"`
	DiagnosticsRetentionDays int `json:"diagnostics_retention_days,omitempty"`
	ShareDiagnostics bool `json:"share_diagnostics,omitempty"`
	TelemetryEnabled bool `json:"telemetry_enabled,omitempty"`
	Location  string  `json:"location,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
	UseCount  int     `json:"use_count,omitempty"`
	LastUsedAt string  `json:"last_used_at,omitempty"`
	LatencySamples int `json:"latency_samples,omitempty"`
	LatencyMinMs float64 `json:"latency_min_ms,omitempty"`
	LatencyMedianMs float64 `json:"latency_median_ms,omitempty"`
	LatencyTrimmedMeanMs float64 `json:"latency_trimmed_mean_ms,omitempty"`
	LatencyAverageMs float64 `json:"latency_average_ms,omitempty"`
	LatencyP90Ms float64 `json:"latency_p90_ms,omitempty"`
	LatencyMaxMs float64 `json:"latency_max_ms,omitempty"`
	LatencyLastTest string `json:"latency_last_test,omitempty"`
	PublicIP string `json:"public_ip,omitempty"`
	DNSMode string `json:"dns_mode,omitempty"`
	DNSProtocol string `json:"dns_protocol,omitempty"`
	DNSHost string `json:"dns_host,omitempty"`
	DNSPort int `json:"dns_port,omitempty"`
	DNSServerName string `json:"dns_server_name,omitempty"`
	DNSPath string `json:"dns_path,omitempty"`
	FastestDNSHost string `json:"fastest_dns_host,omitempty"`
	FastestDNSName string `json:"fastest_dns_name,omitempty"`
	FastestDNSLatencyMs float64 `json:"fastest_dns_latency_ms,omitempty"`
	DNSResults []common.DNSBenchmarkResult `json:"dns_results,omitempty"`
	Editable bool `json:"editable"`
}

type publicProfileStore struct {
	SchemaVersion int             `json:"schema_version"`
	SelectedID    string          `json:"selected_id"`
	Profiles      []publicProfile `json:"profiles"`
}

func publicProfileFor(p common.RouterProfile) publicProfile {
	kind := strings.ToLower(strings.TrimSpace(p.NodeKind))
	if kind == "" { kind = "router-vpn" }
	out := publicProfile{
		SchemaVersion:p.SchemaVersion, ID:p.ID, Name:p.Name, NodeKind:kind,
		Endpoint:p.Endpoint, RouterAPI:p.RouterAPI, AdGuardIPv4:p.AdGuardIPv4, AdGuardIPv6:p.AdGuardIPv6,
		SocksHost:p.SocksHost, SocksPort:p.SocksPort, BaseTunnel:p.BaseTunnel, BaseFallback:p.BaseFallback,
		CustomLayers:append([]string(nil),p.CustomLayers...), HomeLANAccess:p.HomeLANAccess, HomeLANCIDRs:append([]string(nil),p.HomeLANCIDRs...),
		KillSwitchPolicy:p.KillSwitchPolicy, IPv6Mode:p.IPv6Mode, StartupMode:p.StartupMode, AutoConnect:p.AutoConnect,
		MultihopEnabled:p.MultihopEnabled, MultihopEntryID:p.MultihopEntryID, MultihopExitID:p.MultihopExitID,
		MTUPolicy:p.MTUPolicy, ManualMTU:p.ManualMTU, EffectiveMTU:p.EffectiveMTU, EffectiveMTUSource:p.EffectiveMTUSource,
		EffectiveMTUPathKey:p.EffectiveMTUPathKey, EffectiveUnderlayPMTU:p.EffectiveUnderlayPMTU, EffectiveMTUTestedAt:p.EffectiveMTUTestedAt,
		DiagnosticsEnabled:p.DiagnosticsEnabled, DiagnosticsRetentionDays:p.DiagnosticsRetentionDays, ShareDiagnostics:p.ShareDiagnostics, TelemetryEnabled:p.TelemetryEnabled,
		Location:p.Location, Latitude:p.Latitude, Longitude:p.Longitude, UseCount:p.UseCount, LastUsedAt:p.LastUsedAt,
		LatencySamples:p.LatencySamples, LatencyMinMs:p.LatencyMinMs, LatencyMedianMs:p.LatencyMedianMs,
		LatencyTrimmedMeanMs:p.LatencyTrimmedMeanMs, LatencyAverageMs:p.LatencyAverageMs, LatencyP90Ms:p.LatencyP90Ms, LatencyMaxMs:p.LatencyMaxMs, LatencyLastTest:p.LatencyLastTest,
		PublicIP:p.PublicIP, DNSMode:p.DNSMode, DNSProtocol:p.DNSProtocol, DNSHost:p.DNSHost, DNSPort:p.DNSPort, DNSServerName:p.DNSServerName, DNSPath:p.DNSPath,
		FastestDNSHost:p.FastestDNSHost, FastestDNSName:p.FastestDNSName, FastestDNSLatencyMs:p.FastestDNSLatencyMs, DNSResults:append([]common.DNSBenchmarkResult(nil),p.DNSResults...),
		Editable:kind=="router-vpn",
	}
	if kind == "external" && p.External != nil {
		out.External=&publicExternalNode{Protocol:p.External.Protocol,ExpectedPublicIP:p.External.ExpectedPublicIP}
		// External nodes are data-plane peers, not Router VPN admin/control nodes.
		out.RouterAPI="";out.AdGuardIPv4="";out.AdGuardIPv6="";out.SocksHost="";out.SocksPort=0;out.BaseTunnel="";out.BaseFallback=false;out.CustomLayers=nil
	}
	return out
}

func publicProfileStoreFor(store common.RouterProfileStore) publicProfileStore {
	out:=publicProfileStore{SchemaVersion:store.SchemaVersion,SelectedID:store.SelectedID,Profiles:make([]publicProfile,0,len(store.Profiles))}
	for _,p:=range store.Profiles{out.Profiles=append(out.Profiles,publicProfileFor(p))}
	return out
}

func (a *app) listPublicNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method!=http.MethodGet{http.Error(w,"GET only",http.StatusMethodNotAllowed);return}
	a.mu.Lock();store:=a.profiles;a.mu.Unlock()
	w.Header().Set("content-type","application/json")
	w.Header().Set("cache-control","no-store")
	_ = json.NewEncoder(w).Encode(publicProfileStoreFor(store))
}
