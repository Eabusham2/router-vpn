package common

const (
	RouterProfileSchemaVersion = 4
	RouterProfileStoreVersion  = 4
)

type Mode struct {
	ID string `json:"id"`; Name string `json:"name"`; Protection string `json:"protection"`; Engine string `json:"engine"`; Maturity string `json:"maturity"`
	PingMinMs float64 `json:"ping_min_ms"`; PingMaxMs float64 `json:"ping_max_ms"`; TrafficMinPct float64 `json:"traffic_min_pct"`; TrafficMaxPct float64 `json:"traffic_max_pct"`; SpeedLossMinPct float64 `json:"speed_loss_min_pct"`; SpeedLossMaxPct float64 `json:"speed_loss_max_pct"`; MTU int `json:"mtu"`
	Command []string `json:"command"`; StopCommand []string `json:"stop_command"`; CheckCommand []string `json:"check_command"`; AutoEligible bool `json:"auto_eligible"`; DAITASupported bool `json:"daita_supported"`; JumboSupported bool `json:"jumbo_supported"`; Layers []string `json:"layers,omitempty"`; SmartSimplify []string `json:"smart_simplify,omitempty"`; Recommended bool `json:"recommended,omitempty"`
}

type ModeStatus struct { Mode; Available bool `json:"available"`; Reason string `json:"reason,omitempty"` }
type DNSBenchmarkResult struct { Name string `json:"name"`; Address string `json:"address"`; Family string `json:"family,omitempty"`; LatencyMs float64 `json:"latency_ms,omitempty"`; Working bool `json:"working"` }

type ExternalWireGuardConfig struct { PrivateKey string `json:"private_key"`; Addresses []string `json:"addresses"`; PeerPublicKey string `json:"peer_public_key"`; PresharedKey string `json:"preshared_key,omitempty"`; Endpoint string `json:"endpoint"`; AllowedIPs []string `json:"allowed_ips"`; DNS []string `json:"dns,omitempty"`; MTU int `json:"mtu,omitempty"` }
type ExternalOpenVPNConfig struct { Config string `json:"config"`; Username string `json:"username,omitempty"`; Password string `json:"password,omitempty"` }
type ExternalShadowsocksConfig struct { Server string `json:"server"`; Port int `json:"port"`; Method string `json:"method"`; Password string `json:"password"` }
type ExternalSOCKS5Config struct { Host string `json:"host"`; Port int `json:"port"`; Username string `json:"username,omitempty"`; Password string `json:"password,omitempty"` }
type ExternalHTTPConnectConfig struct { Host string `json:"host"`; Port int `json:"port"`; Username string `json:"username,omitempty"`; Password string `json:"password,omitempty"`; TLSServerName string `json:"tls_server_name,omitempty"` }
type ExternalHysteria2Config struct { Server string `json:"server"`; Port int `json:"port"`; Password string `json:"password"`; TLSServerName string `json:"tls_server_name"` }
type ExternalTorBridgeConfig struct { Transport string `json:"transport,omitempty"`; Bridges []string `json:"bridges"`; SocksPort int `json:"socks_port,omitempty"` }

type ExternalNodeConfig struct {
	Protocol string `json:"protocol"`
	ExpectedPublicIP string `json:"expected_public_ip"`
	WireGuard *ExternalWireGuardConfig `json:"wireguard,omitempty"`
	OpenVPN *ExternalOpenVPNConfig `json:"openvpn,omitempty"`
	Shadowsocks *ExternalShadowsocksConfig `json:"shadowsocks,omitempty"`
	SOCKS5 *ExternalSOCKS5Config `json:"socks5,omitempty"`
	HTTPConnect *ExternalHTTPConnectConfig `json:"http_connect,omitempty"`
	HTTPSConnect *ExternalHTTPConnectConfig `json:"https_connect,omitempty"`
	Hysteria2 *ExternalHysteria2Config `json:"hysteria2,omitempty"`
	TorBridge *ExternalTorBridgeConfig `json:"tor_bridge,omitempty"`
}

type RouterProfile struct {
	SchemaVersion int `json:"schema_version,omitempty"`
	ID string `json:"id"`; Name string `json:"name"`; NodeKind string `json:"node_kind,omitempty"`; External *ExternalNodeConfig `json:"external,omitempty"`; NodeProofID string `json:"node_proof_id,omitempty"`
	Endpoint string `json:"endpoint"`; RouterAPI string `json:"router_api"`; APIToken string `json:"api_token"`; AdGuardIPv4 string `json:"adguard_ipv4"`; AdGuardIPv6 string `json:"adguard_ipv6"`; SocksHost string `json:"socks_host"`; SocksPort int `json:"socks_port"`; SocksUsername string `json:"socks_username"`; SocksPassword string `json:"socks_password"`; DAITAHost string `json:"daita_host"`; DAITAPort int `json:"daita_port"`; DAITARateKbps int `json:"daita_rate_kbps"`; BaseTunnel string `json:"base_tunnel,omitempty"`; BaseFallback bool `json:"base_fallback,omitempty"`; CustomLayers []string `json:"custom_layers,omitempty"`; StartLayer string `json:"start_layer,omitempty"`
	HomeLANAccess bool `json:"home_lan_access,omitempty"`; HomeLANCIDRs []string `json:"home_lan_cidrs,omitempty"`; KillSwitch bool `json:"kill_switch,omitempty"`; KillSwitchPolicy string `json:"kill_switch_policy,omitempty"`; IPv6Mode string `json:"ipv6_mode,omitempty"`; StartupMode string `json:"startup_mode,omitempty"`; AutoConnect bool `json:"auto_connect,omitempty"`; AutoRequireEncrypted bool `json:"auto_require_encrypted,omitempty"`; AutoRequireObfuscation bool `json:"auto_require_obfuscation,omitempty"`
	DAITAEnabled bool `json:"daita_enabled,omitempty"`; JumboTUN bool `json:"jumbo_tun,omitempty"`; SocksEnabled bool `json:"socks_enabled,omitempty"`
	MultihopEnabled bool `json:"multihop_enabled,omitempty"`; MultihopEntryID string `json:"multihop_entry_id,omitempty"`; MultihopExitID string `json:"multihop_exit_id,omitempty"`
	MTUPolicy string `json:"mtu_policy,omitempty"`; ManualMTU int `json:"manual_mtu,omitempty"`; EffectiveMTU int `json:"effective_mtu,omitempty"`; EffectiveMTUSource string `json:"effective_mtu_source,omitempty"`; EffectiveMTUPathKey string `json:"effective_mtu_path_key,omitempty"`; EffectiveUnderlayPMTU int `json:"effective_underlay_pmtu,omitempty"`; EffectiveMTUTestedAt string `json:"effective_mtu_tested_at,omitempty"`; EffectiveMTUNetworkFingerprint string `json:"effective_mtu_network_fingerprint,omitempty"`; EffectiveMTUProfileFingerprint string `json:"effective_mtu_profile_fingerprint,omitempty"`; EffectiveMTUMbps float64 `json:"effective_mtu_mbps,omitempty"`; EffectiveMTUMedianRTTMs float64 `json:"effective_mtu_median_rtt_ms,omitempty"`; EffectiveMTUSuccessRatio float64 `json:"effective_mtu_success_ratio,omitempty"`
	DiagnosticsEnabled bool `json:"diagnostics_enabled,omitempty"`; DiagnosticsRetentionDays int `json:"diagnostics_retention_days,omitempty"`; ShareDiagnostics bool `json:"share_diagnostics,omitempty"`; TelemetryEnabled bool `json:"telemetry_enabled,omitempty"`
	PathProbeURL string `json:"path_probe_url,omitempty"`
	Location string `json:"location,omitempty"`; Latitude float64 `json:"latitude,omitempty"`; Longitude float64 `json:"longitude,omitempty"`
	UseCount int `json:"use_count,omitempty"`; LastUsedAt string `json:"last_used_at,omitempty"`; LatencySamples int `json:"latency_samples,omitempty"`; LatencyMinMs float64 `json:"latency_min_ms,omitempty"`; LatencyMedianMs float64 `json:"latency_median_ms,omitempty"`; LatencyTrimmedMeanMs float64 `json:"latency_trimmed_mean_ms,omitempty"`; LatencyAverageMs float64 `json:"latency_average_ms,omitempty"`; LatencyP90Ms float64 `json:"latency_p90_ms,omitempty"`; LatencyMaxMs float64 `json:"latency_max_ms,omitempty"`; LatencyLastTest string `json:"latency_last_test,omitempty"`
	PublicIP string `json:"public_ip,omitempty"`
	DNSMode string `json:"dns_mode,omitempty"`; DNSProtocol string `json:"dns_protocol,omitempty"`; DNSHost string `json:"dns_host,omitempty"`; DNSPort int `json:"dns_port,omitempty"`; DNSServerName string `json:"dns_server_name,omitempty"`; DNSPath string `json:"dns_path,omitempty"`; FastestDNSHost string `json:"fastest_dns_host,omitempty"`; FastestDNSName string `json:"fastest_dns_name,omitempty"`; FastestDNSLatencyMs float64 `json:"fastest_dns_latency_ms,omitempty"`; DNSResults []DNSBenchmarkResult `json:"dns_results,omitempty"`
}

type RouterProfileStore struct { SchemaVersion int `json:"schema_version,omitempty"`; SelectedID string `json:"selected_id"`; Profiles []RouterProfile `json:"profiles"` }

type ClientConfig struct {
	HomeEndpoint string `json:"home_endpoint"`; Listen string `json:"listen"`; HealthURL string `json:"health_url"`; AutoTestSeconds int `json:"auto_test_seconds"`; ModesFile string `json:"modes_file"`; StateFile string `json:"state_file"`; ScriptsDir string `json:"scripts_dir"`; ProfilesFile string `json:"profiles_file"`
	RouterAPI string `json:"router_api,omitempty"`; APIToken string `json:"api_token,omitempty"`; AdGuardIPv4 string `json:"adguard_ipv4,omitempty"`; AdGuardIPv6 string `json:"adguard_ipv6,omitempty"`; SocksHost string `json:"socks_host,omitempty"`; SocksPort int `json:"socks_port,omitempty"`; SocksUsername string `json:"socks_username,omitempty"`; SocksPassword string `json:"socks_password,omitempty"`; DAITAHost string `json:"daita_host,omitempty"`; DAITAPort int `json:"daita_port,omitempty"`; DAITARateKbps int `json:"daita_rate_kbps,omitempty"`
}

type ForwardRequest struct { Protocol string `json:"protocol"`; From int `json:"from"`; To int `json:"to"`; TargetPort int `json:"target_port"`; DMZ bool `json:"dmz"` }