package common

const (
	RouterProfileSchemaVersion = 3
	RouterProfileStoreVersion  = 3
)

type Mode struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Protection      string   `json:"protection"`
	Engine          string   `json:"engine"`
	Maturity        string   `json:"maturity"`
	PingMinMs       float64  `json:"ping_min_ms"`
	PingMaxMs       float64  `json:"ping_max_ms"`
	TrafficMinPct   float64  `json:"traffic_min_pct"`
	TrafficMaxPct   float64  `json:"traffic_max_pct"`
	SpeedLossMinPct float64  `json:"speed_loss_min_pct"`
	SpeedLossMaxPct float64  `json:"speed_loss_max_pct"`
	MTU             int      `json:"mtu"`
	Command         []string `json:"command"`
	StopCommand     []string `json:"stop_command"`
	CheckCommand    []string `json:"check_command"`
	AutoEligible    bool     `json:"auto_eligible"`
	DAITASupported  bool     `json:"daita_supported"`
	JumboSupported  bool     `json:"jumbo_supported"`
	Layers          []string `json:"layers,omitempty"`
	SmartSimplify   []string `json:"smart_simplify,omitempty"`
	Recommended     bool     `json:"recommended,omitempty"`
}

type ModeStatus struct {
	Mode
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type DNSBenchmarkResult struct {
	Name      string  `json:"name"`
	Address   string  `json:"address"`
	Family    string  `json:"family,omitempty"`
	LatencyMs float64 `json:"latency_ms,omitempty"`
	Working   bool    `json:"working"`
}

// ExternalWireGuardConfig is private node data for a non-Router-VPN WireGuard
// peer. These values may contain credentials and therefore belong only in the
// separately linked private profile store, never in generic installers.
type ExternalWireGuardConfig struct {
	PrivateKey   string   `json:"private_key"`
	Addresses    []string `json:"addresses"`
	PeerPublicKey string  `json:"peer_public_key"`
	PresharedKey string   `json:"preshared_key,omitempty"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	DNS          []string `json:"dns,omitempty"`
	MTU          int      `json:"mtu,omitempty"`
}

// ExternalOpenVPNConfig stores an imported .ovpn profile as private node data.
// Runtime support is deliberately separate: accepting/persisting the profile
// must never make the UI claim that an OpenVPN dataplane is available.
type ExternalOpenVPNConfig struct {
	Config   string `json:"config"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type ExternalShadowsocksConfig struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

type ExternalSOCKS5Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// ExternalNodeConfig is a tagged union. Exactly one protocol-specific block is
// accepted. This avoids a generic map of arbitrary launcher arguments and makes
// imported external nodes auditable before a runtime adapter is allowed to use
// their private credentials.
type ExternalNodeConfig struct {
	Protocol    string                     `json:"protocol"`
	WireGuard   *ExternalWireGuardConfig   `json:"wireguard,omitempty"`
	OpenVPN     *ExternalOpenVPNConfig     `json:"openvpn,omitempty"`
	Shadowsocks *ExternalShadowsocksConfig `json:"shadowsocks,omitempty"`
	SOCKS5      *ExternalSOCKS5Config      `json:"socks5,omitempty"`
}

type RouterProfile struct {
	// SchemaVersion is bumped only for persisted node-profile semantics. Older
	// files with a missing/zero version are migrated in the client before write.
	SchemaVersion int `json:"schema_version,omitempty"`

	ID            string `json:"id"`
	Name          string `json:"name"`
	NodeKind      string `json:"node_kind,omitempty"` // router-vpn | external
	External      *ExternalNodeConfig `json:"external,omitempty"`
	NodeProofID   string `json:"node_proof_id,omitempty"`
	Endpoint      string `json:"endpoint"`
	RouterAPI     string `json:"router_api"`
	APIToken      string `json:"api_token"`
	AdGuardIPv4   string `json:"adguard_ipv4"`
	AdGuardIPv6   string `json:"adguard_ipv6"`
	SocksHost     string `json:"socks_host"`
	SocksPort     int    `json:"socks_port"`
	SocksUsername string `json:"socks_username"`
	SocksPassword string `json:"socks_password"`
	DAITAHost     string `json:"daita_host"`
	DAITAPort     int    `json:"daita_port"`
	DAITARateKbps int    `json:"daita_rate_kbps"`
	BaseTunnel    string `json:"base_tunnel,omitempty"`
	BaseFallback  bool   `json:"base_fallback,omitempty"`
	CustomLayers  []string `json:"custom_layers,omitempty"`

	// Network policy is persisted so every platform preserves the same user
	// intent. A field being present here is never proof that its platform runtime
	// adapter is implemented.
	HomeLANAccess bool     `json:"home_lan_access,omitempty"`
	HomeLANCIDRs  []string `json:"home_lan_cidrs,omitempty"`
	KillSwitch    bool     `json:"kill_switch,omitempty"` // legacy compatibility
	KillSwitchPolicy string `json:"kill_switch_policy,omitempty"`
	IPv6Mode      string   `json:"ipv6_mode,omitempty"`
	StartupMode   string   `json:"startup_mode,omitempty"`
	AutoConnect   bool     `json:"auto_connect,omitempty"`

	// Multihop intent is shared across platforms. Runtime adapters still fail
	// closed whenever a requested platform/hop combination is not implemented.
	MultihopEnabled bool   `json:"multihop_enabled,omitempty"`
	MultihopEntryID string `json:"multihop_entry_id,omitempty"`
	MultihopExitID  string `json:"multihop_exit_id,omitempty"`

	// MTU policy distinguishes the user's choice from observed/applied state.
	// Auto mode records the exact path-context key and underlay PMTU used to
	// choose an effective MTU so UIs can distinguish auto/manual/default rather
	// than displaying a number with no provenance.
	MTUPolicy             string `json:"mtu_policy,omitempty"`
	ManualMTU             int    `json:"manual_mtu,omitempty"`
	EffectiveMTU          int    `json:"effective_mtu,omitempty"`
	EffectiveMTUSource    string `json:"effective_mtu_source,omitempty"`
	EffectiveMTUPathKey   string `json:"effective_mtu_path_key,omitempty"`
	EffectiveUnderlayPMTU int    `json:"effective_underlay_pmtu,omitempty"`
	EffectiveMTUTestedAt  string `json:"effective_mtu_tested_at,omitempty"`

	// Diagnostics/privacy preferences are deliberately local and opt-in. They do
	// not enable telemetry merely by existing in the shared schema.
	DiagnosticsEnabled       bool `json:"diagnostics_enabled,omitempty"`
	DiagnosticsRetentionDays int  `json:"diagnostics_retention_days,omitempty"`
	ShareDiagnostics         bool `json:"share_diagnostics,omitempty"`
	TelemetryEnabled         bool `json:"telemetry_enabled,omitempty"`

	// PathProbeURL is a private, node-specific proof endpoint used by Router VPN
	// nodes to distinguish "the Internet works" from "the selected node works".
	// External protocols use protocol-specific validation until an equivalent
	// cryptographic/identity proof is available.
	PathProbeURL string `json:"path_probe_url,omitempty"`

	// Optional location metadata is user-editable. It lets the local UI display
	// multiple self-hosted or custom external nodes on a map without sending the
	// node list to a third-party map/geolocation service.
	Location  string  `json:"location,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`

	// Persistent local selection/latency metadata. Latency testing uses at least
	// 50 TCP handshakes when requested and records ordinary average plus
	// outlier-resistant median and trimmed-mean values.
	UseCount             int     `json:"use_count,omitempty"`
	LastUsedAt           string  `json:"last_used_at,omitempty"`
	LatencySamples       int     `json:"latency_samples,omitempty"`
	LatencyMinMs         float64 `json:"latency_min_ms,omitempty"`
	LatencyMedianMs      float64 `json:"latency_median_ms,omitempty"`
	LatencyTrimmedMeanMs float64 `json:"latency_trimmed_mean_ms,omitempty"`
	LatencyAverageMs     float64 `json:"latency_average_ms,omitempty"`
	LatencyP90Ms         float64 `json:"latency_p90_ms,omitempty"`
	LatencyMaxMs         float64 `json:"latency_max_ms,omitempty"`
	LatencyLastTest      string  `json:"latency_last_test,omitempty"`

	// Last public exit address observed while this profile was active.
	PublicIP string `json:"public_ip,omitempty"`

	// DNS is applied inside the selected VPN path. DNSMode values are home,
	// fastest, custom, doh, dot, doh3, and rescue. Home AdGuard is the default for
	// Router VPN nodes; external-node adapters must not claim Home AdGuard unless
	// they can actually route to it.
	DNSMode             string               `json:"dns_mode,omitempty"`
	DNSProtocol         string               `json:"dns_protocol,omitempty"`
	DNSHost             string               `json:"dns_host,omitempty"`
	DNSPort             int                  `json:"dns_port,omitempty"`
	DNSServerName       string               `json:"dns_server_name,omitempty"`
	DNSPath             string               `json:"dns_path,omitempty"`
	FastestDNSHost      string               `json:"fastest_dns_host,omitempty"`
	FastestDNSName      string               `json:"fastest_dns_name,omitempty"`
	FastestDNSLatencyMs float64              `json:"fastest_dns_latency_ms,omitempty"`
	DNSResults          []DNSBenchmarkResult `json:"dns_results,omitempty"`
}

type RouterProfileStore struct {
	SchemaVersion int             `json:"schema_version,omitempty"`
	SelectedID    string          `json:"selected_id"`
	Profiles      []RouterProfile `json:"profiles"`
}

type ClientConfig struct {
	HomeEndpoint    string `json:"home_endpoint"`
	Listen          string `json:"listen"`
	HealthURL       string `json:"health_url"`
	AutoTestSeconds int    `json:"auto_test_seconds"`
	ModesFile       string `json:"modes_file"`
	StateFile       string `json:"state_file"`
	ScriptsDir      string `json:"scripts_dir"`
	ProfilesFile    string `json:"profiles_file"`

	// Legacy single-router fields. They are imported into profiles_file on first run.
	RouterAPI     string `json:"router_api,omitempty"`
	APIToken      string `json:"api_token,omitempty"`
	AdGuardIPv4   string `json:"adguard_ipv4,omitempty"`
	AdGuardIPv6   string `json:"adguard_ipv6,omitempty"`
	SocksHost     string `json:"socks_host,omitempty"`
	SocksPort     int    `json:"socks_port,omitempty"`
	SocksUsername string `json:"socks_username,omitempty"`
	SocksPassword string `json:"socks_password,omitempty"`
	DAITAHost     string `json:"daita_host,omitempty"`
	DAITAPort     int    `json:"daita_port,omitempty"`
	DAITARateKbps int    `json:"daita_rate_kbps,omitempty"`
}

type ForwardRequest struct {
	Protocol   string `json:"protocol"`
	From       int    `json:"from"`
	To         int    `json:"to"`
	TargetPort int    `json:"target_port"`
	DMZ        bool   `json:"dmz"`
}
