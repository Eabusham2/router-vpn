package common

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

type RouterProfile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
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

	// DNS is applied inside the selected VPN path. DNSMode values are fastest,
	// home, custom, doh, dot, doh3, and rescue.
	DNSMode             string  `json:"dns_mode,omitempty"`
	DNSProtocol         string  `json:"dns_protocol,omitempty"`
	DNSHost             string  `json:"dns_host,omitempty"`
	DNSPort             int     `json:"dns_port,omitempty"`
	DNSServerName       string  `json:"dns_server_name,omitempty"`
	DNSPath             string  `json:"dns_path,omitempty"`
	FastestDNSHost      string  `json:"fastest_dns_host,omitempty"`
	FastestDNSName      string  `json:"fastest_dns_name,omitempty"`
	FastestDNSLatencyMs float64 `json:"fastest_dns_latency_ms,omitempty"`
}

type RouterProfileStore struct {
	SelectedID string          `json:"selected_id"`
	Profiles   []RouterProfile `json:"profiles"`
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
