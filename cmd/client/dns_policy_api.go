package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"

	"router-vpn/internal/common"
)

type dnsPolicyRequest struct {
	ProfileID    string `json:"profile_id,omitempty"`
	ProfileToken string `json:"profile_token,omitempty"`
	Mode         string `json:"mode"`
	Protocol     string `json:"protocol,omitempty"`
	Host         string `json:"host,omitempty"`
	Port         int    `json:"port,omitempty"`
	ServerName   string `json:"server_name,omitempty"`
	Path         string `json:"path,omitempty"`
}

type dnsPolicyPreset struct {
	Name       string `json:"name"`
	Family     string `json:"family"`
	Host       string `json:"host"`
	ServerName string `json:"server_name,omitempty"`
}

type dnsPolicyResponse struct {
	ProfileID           string                      `json:"profile_id"`
	ProfileToken        string                      `json:"profile_token"`
	NodeKind            string                      `json:"node_kind"`
	Mode                string                      `json:"mode"`
	Protocol            string                      `json:"protocol"`
	Host                string                      `json:"host"`
	Port                int                         `json:"port"`
	ServerName          string                      `json:"server_name,omitempty"`
	Path                string                      `json:"path,omitempty"`
	FastestDNSHost      string                      `json:"fastest_dns_host,omitempty"`
	FastestDNSName      string                      `json:"fastest_dns_name,omitempty"`
	FastestDNSLatencyMs float64                     `json:"fastest_dns_latency_ms,omitempty"`
	Results             []common.DNSBenchmarkResult `json:"results,omitempty"`
	Presets             []dnsPolicyPreset           `json:"presets"`
	Note                string                      `json:"note"`
}

func registerDNSPolicyRoute(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/dns/policy", a.dnsPolicy)
}

func (a *app) dnsPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		release, err := a.beginMutationOperation(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		defer release()
	}

	a.mu.Lock()
	profile, entry, ok := a.dnsPolicySelectionLocked()
	a.mu.Unlock()
	if !ok {
		http.Error(w, "add and select a node first", http.StatusBadRequest)
		return
	}
	token := dnsPolicySelectionToken(profile, entry)
	if r.Method == http.MethodGet {
		writeDNSPolicy(w, profile, entry)
		return
	}
	var request dnsPolicyRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid DNS policy", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "one DNS policy object is required", http.StatusBadRequest)
		return
	}
	// External editors must identify the selected private source and its saved
	// entry. Older Router-only clients remain compatible; every supplied
	// revision is checked, and both paths recheck the capture before saving.
	if externalDNSProfile(profile) || request.ProfileID != "" || request.ProfileToken != "" {
		if request.ProfileID != profile.ID || request.ProfileToken == "" || request.ProfileToken != token {
			http.Error(w, "selected node, entry or DNS policy changed; refresh DNS settings", http.StatusConflict)
			return
		}
	}
	updated, err := applyCapturedDNSPolicy(profile, entry, request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	current, currentEntry, exists := a.dnsPolicySelectionLocked()
	if !exists || current.ID != profile.ID || dnsPolicySelectionToken(current, currentEntry) != token ||
		a.closing || r.Context().Err() != nil || profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "node, entry or connection changed; refresh DNS settings when disconnected", http.StatusConflict)
		return
	}
	// Measurement and display changes outside the revision belong to the
	// current profile. A DNS edit must never replace their object or secrets.
	currentUpdate := cloneRouterProfile(current)
	copyDNSPolicy(&currentUpdate, updated)
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != current.ID {
			continue
		}
		a.profiles.Profiles[i] = currentUpdate
		err = a.persistProfilesLocked()
		if err != nil {
			a.profiles.Profiles[i] = current
		}
		break
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "could not save DNS policy", http.StatusInternalServerError)
		return
	}
	cancelPendingStartupPolicy(a)
	writeDNSPolicy(w, currentUpdate, currentEntry)
}

func writeDNSPolicy(w http.ResponseWriter, profile, entry common.RouterProfile) {
	results := append([]common.DNSBenchmarkResult(nil), profile.DNSResults...)
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Working != results[j].Working {
			return results[i].Working
		}
		if !results[i].Working {
			return results[i].Name < results[j].Name
		}
		if results[i].LatencyMs == results[j].LatencyMs {
			return results[i].Name < results[j].Name
		}
		return results[i].LatencyMs < results[j].LatencyMs
	})
	response := dnsPolicyResponse{
		ProfileID: profile.ID, ProfileToken: dnsPolicySelectionToken(profile, entry), NodeKind: "router-vpn",
		Mode:                strings.ToLower(strings.TrimSpace(profile.DNSMode)),
		Protocol:            strings.ToLower(strings.TrimSpace(profile.DNSProtocol)),
		Host:                profile.DNSHost,
		Port:                profile.DNSPort,
		ServerName:          profile.DNSServerName,
		Path:                profile.DNSPath,
		FastestDNSHost:      profile.FastestDNSHost,
		FastestDNSName:      profile.FastestDNSName,
		FastestDNSLatencyMs: profile.FastestDNSLatencyMs,
		Results:             results,
		Presets:             dnsPolicyPresets(),
		Note:                "DNS benchmark values are real A/AAAA DNS query RTTs measured from the selected home node; saved policy is applied on the next connection and runtime proof is still required.",
	}
	if externalDNSProfile(profile) {
		response.NodeKind = "external"
		response.Note = "The saved DNS policy belongs to this external node and its captured entry. It is applied on the next native connection, which still requires fresh DNS proof. Stored samples do not establish current-path performance."
		if response.Mode == "rescue" && profile.External != nil && profile.External.Protocol != "tor-bridge" {
			// Rescue is an explicit named preset in the shared runtime. Historical
			// leftover custom fields must not mislabel the resolver it will use.
			response.Protocol, response.Host, response.Port = "https", "1.1.1.1", 443
			response.ServerName, response.Path = "cloudflare-dns.com", "/dns-query"
		}
		if (response.Mode == "home" || response.Mode == "") && profile.External != nil && profile.External.Protocol == "tor-bridge" {
			response.Note += " Tor bridge DNS needs Custom TCP, DoT, DoH or explicit Rescue through its circuit."
		} else if (response.Mode == "home" || response.Mode == "") && entry.ID == "" {
			response.Note += " Home AdGuard needs a paired Router VPN entry before this path can connect; choose an explicit resolver for a direct external connection."
		}
	}
	if response.Mode == "" {
		response.Mode = "home"
	}
	if response.Protocol == "" {
		response.Protocol = "udp"
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(response)
}

func applyDNSPolicyToProfile(profile common.RouterProfile, request dnsPolicyRequest) (common.RouterProfile, error) {
	mode := strings.ToLower(strings.TrimSpace(request.Mode))
	if mode == "" {
		return profile, errors.New("DNS mode is required")
	}
	protocol := strings.ToLower(strings.TrimSpace(request.Protocol))
	host := strings.TrimSpace(request.Host)
	serverName := strings.TrimSpace(request.ServerName)
	path := strings.TrimSpace(request.Path)
	port := request.Port

	switch mode {
	case "home":
		if protocol != "" && protocol != "udp" {
			return profile, errors.New("this Router Home preset uses UDP port 53; select Custom TCP, DoT, DoH or DoH3 explicitly to use another transport")
		}
		host = strings.TrimSpace(profile.AdGuardIPv4)
		if host == "" {
			host = strings.TrimSpace(profile.AdGuardIPv6)
		}
		if host == "" {
			return profile, errors.New("Home AdGuard address is missing from this Router VPN node")
		}
		protocol, port, serverName, path = "udp", 53, "", ""
	case "fastest":
		host = strings.TrimSpace(profile.FastestDNSHost)
		if host == "" {
			return profile, errors.New("no measured fastest resolver is stored; connect this home node and run DNS Retest first")
		}
		protocol, port, serverName, path = "udp", 53, "", ""
	case "custom":
		if protocol == "" {
			protocol = "udp"
		}
		if protocol != "udp" && protocol != "tcp" {
			return profile, errors.New("Custom DNS protocol must be UDP or TCP")
		}
		if port == 0 {
			port = 53
		}
	case "dot":
		protocol = "tls"
		if port == 0 {
			port = 853
		}
	case "doh":
		protocol = "https"
		if port == 0 {
			port = 443
		}
		if path == "" {
			path = "/dns-query"
		}
	case "doh3":
		protocol = "h3"
		if port == 0 {
			port = 443
		}
		if path == "" {
			path = "/dns-query"
		}
	case "rescue":
		protocol = "rescue"
		if host == "" {
			host = strings.TrimSpace(profile.FastestDNSHost)
		}
		if host == "" {
			host = "1.1.1.1"
		}
		if port == 0 {
			port = 443
		}
		if path == "" {
			path = "/dns-query"
		}
	default:
		return profile, errors.New("DNS mode must be home, fastest, custom, dot, doh, doh3, or rescue")
	}

	if mode != "home" && mode != "fastest" {
		if host == "" {
			return profile, errors.New("DNS host is required for this policy")
		}
		normalized, err := normalizeEndpoint(host)
		if err != nil {
			return profile, errors.New("invalid DNS host")
		}
		host = normalized
	}
	if port < 1 || port > 65535 {
		return profile, errors.New("DNS port must be between 1 and 65535")
	}
	if mode == "dot" || mode == "doh" || mode == "doh3" {
		if serverName == "" {
			serverName = inferDNSServerName(host)
		}
		if serverName == "" {
			return profile, errors.New("encrypted DNS to an IP address requires a TLS server name")
		}
		if _, err := normalizeEndpoint(serverName); err != nil || net.ParseIP(serverName) != nil {
			return profile, errors.New("DNS TLS server name must be a hostname")
		}
	}
	if path != "" && !strings.HasPrefix(path, "/") {
		return profile, errors.New("DNS HTTPS path must start with /")
	}

	profile.DNSMode = mode
	profile.DNSProtocol = protocol
	profile.DNSHost = host
	profile.DNSPort = port
	profile.DNSServerName = serverName
	profile.DNSPath = path
	return profile, nil
}

func inferDNSServerName(host string) string {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	known := map[string]string{
		"1.1.1.1": "cloudflare-dns.com", "1.0.0.1": "cloudflare-dns.com",
		"2606:4700:4700::1111": "cloudflare-dns.com", "2606:4700:4700::1001": "cloudflare-dns.com",
		"8.8.8.8": "dns.google", "8.8.4.4": "dns.google",
		"2001:4860:4860::8888": "dns.google", "2001:4860:4860::8844": "dns.google",
		"9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net",
		"2620:fe::fe": "dns.quad9.net", "2620:fe::9": "dns.quad9.net",
	}
	if value := known[host]; value != "" {
		return value
	}
	if net.ParseIP(host) == nil && strings.Contains(host, ".") {
		return host
	}
	return ""
}

func dnsPolicyPresets() []dnsPolicyPreset {
	return []dnsPolicyPreset{
		{Name: "Cloudflare IPv4", Family: "ipv4", Host: "1.1.1.1", ServerName: "cloudflare-dns.com"},
		{Name: "Cloudflare IPv6", Family: "ipv6", Host: "2606:4700:4700::1111", ServerName: "cloudflare-dns.com"},
		{Name: "Google IPv4", Family: "ipv4", Host: "8.8.8.8", ServerName: "dns.google"},
		{Name: "Google IPv6", Family: "ipv6", Host: "2001:4860:4860::8888", ServerName: "dns.google"},
		{Name: "Quad9 IPv4", Family: "ipv4", Host: "9.9.9.9", ServerName: "dns.quad9.net"},
		{Name: "Quad9 IPv6", Family: "ipv6", Host: "2620:fe::fe", ServerName: "dns.quad9.net"},
	}
}
