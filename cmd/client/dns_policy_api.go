package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"

	"router-vpn/internal/common"
)

type dnsPolicyRequest struct {
	Mode       string `json:"mode"`
	Protocol   string `json:"protocol,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	Path       string `json:"path,omitempty"`
}

type dnsPolicyPreset struct {
	Name       string `json:"name"`
	Family     string `json:"family"`
	Host       string `json:"host"`
	ServerName string `json:"server_name,omitempty"`
}

type dnsPolicyResponse struct {
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
	selected := a.profiles.SelectedID
	profile, ok := a.profileByIDLocked(selected)
	busy := profileSettingsBusy(a.state.Connected, a.state.Phase)
	a.mu.Unlock()
	if !ok {
		http.Error(w, "add and select your home router first", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(strings.TrimSpace(profile.NodeKind), "external") || profile.External != nil {
		http.Error(w, "Router VPN DNS policy applies only to Router VPN home nodes; external exits own their own DNS runtime", http.StatusConflict)
		return
	}

	if r.Method == http.MethodGet {
		writeDNSPolicy(w, profile)
		return
	}
	if busy {
		http.Error(w, "disconnect before changing DNS policy so the next tunnel starts with one coherent resolver configuration", http.StatusConflict)
		return
	}
	var request dnsPolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&request); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	updated, err := applyDNSPolicyToProfile(profile, request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "disconnect before changing DNS policy", http.StatusConflict)
		return
	}
	found := false
	oldProfile := profile
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == selected {
			oldProfile = a.profiles.Profiles[i]
			a.profiles.Profiles[i] = updated
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		http.Error(w, "selected router disappeared", http.StatusConflict)
		return
	}
	err = a.persistProfilesLocked()
	if err != nil {
		for i := range a.profiles.Profiles {
			if a.profiles.Profiles[i].ID == selected {
				a.profiles.Profiles[i] = oldProfile
				break
			}
		}
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeDNSPolicy(w, updated)
}

func writeDNSPolicy(w http.ResponseWriter, profile common.RouterProfile) {
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
	if response.Mode == "" {
		response.Mode = "home"
	}
	if response.Protocol == "" {
		response.Protocol = "udp"
	}
	w.Header().Set("content-type", "application/json")
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
