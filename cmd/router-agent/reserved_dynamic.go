package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// init runs before main reads ROUTER_VPN_CONFIG. The config volume is mounted
// read-only, so create a private augmented copy in /tmp instead of mutating the
// user's persistent JSON. This keeps Protected DMZ/forwarding safe when custom
// listener ports were chosen during installation or an older persisted config
// predates a newly protected management listener.
func init() {
	path := os.Getenv("ROUTER_VPN_CONFIG")
	if path == "" {
		path = os.Getenv("HOMEVPN_ROUTER_CONFIG")
	}
	if path == "" {
		path = "/etc/router-vpn/router-agent.json"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return
	}
	reserved := map[int]bool{}
	if raw, ok := doc["reserved_ports"].([]any); ok {
		for _, v := range raw {
			if n, ok := v.(float64); ok && n >= 1 && n <= 65535 {
				reserved[int(n)] = true
			}
		}
	}
	// These fixed/default management and private-control ports are protected on
	// every startup even when the persisted router-agent.json came from an older
	// release that did not list them yet. Custom listener ports are added below
	// from their live generated configuration files.
	for _, p := range []int{
		22,    // SSH
		53,    // DNS / AdGuard service
		80,    // ACME external control
		1080,  // private SOCKS5
		3000,  // AdGuard admin UI
		8786,  // authenticated Setup Center
		8787,  // private router-agent API
		8789,  // loopback read-only admin plane
		8790,  // loopback mutation admin plane
		9443,  // Portainer
		14444, // default OverTLS loopback backend
		45999, // DAITA-like private cover sink
	} {
		reserved[p] = true
	}

	root := filepath.Dir(path)
	for _, conf := range []string{
		filepath.Join(root, "wireguard", "wg0.conf"),
		filepath.Join(root, "awg2", "awg0.conf"),
	} {
		if x, err := os.ReadFile(conf); err == nil {
			for _, m := range regexp.MustCompile(`(?mi)^ListenPort\s*=\s*(\d+)\s*$`).FindAllSubmatch(x, -1) {
				if p, err := strconv.Atoi(string(m[1])); err == nil && p >= 1 && p <= 65535 {
					reserved[p] = true
				}
			}
		}
	}

	addJSONPorts := func(file string) {
		x, err := os.ReadFile(file)
		if err != nil {
			return
		}
		var v map[string]any
		if json.Unmarshal(x, &v) != nil {
			return
		}
		if list, ok := v["inbounds"].([]any); ok {
			for _, item := range list {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				for _, key := range []string{"listen_port", "port"} {
					if n, ok := m[key].(float64); ok && n >= 1 && n <= 65535 {
						reserved[int(n)] = true
					}
				}
			}
		}
	}
	addJSONPorts(filepath.Join(root, "transports", "server.json"))
	addJSONPorts(filepath.Join(root, "xray", "server.json"))

	addScalarPorts := func(file string, keys ...string) {
		x, err := os.ReadFile(file)
		if err != nil {
			return
		}
		var v map[string]any
		if json.Unmarshal(x, &v) != nil {
			return
		}
		for _, key := range keys {
			if n, ok := v[key].(float64); ok && n >= 1 && n <= 65535 {
				reserved[int(n)] = true
			}
		}
	}
	addScalarPorts(filepath.Join(root, "tls", "generated.json"), "ss_v2ray_port", "naive_port")
	addScalarPorts(filepath.Join(root, "aux", "generated.json"), "overtls_port", "overtls_internal_port", "ssr_port")

	if x, err := os.ReadFile(filepath.Join(root, "rosenpass", "server.toml")); err == nil {
		for _, m := range regexp.MustCompile(`(?m)["'](?:0\.0\.0\.0|\[::\]):(\d+)["']`).FindAllSubmatch(x, -1) {
			if p, err := strconv.Atoi(string(m[1])); err == nil && p >= 1 && p <= 65535 {
				reserved[p] = true
			}
		}
	}

	ports := make([]int, 0, len(reserved))
	for p := range reserved {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	values := make([]any, len(ports))
	for i, p := range ports {
		values[i] = p
	}
	doc["reserved_ports"] = values
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	tmp := "/tmp/router-vpn-agent.json"
	if os.WriteFile(tmp, append(out, '\n'), 0o600) == nil {
		os.Setenv("ROUTER_VPN_CONFIG", tmp)
	}

	_ = strings.Builder{}
}
