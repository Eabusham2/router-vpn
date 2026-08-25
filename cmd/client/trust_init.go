package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

const defaultPrivatePathProbeURL = "http://10.77.0.1:8787/health"
const legacyPublicHealthURL = "https://connectivitycheck.gstatic.com/generate_204"

// init migrates the historical public-Internet health probe before main reads
// client.json. A generic Internet 2xx must never be enough to claim Router VPN
// is connected. The default proof target is reachable only through the private
// Router VPN path. Tests skip the startup write and exercise the helpers below.
func init() {
	if strings.HasSuffix(strings.ToLower(os.Args[0]), ".test") {
		return
	}
	path := os.Getenv("HOMEVPN_CLIENT_CONFIG")
	if strings.TrimSpace(path) == "" {
		path = "./client.json"
	}
	if err := migrateClientTrustConfig(path); err != nil {
		panic(fmt.Sprintf("Router VPN cannot establish a safe path-proof configuration: %v", err))
	}
}

func migrateClientTrustConfig(path string) error {
	raw := map[string]any{}
	b, err := readPrivateRegular(path, maxPrivateStoreBytes)
	if err == nil {
		if err := json.Unmarshal(b, &raw); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	current, _ := raw["health_url"].(string)
	current = strings.TrimSpace(current)
	if current != "" && current != legacyPublicHealthURL && trustedPathProbeURL(current) {
		return nil
	}
	raw["health_url"] = defaultPrivatePathProbeURL

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return atomicWritePrivate(path, append(out, '\n'))
}

func trustedPathProbeURL(value string) bool {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".home.arpa") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Public DNS names are deliberately not accepted as connection truth.
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
