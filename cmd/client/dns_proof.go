package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type dnsSelection struct {
	Mode       string
	Protocol   string
	Host       string
	Port       int
	ServerName string
	Path       string
}

func expectedDNSSelection(p common.RouterProfile) dnsSelection {
	mode := strings.ToLower(strings.TrimSpace(p.DNSMode))
	if mode == "" {
		mode = "home"
	}
	fastest := strings.TrimSpace(p.FastestDNSHost)
	if fastest == "" {
		fastest = "1.1.1.1"
	}
	host := strings.Trim(strings.TrimSpace(p.DNSHost), "[]")
	if host == "" {
		host = fastest
	}
	protocol := strings.ToLower(strings.TrimSpace(p.DNSProtocol))
	if protocol == "" {
		protocol = "udp"
	}
	port := p.DNSPort
	serverName := strings.TrimSpace(p.DNSServerName)
	path := strings.TrimSpace(p.DNSPath)
	if path == "" {
		path = "/dns-query"
	}

	switch mode {
	case "home":
		host = strings.Trim(strings.TrimSpace(p.AdGuardIPv4), "[]")
		if host == "" {
			host = strings.Trim(strings.TrimSpace(p.AdGuardIPv6), "[]")
		}
		if host == "" {
			host = "10.77.0.1"
		}
		protocol, port, serverName, path = "udp", 53, "", ""
	case "fastest":
		host, protocol, port, serverName, path = fastest, "udp", 53, "", ""
	case "doh":
		protocol = "https"
		if port == 0 {
			port = 443
		}
	case "dot":
		protocol = "tls"
		if port == 0 {
			port = 853
		}
	case "doh3":
		protocol = "h3"
		if port == 0 {
			port = 443
		}
	case "rescue":
		protocol = "rescue"
		if port == 0 {
			port = 443
		}
	default:
		switch protocol {
		case "doh":
			protocol = "https"
		case "dot":
			protocol = "tls"
		case "doh3":
			protocol = "h3"
		}
		if port == 0 {
			switch protocol {
			case "https", "h3":
				port = 443
			case "tls":
				port = 853
			default:
				port = 53
			}
		}
	}
	return dnsSelection{Mode: mode, Protocol: protocol, Host: strings.Trim(host, "[]"), Port: port, ServerName: serverName, Path: path}
}

func clientRoot(a *app) string {
	if value := strings.TrimSpace(os.Getenv("HOMEVPN_ROOT")); value != "" {
		return filepath.Clean(value)
	}
	if a != nil && strings.TrimSpace(a.cfg.ProfilesFile) != "" {
		return filepath.Dir(filepath.Clean(a.cfg.ProfilesFile))
	}
	return "."
}

func kernelDNSMode(mode string) bool {
	switch mode {
	case "wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "max-tls-wg", "max-quic-wg", "max-tls-awg", "max-quic-awg":
		return true
	default:
		return false
	}
}

func runtimeConfigDirs(root, profileID, mode string) []string {
	return []string{
		filepath.Join(root, "run", "profile-"+profileID+"-"+mode),
		filepath.Join(root, "run", "windows", profileID, mode),
	}
}

func parseDNSHint(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key != "" {
			out[key] = value
		}
	}
	return out, nil
}

func hostPortEqual(hint string, selected dnsSelection) bool {
	want := net.JoinHostPort(selected.Host, strconv.Itoa(selected.Port))
	if strings.EqualFold(strings.TrimSpace(hint), want) {
		return true
	}
	// Historical hints wrote IPv4 as host:port without JoinHostPort formatting.
	return strings.EqualFold(strings.TrimSpace(hint), fmt.Sprintf("%s:%d", selected.Host, selected.Port))
}

func verifyKernelDNSRuntime(root, profileID, mode string, selected dnsSelection) error {
	var configFound bool
	for _, dir := range runtimeConfigDirs(root, profileID, mode) {
		for _, name := range []string{"wg.conf", "awg.conf"} {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			configFound = true
			if strings.Contains(strings.ToLower(string(b)), "dns = 127.0.0.1") {
				goto configOK
			}
		}
	}
	if configFound {
		return errors.New("active kernel tunnel config does not force DNS to Router VPN local proxy")
	}
	return errors.New("active kernel tunnel DNS config was not found")

configOK:
	hint, err := parseDNSHint(filepath.Join(root, "run", "dns.txt"))
	if err != nil {
		return fmt.Errorf("selected DNS runtime hint unavailable: %w", err)
	}
	if !strings.EqualFold(hint["mode"], selected.Mode) {
		return fmt.Errorf("runtime DNS mode %q does not match selected %q", hint["mode"], selected.Mode)
	}
	if !strings.EqualFold(hint["protocol"], selected.Protocol) {
		return fmt.Errorf("runtime DNS protocol %q does not match selected %q", hint["protocol"], selected.Protocol)
	}
	if !hostPortEqual(hint["server"], selected) {
		return fmt.Errorf("runtime DNS upstream %q does not match selected %s:%d", hint["server"], selected.Host, selected.Port)
	}
	return probeLocalDNSProxy()
}

func probeLocalDNSProxy() error {
	// Minimal A query for example.com. The query ID is arbitrary; success only
	// requires a syntactically valid response from Router VPN's bound local DNS
	// proxy. The subsequent OS-resolver proof verifies the client resolver path.
	q := []byte{
		0x52, 0x56, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	conn, err := net.DialTimeout("udp", "127.0.0.1:53", 1500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("Router VPN local DNS proxy is not reachable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write(q); err != nil {
		return fmt.Errorf("Router VPN local DNS proxy query failed: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("Router VPN local DNS proxy returned no response: %w", err)
	}
	if n < 12 || buf[0] != 0x52 || buf[1] != 0x56 || buf[2]&0x80 == 0 {
		return errors.New("Router VPN local DNS proxy returned an invalid DNS response")
	}
	return nil
}

func verifySingBoxDNSRuntime(root, profileID, mode string, selected dnsSelection) error {
	candidates := []string{filepath.Join(root, "run", mode+"-sing-box.json")}
	for _, dir := range runtimeConfigDirs(root, profileID, mode) {
		candidates = append(candidates, filepath.Join(dir, "sing-box.json"))
	}
	var last error
	for _, candidate := range candidates {
		if err := verifySingBoxDNSConfig(candidate, selected); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			last = err
		}
	}
	if last != nil {
		return last
	}
	return errors.New("active sing-box DNS config was not found")
}

func verifySingBoxDNSConfig(path string, selected dnsSelection) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg map[string]any
	if err = json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("invalid active sing-box config: %w", err)
	}
	dns, ok := cfg["dns"].(map[string]any)
	if !ok {
		return errors.New("active sing-box config has no DNS policy")
	}
	if final, _ := dns["final"].(string); final != "selected-dns" {
		return fmt.Errorf("active sing-box DNS final is %q, not selected-dns", final)
	}
	servers, _ := dns["servers"].([]any)
	matched := false
	for _, raw := range servers {
		server, _ := raw.(map[string]any)
		if server == nil || server["tag"] != "selected-dns" {
			continue
		}
		host, _ := server["server"].(string)
		port := intFromJSON(server["server_port"])
		protocol, _ := server["type"].(string)
		if strings.EqualFold(strings.Trim(host, "[]"), selected.Host) && port == selected.Port && dnsProtocolCompatible(protocol, selected.Protocol) {
			matched = true
		}
	}
	if !matched {
		return fmt.Errorf("active sing-box selected-dns does not match %s://%s:%d", selected.Protocol, selected.Host, selected.Port)
	}
	route, _ := cfg["route"].(map[string]any)
	rules, _ := route["rules"].([]any)
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		if rule == nil {
			continue
		}
		protocol, _ := rule["protocol"].(string)
		action, _ := rule["action"].(string)
		if protocol == "dns" && action == "hijack-dns" {
			return nil
		}
	}
	return errors.New("active sing-box route does not hijack DNS to selected-dns")
}

func intFromJSON(value any) int {
	switch n := value.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := strconv.Atoi(n.String())
		return i
	default:
		return 0
	}
}

func dnsProtocolCompatible(actual, selected string) bool {
	actual = strings.ToLower(actual)
	selected = strings.ToLower(selected)
	if actual == selected {
		return true
	}
	return (selected == "doh" && actual == "https") || (selected == "dot" && actual == "tls") || (selected == "doh3" && actual == "h3")
}

func proveSelectedDNS(a *app, s observedConnection, runtimeID string) dnsProofState {
	selected := expectedDNSSelection(s.Profile)
	result := dnsProofState{Mode: selected.Mode, Host: selected.Host, Status: "failed"}
	if !s.Connected || strings.TrimSpace(s.Phase) != "connected" {
		result.Reason = "selected-node path is not connected"
		return result
	}
	if selected.Host == "" || selected.Port == 0 {
		result.Reason = "selected DNS policy has no concrete upstream"
		return result
	}
	root := clientRoot(a)
	var err error
	if kernelDNSMode(runtimeID) {
		err = verifyKernelDNSRuntime(root, s.RouterID, runtimeID, selected)
	} else {
		err = verifySingBoxDNSRuntime(root, s.RouterID, runtimeID, selected)
	}
	if err != nil {
		result.Reason = err.Error()
		return result
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, "example.com")
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = errors.New("resolver returned no addresses")
		}
		result.Reason = "active selected-DNS policy is structurally enforced, but OS resolver proof failed: " + err.Error()
		return result
	}
	result.Status = "passed"
	result.LatencyMs = float64(time.Since(started).Microseconds()) / 1000.0
	result.Reason = fmt.Sprintf("selected DNS %s://%s:%d is enforced by the active %s runtime and an OS resolver query succeeded through the connected Router VPN path", selected.Protocol, selected.Host, selected.Port, runtimeID)
	return result
}
