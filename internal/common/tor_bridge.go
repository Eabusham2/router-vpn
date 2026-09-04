package common

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const ExternalTorDefaultSocksPort = 19050

func validTorFingerprint(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 40 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func normalizeTorTransport(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "obfs", "obfs4":
		return "obfs4", nil
	case "meek", "meek-azure", "meek_lite", "meek-lite":
		return "meek_lite", nil
	case "snowflake":
		return "snowflake", nil
	case "webtunnel", "web-tunnel", "web_tunnel":
		return "webtunnel", nil
	case "auto", "custom":
		return "custom", nil
	default:
		return "", fmt.Errorf("unsupported Tor pluggable transport %q", value)
	}
}

func validTorHTTPSURL(value string) bool {
	if len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	return true
}

func validTorFrontList(value string) bool {
	if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\r\n\x00/\\?#@") {
		return false
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" || len(item) > 253 || strings.ContainsAny(item, " \t") {
			return false
		}
	}
	return true
}

func validTorICEList(value string) bool {
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" || (!strings.HasPrefix(item, "stun:") && !strings.HasPrefix(item, "stuns:")) || strings.ContainsAny(item, " \t") {
			return false
		}
	}
	return true
}

func validTorUTLS(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\x00 /\\?#@\"'`;$|&<>")
}

func normalizeTorBridgeLine(value string) (string, string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00") {
		return "", "", "", fmt.Errorf("Tor bridge line is empty, oversized, or contains a control character")
	}
	fields := strings.Fields(value)
	if len(fields) > 0 && strings.EqualFold(fields[0], "Bridge") {
		fields = fields[1:]
	}
	if len(fields) < 3 {
		return "", "", "", fmt.Errorf("Tor bridge line is incomplete")
	}
	transport, err := normalizeTorTransport(fields[0])
	if err != nil || transport == "custom" {
		return "", "", "", fmt.Errorf("Tor bridge line uses an unsupported pluggable transport %q", fields[0])
	}
	host, portText, err := net.SplitHostPort(fields[1])
	if err != nil {
		return "", "", "", fmt.Errorf("Tor %s bridge endpoint must be IP:port: %w", transport, err)
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "", "", "", fmt.Errorf("Tor %s bridge endpoint must be a literal IP address", transport)
	}
	if transport == "obfs4" && ip.IsPrivate() {
		return "", "", "", fmt.Errorf("Tor obfs4 bridge endpoint must be a public literal IP address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", "", "", fmt.Errorf("Tor %s bridge endpoint has an invalid port", transport)
	}

	fingerprint := ""
	optionStart := 2
	if transport != "meek_lite" || !strings.Contains(fields[2], "=") {
		if !validTorFingerprint(fields[2]) {
			return "", "", "", fmt.Errorf("Tor %s bridge fingerprint must be exactly 40 hexadecimal characters", transport)
		}
		fingerprint = strings.ToUpper(fields[2])
		fields[2] = fingerprint
		optionStart = 3
	}
	if transport != "meek_lite" && fingerprint == "" {
		return "", "", "", fmt.Errorf("Tor %s bridge requires a relay fingerprint", transport)
	}

	options := map[string]string{}
	for i := optionStart; i < len(fields); i++ {
		key, val, ok := strings.Cut(fields[i], "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" || val == "" || strings.ContainsAny(key+val, "\r\n\x00") {
			return "", "", "", fmt.Errorf("Tor %s bridge option is malformed", transport)
		}
		if _, duplicate := options[key]; duplicate {
			return "", "", "", fmt.Errorf("Tor %s bridge option %q is duplicated", transport, key)
		}
		options[key] = val
		fields[i] = key + "=" + val
	}

	switch transport {
	case "obfs4":
		cert, ok := options["cert"]
		if !ok || cert == "" || len(cert) > 1024 {
			return "", "", "", fmt.Errorf("Tor obfs4 bridge requires a bounded cert= option")
		}
		if val, ok := options["iat-mode"]; ok && val != "0" && val != "1" && val != "2" {
			return "", "", "", fmt.Errorf("Tor obfs4 iat-mode must be 0, 1, or 2")
		}
		for key := range options {
			if key != "cert" && key != "iat-mode" {
				return "", "", "", fmt.Errorf("unsupported Tor obfs4 bridge option %q", key)
			}
		}
	case "meek_lite":
		if !validTorHTTPSURL(options["url"]) || !validTorFrontList(options["front"]) {
			return "", "", "", fmt.Errorf("Tor meek_lite requires safe url=https://… and front=… options")
		}
		if val := options["utls"]; val != "" && !validTorUTLS(val) {
			return "", "", "", fmt.Errorf("Tor meek_lite utls option is unsafe")
		}
		if val := options["utls-imitate"]; val != "" && !validTorUTLS(val) {
			return "", "", "", fmt.Errorf("Tor meek_lite utls-imitate option is unsafe")
		}
		for key := range options {
			if key != "url" && key != "front" && key != "utls" && key != "utls-imitate" {
				return "", "", "", fmt.Errorf("unsupported Tor meek_lite bridge option %q", key)
			}
		}
	case "snowflake":
		if fp := options["fingerprint"]; !validTorFingerprint(fp) || !strings.EqualFold(fp, fingerprint) {
			return "", "", "", fmt.Errorf("Tor Snowflake requires fingerprint= matching the bridge fingerprint")
		}
		if !validTorHTTPSURL(options["url"]) || !validTorFrontList(options["front"]) || !validTorICEList(options["ice"]) {
			return "", "", "", fmt.Errorf("Tor Snowflake requires safe url=https://…, front=…, and ice=stun:… options")
		}
		if val := options["utls-imitate"]; val != "" && !validTorUTLS(val) {
			return "", "", "", fmt.Errorf("Tor Snowflake utls-imitate option is unsafe")
		}
		for key := range options {
			if key != "fingerprint" && key != "url" && key != "front" && key != "ice" && key != "utls-imitate" {
				return "", "", "", fmt.Errorf("unsupported Tor Snowflake bridge option %q", key)
			}
		}
	case "webtunnel":
		if !validTorHTTPSURL(options["url"]) {
			return "", "", "", fmt.Errorf("Tor WebTunnel requires a safe url=https://… option")
		}
		if val := options["ver"]; val != "" && len(val) > 64 {
			return "", "", "", fmt.Errorf("Tor WebTunnel ver option is oversized")
		}
		for key := range options {
			if key != "url" && key != "ver" {
				return "", "", "", fmt.Errorf("unsupported Tor WebTunnel bridge option %q", key)
			}
		}
	}

	normalizedEndpoint := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	fields[0], fields[1] = transport, normalizedEndpoint
	return strings.Join(fields, " "), ip.String(), transport, nil
}

func TorBridgeTransport(c *ExternalTorBridgeConfig) (string, error) {
	if c == nil || len(c.Bridges) == 0 {
		return "", fmt.Errorf("external Tor bridge configuration is missing")
	}
	if strings.TrimSpace(c.Transport) != "" {
		transport, err := normalizeTorTransport(c.Transport)
		if err != nil {
			return "", err
		}
		if transport == "custom" {
			return "custom", nil
		}
	}
	fields := strings.Fields(strings.TrimSpace(c.Bridges[0]))
	if len(fields) > 0 && strings.EqualFold(fields[0], "Bridge") {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return "", fmt.Errorf("Tor bridge line is empty")
	}
	return normalizeTorTransport(fields[0])
}

func normalizeExternalTorBridge(c *ExternalTorBridgeConfig) (string, error) {
	if c == nil {
		return "", fmt.Errorf("external Tor bridge configuration is missing")
	}
	if len(c.Bridges) < 1 || len(c.Bridges) > 8 {
		return "", fmt.Errorf("external Tor bridge requires between 1 and 8 pluggable-transport bridge lines")
	}
	configuredTransport := ""
	if strings.TrimSpace(c.Transport) != "" {
		transport, err := normalizeTorTransport(c.Transport)
		if err != nil {
			return "", err
		}
		configuredTransport = transport
	}
	firstHost := ""
	lineTransport := ""
	seen := map[string]bool{}
	seenTransports := map[string]bool{}
	for i := range c.Bridges {
		line, host, transport, err := normalizeTorBridgeLine(c.Bridges[i])
		if err != nil {
			return "", fmt.Errorf("Tor bridge %d: %w", i+1, err)
		}
		if configuredTransport != "" && configuredTransport != "custom" && configuredTransport != transport {
			return "", fmt.Errorf("Tor bridge %d transport %q does not match configured transport %q", i+1, transport, configuredTransport)
		}
		if configuredTransport != "custom" && lineTransport != "" && lineTransport != transport {
			return "", fmt.Errorf("Tor profile cannot mix pluggable transports %q and %q unless transport=custom", lineTransport, transport)
		}
		if lineTransport == "" {
			lineTransport = transport
		}
		seenTransports[transport] = true
		if seen[line] {
			return "", fmt.Errorf("duplicate Tor %s bridge line", transport)
		}
		seen[line] = true
		c.Bridges[i] = line
		if firstHost == "" {
			firstHost = host
		}
	}
	if configuredTransport == "custom" {
		c.Transport = "custom"
	} else if configuredTransport != "" {
		c.Transport = configuredTransport
	} else if len(seenTransports) == 1 {
		c.Transport = lineTransport
	} else {
		return "", fmt.Errorf("mixed Tor pluggable transports require transport=custom")
	}
	if c.SocksPort == 0 {
		c.SocksPort = ExternalTorDefaultSocksPort
	}
	if c.SocksPort < 1024 || c.SocksPort > 65535 || c.SocksPort == 1098 || c.SocksPort == 1099 || c.SocksPort == 8788 {
		return "", fmt.Errorf("Tor local SOCKS port is unsafe or reserved")
	}
	return firstHost, nil
}
