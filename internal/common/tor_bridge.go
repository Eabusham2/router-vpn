package common

import (
	"fmt"
	"net"
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

func normalizeTorBridgeLine(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return "", "", fmt.Errorf("Tor bridge line is empty, oversized, or contains a control character")
	}
	fields := strings.Fields(value)
	if len(fields) > 0 && strings.EqualFold(fields[0], "Bridge") {
		fields = fields[1:]
	}
	if len(fields) < 4 || !strings.EqualFold(fields[0], "obfs4") {
		return "", "", fmt.Errorf("Tor bridge currently requires an obfs4 bridge line")
	}
	host, portText, err := net.SplitHostPort(fields[1])
	if err != nil {
		return "", "", fmt.Errorf("Tor obfs4 bridge endpoint must be IP:port: %w", err)
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "", "", fmt.Errorf("Tor obfs4 bridge endpoint must be a public literal IP address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", "", fmt.Errorf("Tor obfs4 bridge endpoint has an invalid port")
	}
	if !validTorFingerprint(fields[2]) {
		return "", "", fmt.Errorf("Tor obfs4 bridge fingerprint must be exactly 40 hexadecimal characters")
	}
	certSeen := false
	for _, option := range fields[3:] {
		key, val, ok := strings.Cut(option, "=")
		if !ok || key == "" || val == "" || strings.ContainsAny(key+val, "\r\n\x00") {
			return "", "", fmt.Errorf("Tor obfs4 bridge option is malformed")
		}
		switch key {
		case "cert":
			if len(val) > 1024 {
				return "", "", fmt.Errorf("Tor obfs4 cert option is oversized")
			}
			certSeen = true
		case "iat-mode":
			if val != "0" && val != "1" && val != "2" {
				return "", "", fmt.Errorf("Tor obfs4 iat-mode must be 0, 1, or 2")
			}
		default:
			return "", "", fmt.Errorf("unsupported Tor obfs4 bridge option %q", key)
		}
	}
	if !certSeen {
		return "", "", fmt.Errorf("Tor obfs4 bridge requires cert=…")
	}
	normalizedEndpoint := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	fields[0], fields[1], fields[2] = "obfs4", normalizedEndpoint, strings.ToUpper(fields[2])
	return strings.Join(fields, " "), ip.String(), nil
}

func normalizeExternalTorBridge(c *ExternalTorBridgeConfig) (string, error) {
	if c == nil {
		return "", fmt.Errorf("external Tor bridge configuration is missing")
	}
	if len(c.Bridges) < 1 || len(c.Bridges) > 8 {
		return "", fmt.Errorf("external Tor bridge requires between 1 and 8 obfs4 bridge lines")
	}
	firstHost := ""
	seen := map[string]bool{}
	for i := range c.Bridges {
		line, host, err := normalizeTorBridgeLine(c.Bridges[i])
		if err != nil {
			return "", fmt.Errorf("Tor bridge %d: %w", i+1, err)
		}
		if seen[line] {
			return "", fmt.Errorf("duplicate Tor obfs4 bridge line")
		}
		seen[line] = true
		c.Bridges[i] = line
		if firstHost == "" {
			firstHost = host
		}
	}
	if c.SocksPort == 0 {
		c.SocksPort = ExternalTorDefaultSocksPort
	}
	if c.SocksPort < 1024 || c.SocksPort > 65535 || c.SocksPort == 1098 || c.SocksPort == 1099 || c.SocksPort == 8788 {
		return "", fmt.Errorf("Tor local SOCKS port is unsafe or reserved")
	}
	return firstHost, nil
}
