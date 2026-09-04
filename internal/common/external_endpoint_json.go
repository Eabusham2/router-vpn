package common

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// externalNodeConfigJSON deliberately aliases ExternalNodeConfig so the custom
// decoder can canonicalize endpoint identity fields without recursive decoding.
type externalNodeConfigJSON ExternalNodeConfig

// normalizeExternalJSONHost mirrors the controller's established endpoint
// grammar: IPv4/IPv6 and normal DNS hostnames are accepted; an explicitly
// supplied URL contributes only its hostname; path/query/userinfo/whitespace in
// a bare host are rejected. The normalized value is safe to persist as the
// protocol's host identity, while protocol-specific validation remains in
// NormalizeRouterProfile.
func normalizeExternalJSONHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("external endpoint host is empty")
	}
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("external endpoint address is invalid")
		}
		value = u.Hostname()
	}
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if strings.ContainsAny(value, " /\\?#@") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return "", fmt.Errorf("external endpoint hostname is invalid")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("external endpoint hostname is invalid")
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return "", fmt.Errorf("external endpoint hostname is invalid")
			}
		}
	}
	return strings.ToLower(value), nil
}

func normalizeExternalJSONWireGuardEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("external WireGuard endpoint is empty")
	}
	if host, portText, err := net.SplitHostPort(value); err == nil {
		port, convErr := strconv.Atoi(portText)
		if convErr != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("external WireGuard endpoint port is invalid")
		}
		host, err = normalizeExternalJSONHost(host)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String(), nil
	}
	if strings.Count(value, ":") == 1 && !strings.Contains(value, "://") {
		parts := strings.SplitN(value, ":", 2)
		port, err := strconv.Atoi(parts[1])
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("external WireGuard endpoint port is invalid")
		}
		host, err := normalizeExternalJSONHost(parts[0])
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}
	return normalizeExternalJSONHost(value)
}

func (e *ExternalNodeConfig) UnmarshalJSON(data []byte) error {
	var decoded externalNodeConfigJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*e = ExternalNodeConfig(decoded)

	var err error
	if e.WireGuard != nil {
		e.WireGuard.Endpoint, err = normalizeExternalJSONWireGuardEndpoint(e.WireGuard.Endpoint)
		if err != nil { return err }
	}
	if e.Shadowsocks != nil {
		e.Shadowsocks.Server, err = normalizeExternalJSONHost(e.Shadowsocks.Server)
		if err != nil { return fmt.Errorf("external Shadowsocks server: %w", err) }
	}
	if e.SOCKS5 != nil {
		e.SOCKS5.Host, err = normalizeExternalJSONHost(e.SOCKS5.Host)
		if err != nil { return fmt.Errorf("external SOCKS5 host: %w", err) }
	}
	if e.HTTPConnect != nil {
		e.HTTPConnect.Host, err = normalizeExternalJSONHost(e.HTTPConnect.Host)
		if err != nil { return fmt.Errorf("external HTTP CONNECT host: %w", err) }
	}
	if e.HTTPSConnect != nil {
		e.HTTPSConnect.Host, err = normalizeExternalJSONHost(e.HTTPSConnect.Host)
		if err != nil { return fmt.Errorf("external HTTPS CONNECT host: %w", err) }
	}
	if e.Hysteria2 != nil {
		e.Hysteria2.Server, err = normalizeExternalJSONHost(e.Hysteria2.Server)
		if err != nil { return fmt.Errorf("external Hysteria2 server: %w", err) }
	}
	return nil
}
