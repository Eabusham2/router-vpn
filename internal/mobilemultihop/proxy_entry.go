package mobilemultihop

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"unicode/utf8"
)

// ProxyEntryMode denotes a native TCP+UDP encrypted transport. A SOCKS label,
// TCP-only proxy or an unstarted helper process is not an equivalent entry.
func ProxyEntryMode(mode string) bool { return mode == "shadowsocks" || mode == "hysteria2" }

// CompileProxyEntry consumes the exact selected bundle profile (base64 files),
// not mutable app state. Its output is a self-contained native outbound. The
// entry certificate is inlined from its owned asset, so an identically named
// exit certificate cannot replace it when the two node profiles are composed.
// It opens no files, sockets, listeners, routes, or OS VPN services.
func CompileProxyEntry(profile, mode string) (string, error) {
	bad := errors.New("entry requires one bounded self-contained native Shadowsocks or Hysteria2 profile")
	if !ProxyEntryMode(mode) {
		return "", bad
	}
	var encoded map[string]string
	if exactJSON([]byte(profile), &encoded, 8<<20) != nil || len(encoded) == 0 || len(encoded) > 8 {
		return "", bad
	}
	assets := map[string][]byte{}
	total := 0
	for name, text := range encoded {
		if !exactID.MatchString(name) || strings.Contains(name, "..") {
			return "", bad
		}
		data, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil || len(data) == 0 || len(data) > 4<<20 {
			return "", bad
		}
		total += len(data)
		if total > 4<<20 {
			return "", bad
		}
		assets[name] = data
	}
	var root map[string]any
	if exactJSON(assets["sing-box.json"], &root, 4<<20) != nil || root == nil {
		return "", bad
	}
	for key, value := range root {
		switch key {
		case "log", "dns", "inbounds", "outbounds", "route":
		case "endpoints", "services":
			if values, ok := value.([]any); !ok || len(values) != 0 {
				return "", bad
			}
		default:
			return "", bad
		}
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return "", bad
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return "", bad
	}
	for _, key := range []string{"route_address", "route_exclude_address", "route_address_set", "route_exclude_address_set", "include_interface", "exclude_interface", "include_uid", "exclude_uid", "include_package", "exclude_package", "include_android_user"} {
		if _, exists := tun[key]; exists {
			return "", errors.New("entry split or bypass policy cannot be discarded")
		}
	}
	route, ok := root["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return "", bad
	}
	for key, value := range route {
		switch key {
		case "final":
		case "auto_detect_interface":
			if value != true {
				return "", bad
			}
		case "rules":
			rules, ok := value.([]any)
			if !ok {
				return "", bad
			}
			for _, raw := range rules {
				rule, ok := raw.(map[string]any)
				if !ok || len(rule) != 2 || rule["protocol"] != "dns" || rule["action"] != "hijack-dns" {
					return "", errors.New("entry custom routing cannot be discarded")
				}
			}
		default:
			return "", bad
		}
	}
	outbounds, ok := root["outbounds"].([]any)
	if !ok || len(outbounds) == 0 || len(outbounds) > 3 {
		return "", bad
	}
	var entry map[string]any
	tags := map[string]bool{}
	for _, raw := range outbounds {
		value, ok := raw.(map[string]any)
		if !ok {
			return "", bad
		}
		tag, ok := value["tag"].(string)
		if !ok || !exactID.MatchString(tag) || tags[tag] {
			return "", bad
		}
		tags[tag] = true
		if tag == "proxy" {
			entry = value
			continue
		}
		if (value["type"] != "direct" && value["type"] != "block") || len(value) != 2 {
			return "", bad
		}
	}
	if entry == nil || entry["type"] != mode {
		return "", bad
	}
	used := map[string]bool{"sing-box.json": true}
	if mode == "hysteria2" {
		tls, ok := entry["tls"].(map[string]any)
		if !ok {
			return "", bad
		}
		if raw, exists := tls["certificate_path"]; exists {
			name, ok := raw.(string)
			data, found := assets[name]
			if !ok || !found || name == "sing-box.json" || tls["certificate"] != nil || !validEntryCertificate(data) {
				return "", errors.New("entry TLS certificate must be its own bounded certificate asset")
			}
			tls["certificate"] = []any{string(data)}
			delete(tls, "certificate_path")
			used[name] = true
		}
	}
	if len(used) != len(assets) {
		return "", errors.New("entry profile contains an unowned helper or asset")
	}
	if err := validateProxyEntry(entry, mode); err != nil {
		return "", err
	}
	entry["tag"] = "routervpn-hop-entry"
	result, err := json.Marshal(entry)
	return string(result), err
}

func validEntryCertificate(data []byte) bool {
	if len(data) == 0 || len(data) > 256<<10 || !utf8.Valid(data) {
		return false
	}
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		// pem.Decode otherwise skips arbitrary preceding text (including keys).
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
		if count > 16 {
			return false
		}
		data = rest
	}
	return count > 0
}

func validateProxyEntry(entry map[string]any, mode string) error {
	bad := errors.New("entry transport must retain its authenticated native TCP/UDP path")
	if !ProxyEntryMode(mode) || entry["type"] != mode {
		return bad
	}
	allowed := map[string]bool{"type": true, "tag": true, "server": true, "server_port": true, "password": true, "network": true}
	if mode == "shadowsocks" {
		allowed["method"] = true
		allowed["udp_over_tcp"] = true
	} else {
		for _, key := range []string{"tls", "obfs", "up_mbps", "down_mbps"} {
			allowed[key] = true
		}
	}
	for key := range entry {
		if !allowed[key] {
			return errors.New("entry contains unowned transport or dial policy")
		}
	}
	host, ok := entry["server"].(string)
	if !ok || !wireGuardServerIP(host) {
		return errors.New("entry requires a literal unicast server; no physical DNS fallback is permitted")
	}
	port, ok := entry["server_port"].(float64)
	if !ok || port < 1 || port > 65535 || port != float64(int(port)) {
		return bad
	}
	password, ok := entry["password"].(string)
	if !ok || password == "" || len(password) > 4096 || strings.ContainsRune(password, 0) {
		return bad
	}
	if network, exists := entry["network"]; exists && network != "" {
		return errors.New("multihop entry must preserve both TCP and UDP")
	}
	if mode == "shadowsocks" {
		switch entry["method"] {
		case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
		default:
			return errors.New("entry Shadowsocks requires an authenticated cipher")
		}
	} else {
		tls, ok := entry["tls"].(map[string]any)
		if !ok || tls["enabled"] != true || (tls["insecure"] != nil && tls["insecure"] != false) {
			return errors.New("entry Hysteria2 requires verified TLS")
		}
		if cert, exists := tls["certificate"]; exists {
			certificates := []any{cert}
			if array, ok := cert.([]any); ok {
				certificates = array
			}
			if len(certificates) == 0 || len(certificates) > 16 {
				return bad
			}
			for _, raw := range certificates {
				value, ok := raw.(string)
				if !ok || !validEntryCertificate([]byte(value)) {
					return errors.New("entry has an invalid inline trust certificate")
				}
			}
		}
	}
	if entryHasHostPath(entry) {
		return errors.New("entry cannot depend on a host file or the exit's assets")
	}
	return nil
}
func entryHasHostPath(value any) bool {
	switch x := value.(type) {
	case map[string]any:
		for key, item := range x {
			if key == "path" || strings.HasSuffix(key, "_path") || entryHasHostPath(item) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if entryHasHostPath(item) {
				return true
			}
		}
	}
	return false
}
