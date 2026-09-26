// Package nativesip003 composes the generated SS2022+WebSocket/TLS TCP and
// Hysteria2 UDP graph into one native Libbox runtime. It opens no sockets, starts
// no helper processes, reads no files, and never weakens imported cryptography.
package nativesip003

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxConfig = 4 << 20
const Mode = "ss-v2ray"

var label = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)
var invalid = errors.New("invalid native Shadowsocks/V2Ray graph or unowned helper option")

// Object rejects duplicate keys and excessive nesting before the normal map
// decoder could erase that ambiguity. Error messages never contain credentials.
func Object(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaxConfig || !utf8.Valid(raw) {
		return nil, invalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := read(d, 0)
	if err != nil {
		return nil, invalid
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, invalid
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, invalid
	}
	return object, nil
}
func read(d *json.Decoder, depth int) (any, error) {
	if depth > 48 {
		return nil, invalid
	}
	token, err := d.Token()
	if err != nil {
		return nil, invalid
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		result := map[string]any{}
		for d.More() {
			k, err := d.Token()
			key, ok := k.(string)
			if err != nil || !ok {
				return nil, invalid
			}
			if _, exists := result[key]; exists {
				return nil, invalid
			}
			v, err := read(d, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, invalid
		}
		return result, nil
	case '[':
		result := []any{}
		for d.More() {
			v, err := read(d, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, invalid
		}
		return result, nil
	}
	return nil, invalid
}
func text(v any) string { s, _ := v.(string); return s }
func keys(m map[string]any, names ...string) bool {
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	for name := range m {
		if !allowed[name] {
			return false
		}
	}
	return true
}
func port(v any) (int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, invalid
	}
	i, e := n.Int64()
	if e != nil || i < 1 || i > 65535 {
		return 0, invalid
	}
	return int(i), nil
}
func hostname(value string) bool {
	if value == "" || len(value) > 253 || strings.EqualFold(value, "localhost") {
		return false
	}
	if ip, e := netip.ParseAddr(value); e == nil {
		return ip.Zone() == "" && !ip.Unmap().IsUnspecified() && !ip.Unmap().IsLoopback() && !ip.Unmap().IsMulticast() && !ip.Unmap().IsLinkLocalUnicast()
	}
	if strings.Trim(value, "0123456789.") == "" {
		return false
	}
	for _, part := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	return true
}
func loopback(value string) bool {
	if strings.EqualFold(value, "localhost") {
		return true
	}
	ip, e := netip.ParseAddr(strings.Trim(value, "[]"))
	return e == nil && ip.Unmap().IsLoopback()
}
func validateOptions(raw string) error {
	if len(raw) == 0 || len(raw) > 16384 || strings.ContainsAny(raw, "\\\r\n\x00") {
		return invalid
	}
	seen := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		if part == "" {
			return invalid
		}
		item := strings.SplitN(part, "=", 2)
		key := item[0]
		value := ""
		if len(item) == 2 {
			value = item[1]
		}
		if _, exists := seen[key]; exists {
			return invalid
		}
		seen[key] = value
		switch key {
		case "tls":
			if len(item) != 1 {
				return invalid
			}
		case "host":
			if !hostname(value) {
				return invalid
			}
		case "path":
			if !strings.HasPrefix(value, "/") || len(value) > 2048 {
				return invalid
			}
			for _, r := range value {
				if r < 0x21 || r > 0x7e {
					return invalid
				}
			}
		case "mode":
			if value != "websocket" {
				return invalid
			}
		case "mux":
			n, e := strconv.Atoi(value)
			if e != nil || n < 0 || n > 64 || strconv.Itoa(n) != value {
				return invalid
			}
		case "certRaw":
			der, e := base64.StdEncoding.Strict().DecodeString(value)
			if e != nil || len(der) > 8192 {
				return invalid
			}
			if _, e = x509.ParseCertificate(der); e != nil {
				return invalid
			}
		default:
			return invalid
		}
	}
	if _, ok := seen["tls"]; !ok {
		return invalid
	}
	if seen["host"] == "" || seen["path"] == "" {
		return invalid
	}
	return nil
}

// Compile also accepts its own exact output, making DNS patching/reconnect
// idempotent. An existing native outbound must still match the imported helper
// credentials, server, transport options, and route identity byte-for-byte.
func Compile(wrapper, helper []byte) ([]byte, error) {
	local, e := Object(helper)
	if e != nil {
		return nil, e
	}
	if !keys(local, "server", "server_port", "password", "method", "local_address", "local_port", "mode", "plugin", "plugin_opts") || len(local) != 9 {
		return nil, invalid
	}
	remotePort, e := port(local["server_port"])
	if e != nil {
		return nil, e
	}
	localPort, e := port(local["local_port"])
	if e != nil {
		return nil, e
	}
	if !hostname(text(local["server"])) || local["local_address"] != "127.0.0.1" || local["mode"] != "tcp_only" || local["method"] != "2022-blake3-aes-256-gcm" || local["plugin"] != "v2ray-plugin" {
		return nil, invalid
	}
	key, e := base64.StdEncoding.Strict().DecodeString(text(local["password"]))
	if e != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != text(local["password"]) {
		return nil, invalid
	}
	if e = validateOptions(text(local["plugin_opts"])); e != nil {
		return nil, e
	}
	root, e := Object(wrapper)
	if e != nil {
		return nil, e
	}
	if !keys(root, "log", "dns", "inbounds", "outbounds", "route") {
		return nil, invalid
	}
	inbound, ok := root["inbounds"].([]any)
	if !ok || len(inbound) != 1 {
		return nil, invalid
	}
	tun, ok := inbound[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return nil, invalid
	}
	list, ok := root["outbounds"].([]any)
	if !ok || len(list) < 2 || len(list) > 3 {
		return nil, invalid
	}
	tcpTag, udpTag := "", ""
	seen := map[string]bool{}
	for index, item := range list {
		outbound, ok := item.(map[string]any)
		if !ok {
			return nil, invalid
		}
		tag := text(outbound["tag"])
		if !tagPattern.MatchString(tag) || seen[tag] {
			return nil, invalid
		}
		seen[tag] = true
		switch outbound["type"] {
		case "socks", "shadowsocks":
			if tcpTag != "" {
				return nil, invalid
			}
			tcpTag = tag
			expected := map[string]any{"type": "shadowsocks", "tag": tag, "server": local["server"], "server_port": remotePort, "method": local["method"], "password": local["password"], "plugin": "v2ray-plugin", "plugin_opts": local["plugin_opts"], "network": "tcp"}
			if outbound["type"] == "socks" {
				p, e := port(outbound["server_port"])
				if e != nil || p != localPort || len(outbound) != 5 || !keys(outbound, "type", "tag", "server", "server_port", "version") || outbound["server"] != "127.0.0.1" || outbound["version"] != "5" {
					return nil, invalid
				}
			} else {
				a, _ := json.Marshal(outbound)
				b, _ := json.Marshal(expected)
				if !bytes.Equal(a, b) {
					return nil, invalid
				}
			}
			list[index] = expected
		case "hysteria2":
			if udpTag != "" || !hostname(text(outbound["server"])) || text(outbound["detour"]) != "" {
				return nil, invalid
			}
			udpTag = tag
			if _, e := port(outbound["server_port"]); e != nil {
				return nil, e
			}
			tls, ok := outbound["tls"].(map[string]any)
			if !ok || tls["enabled"] != true || tls["insecure"] == true || text(outbound["password"]) == "" {
				return nil, invalid
			}
		case "direct":
			if len(outbound) != 2 || !keys(outbound, "type", "tag") {
				return nil, invalid
			}
		default:
			return nil, invalid
		}
		if outbound["type"] != "socks" && loopback(text(outbound["server"])) {
			return nil, invalid
		}
	}
	if tcpTag == "" || udpTag == "" {
		return nil, invalid
	}
	route, ok := root["route"].(map[string]any)
	if !ok || route["final"] != tcpTag {
		return nil, invalid
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return nil, invalid
	}
	tcp, udp, dns := false, false, false
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			return nil, invalid
		}
		if rule["protocol"] == "dns" && rule["action"] == "hijack-dns" {
			dns = true
			continue
		}
		if rule["action"] != "route" || !keys(rule, "network", "action", "outbound") {
			return nil, invalid
		}
		switch rule["network"] {
		case "tcp":
			if tcp || rule["outbound"] != tcpTag {
				return nil, invalid
			}
			tcp = true
		case "udp":
			if udp || rule["outbound"] != udpTag {
				return nil, invalid
			}
			udp = true
		default:
			return nil, invalid
		}
	}
	if !tcp || !udp || !dns {
		return nil, invalid
	}
	// A TCP-only SIP003 stream cannot carry UDP DNS or HTTP/3. Keep the selected
	// resolver/protocol but route datagram DNS through this mode's real UDP leg.
	dnsConfig, ok := root["dns"].(map[string]any)
	if !ok {
		return nil, invalid
	}
	servers, ok := dnsConfig["servers"].([]any)
	if !ok || len(servers) == 0 {
		return nil, invalid
	}
	for _, item := range servers {
		server, ok := item.(map[string]any)
		if !ok {
			return nil, invalid
		}
		if server["detour"] != tcpTag && server["detour"] != udpTag {
			return nil, invalid
		}
		switch server["type"] {
		case "udp", "h3", "quic":
			server["detour"] = udpTag
		case "tcp", "tls", "https":
			server["detour"] = tcpTag
		default:
			return nil, invalid
		}
	}
	root["outbounds"] = list
	output, e := json.Marshal(root)
	if e != nil || len(output) > MaxConfig {
		return nil, invalid
	}
	return output, nil
}
