// Package applexray validates the imported native Xray portion of an Apple
// PacketTunnel. It never opens a socket or executes an imported command.
package applexray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxConfig = 4 * 1024 * 1024
const Type = "routervpn-xray"

// Plan retains the exact authenticated protocol and transport fields. Only the
// obsolete local SOCKS ingress and diagnostic logging are removed; the native
// Libbox outbound calls this instance directly and owns all its network dials.
type Plan struct {
	JSON         []byte
	Server       netip.AddrPort
	ListenerPort int
	ServerHost   string
	ServerPort   uint16
}

func Object(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaxConfig || !utf8.Valid(raw) {
		return nil, errors.New("Xray configuration must be bounded UTF-8 JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := readValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing Xray JSON")
	}
	root, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("Xray configuration must be an object")
	}
	return root, nil
}
func readValue(d *json.Decoder, depth int) (any, error) {
	bad := errors.New("ambiguous or excessively nested Xray JSON")
	if depth > 48 {
		return nil, bad
	}
	t, e := d.Token()
	if e != nil {
		return nil, bad
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for d.More() {
			k, e := d.Token()
			name, ok := k.(string)
			if e != nil || !ok {
				return nil, bad
			}
			if _, found := m[name]; found {
				return nil, bad
			}
			v, e := readValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[name] = v
		}
		if t, e = d.Token(); e != nil || t != json.Delim('}') {
			return nil, bad
		}
		return m, nil
	case '[':
		a := []any{}
		for d.More() {
			v, e := readValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		if t, e = d.Token(); e != nil || t != json.Delim(']') {
			return nil, bad
		}
		return a, nil
	}
	return nil, bad
}
func keys(m map[string]any, allowed ...string) error {
	set := map[string]bool{}
	for _, k := range allowed {
		set[k] = true
	}
	for k := range m {
		if !set[k] {
			return errors.New("Xray profile requests an unowned configuration field")
		}
	}
	return nil
}
func object(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("missing Xray object")
	}
	return m, nil
}
func one(v any) (map[string]any, error) {
	a, ok := v.([]any)
	if !ok || len(a) != 1 {
		return nil, errors.New("Xray profile requires exactly one owned endpoint")
	}
	return object(a[0])
}
func text(v any) string { s, _ := v.(string); return s }
func port(v any) (int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("invalid Xray port")
	}
	i, e := n.Int64()
	if e != nil || i < 1 || i > 65535 {
		return 0, errors.New("invalid Xray port")
	}
	return int(i), nil
}

func Prepare(mode string, raw []byte) (Plan, error) { return prepare(mode, raw, false) }
func prepare(mode string, raw []byte, allowHostname bool) (Plan, error) {
	var plan Plan
	switch mode {
	case "reality-vision", "reality-pq-vision", "reality-xhttp", "split", "max":
	default:
		return plan, errors.New("raw mode does not describe an implemented Apple Xray graph")
	}
	root, e := Object(raw)
	if e != nil {
		return plan, e
	}
	if e = keys(root, "log", "inbounds", "outbounds"); e != nil {
		return plan, e
	}
	if log, found := root["log"]; found {
		v, e := object(log)
		if e != nil {
			return plan, e
		}
		if e = keys(v, "loglevel"); e != nil {
			return plan, e
		}
	}
	in, e := one(root["inbounds"])
	if e != nil {
		return plan, e
	}
	if e = keys(in, "tag", "listen", "port", "protocol", "settings"); e != nil {
		return plan, e
	}
	if in["protocol"] != "socks" || in["listen"] != "127.0.0.1" {
		return plan, errors.New("Xray import must use a single private SOCKS wrapper")
	}
	plan.ListenerPort, e = port(in["port"])
	if e != nil {
		return plan, e
	}
	settings, e := object(in["settings"])
	if e != nil {
		return plan, e
	}
	if e = keys(settings, "auth", "udp"); e != nil {
		return plan, e
	}
	if settings["auth"] != "noauth" || settings["udp"] != true {
		return plan, errors.New("unexpected Xray ingress policy")
	}
	out, e := one(root["outbounds"])
	if e != nil {
		return plan, e
	}
	if e = keys(out, "tag", "protocol", "settings", "streamSettings", "mux"); e != nil {
		return plan, e
	}
	if out["protocol"] != "vless" || text(out["tag"]) == "" {
		return plan, errors.New("native Xray requires the generated VLESS proxy")
	}
	if mux, found := out["mux"]; found {
		m, e := object(mux)
		if e != nil {
			return plan, e
		}
		if e = keys(m, "enabled"); e != nil || m["enabled"] != false {
			return plan, errors.New("unowned Xray multiplex policy")
		}
	}
	settings, e = object(out["settings"])
	if e != nil {
		return plan, e
	}
	if e = keys(settings, "vnext"); e != nil {
		return plan, e
	}
	remote, e := one(settings["vnext"])
	if e != nil {
		return plan, e
	}
	if e = keys(remote, "address", "port", "users"); e != nil {
		return plan, e
	}
	host := text(remote["address"])
	ip, ipErr := netip.ParseAddr(host)
	if ipErr != nil {
		if !allowHostname || !safeHostname(host) {
			return plan, errors.New("Xray outer endpoint must be a literal IP or an explicitly resolved node hostname")
		}
	} else if !safeIP(ip) {
		return plan, errors.New("unsafe Xray outer endpoint")
	}
	p, e := port(remote["port"])
	if e != nil {
		return plan, e
	}
	plan.ServerHost = host
	plan.ServerPort = uint16(p)
	if ip.IsValid() {
		plan.Server = netip.AddrPortFrom(ip.Unmap(), uint16(p))
	}
	user, e := one(remote["users"])
	if e != nil {
		return plan, e
	}
	if e = keys(user, "id", "flow", "encryption"); e != nil {
		return plan, e
	}
	if id := text(user["id"]); len(id) != 36 || strings.Count(id, "-") != 4 {
		return plan, errors.New("invalid generated VLESS user identity")
	}
	enc := text(user["encryption"])
	if enc == "" {
		return plan, errors.New("VLESS encryption policy missing")
	}
	pq := mode == "reality-pq-vision" || mode == "reality-xhttp" || mode == "max"
	if pq && !strings.HasPrefix(enc, "mlkem768x25519plus.") {
		return plan, errors.New("PQ-labelled mode has no hybrid ML-KEM VLESS encryption")
	}
	if !pq && enc != "none" {
		return plan, errors.New("ordinary REALITY graph has mismatched VLESS encryption")
	}
	stream, e := object(out["streamSettings"])
	if e != nil {
		return plan, e
	}
	if e = keys(stream, "network", "security", "realitySettings", "xhttpSettings", "finalmask"); e != nil {
		return plan, e
	}
	if stream["security"] != "reality" {
		return plan, errors.New("REALITY transport protection is required")
	}
	network := text(stream["network"])
	if mode == "reality-xhttp" {
		if network != "xhttp" && network != "splithttp" {
			return plan, errors.New("XHTTP label does not match the transport")
		}
		if text(user["flow"]) != "" {
			return plan, errors.New("XHTTP cannot silently replace a Vision flow")
		}
		x, e := object(stream["xhttpSettings"])
		if e != nil {
			return plan, e
		}
		if e = keys(x, "path", "mode"); e != nil {
			return plan, e
		}
		if !strings.HasPrefix(text(x["path"]), "/") || x["mode"] != "auto" {
			return plan, errors.New("unowned XHTTP path or mode")
		}
	} else if (network != "raw" && network != "tcp") || user["flow"] != "xtls-rprx-vision" {
		return plan, errors.New("Vision graph must retain its native XTLS flow")
	}
	reality, e := object(stream["realitySettings"])
	if e != nil {
		return plan, e
	}
	if e = keys(reality, "serverName", "fingerprint", "password", "publicKey", "shortId", "mldsa65Verify"); e != nil {
		return plan, e
	}
	if text(reality["serverName"]) == "" || text(reality["fingerprint"]) == "" || (text(reality["password"]) == "" && text(reality["publicKey"]) == "") {
		return plan, errors.New("REALITY server authentication settings missing")
	}
	if v, found := stream["finalmask"]; found {
		m, e := object(v)
		if e != nil {
			return plan, e
		}
		if e = keys(m, "tcp"); e != nil {
			return plan, e
		}
		a, ok := m["tcp"].([]any)
		if !ok || len(a) > 4 {
			return plan, errors.New("invalid FinalMask transport settings")
		}
		for _, v := range a {
			m, e := object(v)
			if e != nil {
				return plan, e
			}
			if e = keys(m, "type", "settings"); e != nil {
				return plan, e
			}
			if m["type"] != "fragment" && m["type"] != "noise" {
				return plan, errors.New("unowned FinalMask method")
			}
		}
	}
	// No public ingress, file logging, API, OS TUN, global resolver or environment
	// mutation. Dial() enters the instance directly; the user config is not run as
	// an executable and all protocol/security/transport settings remain unchanged.
	root["inbounds"] = []any{}
	root["log"] = map[string]any{"loglevel": "none"}
	plan.JSON, e = json.Marshal(root)
	return plan, e
}

// Compile replaces only the exact loopback wrapper which references this
// imported Xray listener. The surrounding DNS/route policy is preserved.
func Compile(mode string, wrapper, raw []byte) ([]byte, error) {
	return compile(mode, wrapper, raw, false)
}
func compile(mode string, wrapper, raw []byte, allowHostname bool) ([]byte, error) {
	plan, e := prepare(mode, raw, allowHostname)
	if e != nil {
		return nil, e
	}
	root, e := Object(wrapper)
	if e != nil {
		return nil, e
	}
	list, ok := root["outbounds"].([]any)
	if !ok {
		return nil, errors.New("missing native wrapper outbounds")
	}
	replaced := 0
	for i, v := range list {
		o, e := object(v)
		if e != nil {
			return nil, e
		}
		if o["type"] == Type {
			if e = keys(o, "type", "tag", "mode", "config_json"); e != nil {
				return nil, e
			}
			if o["mode"] != mode || o["config_json"] != string(raw) || text(o["tag"]) == "" {
				return nil, errors.New("saved Xray wrapper does not match the exact imported protocol")
			}
			replaced++
			continue
		}
		if server := text(o["server"]); server != "127.0.0.1" {
			if server == "::1" || strings.EqualFold(server, "localhost") || strings.HasPrefix(server, "127.") {
				return nil, errors.New("unowned loopback helper in Xray wrapper")
			}
			continue
		}
		p, e := port(o["server_port"])
		if e != nil {
			return nil, e
		}
		if o["type"] != "socks" || p != plan.ListenerPort || o["version"] != "5" {
			return nil, errors.New("unowned loopback helper in Xray wrapper")
		}
		if e = keys(o, "type", "tag", "server", "server_port", "version"); e != nil {
			return nil, e
		}
		tag := text(o["tag"])
		if tag == "" {
			return nil, errors.New("missing Xray wrapper route tag")
		}
		list[i] = map[string]any{"type": Type, "tag": tag, "mode": mode, "config_json": string(raw)}
		replaced++
	}
	if replaced != 1 {
		return nil, fmt.Errorf("expected exactly one owned Xray wrapper, got %d", replaced)
	}
	root["outbounds"] = list
	if e = validateGraph(mode, root); e != nil {
		return nil, e
	}
	return json.Marshal(root)
}

// Split/PQ Dual Transport mean two real routing components, not a friendly
// name on a single Xray connection. Validate the generator's intended graph.
func validateGraph(mode string, root map[string]any) error {
	if e := keys(root, "log", "inbounds", "outbounds", "dns", "route"); e != nil {
		return e
	}
	inbound, e := one(root["inbounds"])
	if e != nil {
		return e
	}
	if inbound["type"] != "tun" || inbound["auto_route"] != true || inbound["strict_route"] != true {
		return errors.New("native Xray wrapper must own exactly one full-device strict TUN")
	}
	route, e := object(root["route"])
	if e != nil {
		return e
	}
	native, udp := "", ""
	seen := map[string]bool{}
	for _, item := range root["outbounds"].([]any) {
		outbound, e := object(item)
		if e != nil {
			return e
		}
		tag := text(outbound["tag"])
		if tag == "" || seen[tag] {
			return errors.New("native Xray route tags must be unique")
		}
		seen[tag] = true
		switch outbound["type"] {
		case Type:
			native = tag
		case "hysteria2":
			if udp != "" {
				return errors.New("dual-transport graph has ambiguous UDP ownership")
			}
			udp = tag
		case "direct":
			if e = keys(outbound, "type", "tag"); e != nil {
				return e
			}
		default:
			return errors.New("unowned extra transport in native Xray wrapper")
		}
	}
	if route["final"] != native {
		return errors.New("Xray wrapper final route must be its authenticated native outbound")
	}
	if mode != "split" && mode != "max" {
		if udp != "" {
			return errors.New("single Xray mode contains an unowned second transport")
		}
		return nil
	}
	tcpRule, udpRule := false, false
	rules, _ := route["rules"].([]any)
	for _, item := range rules {
		r, e := object(item)
		if e != nil {
			return e
		}
		switch text(r["network"]) {
		case "tcp":
			tcpRule = r["outbound"] == native
		case "udp":
			udpRule = r["outbound"] == udp && udp != ""
		}
	}
	if !tcpRule || !udpRule {
		return errors.New("dual-transport mode must retain its independent TCP Xray and UDP Hysteria2 routes")
	}
	return nil
}

var hostnameLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func safeHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.EqualFold(host, "localhost") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if !hostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func safeIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}
