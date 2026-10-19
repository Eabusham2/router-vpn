// Package nativecomposite preserves the generated TCP and UDP transports under
// one explicit runtime owner. It does not create listeners, routes or engines.
package nativecomposite

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"

	"router-vpn/internal/applexray"
	"router-vpn/internal/nativesip003"
)

const Type = "routervpn-composite"
const PlanType = "routervpn-composite-plan"
const MaxSize = 4 << 20
const TCPTag = "routervpn-composite-tcp"
const UDPTag = "routervpn-composite-udp"
const StartTag = "routervpn-composite-start"
const SourcePrefix = "routervpn-composite-"

var id = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)
var nodeID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var invalid = errors.New("composite transport lost its exact TCP/UDP authentication or routing owner")

func Mode(mode string) bool { return mode == "ss-v2ray" || mode == "split" || mode == "max" }
func Layer(mode string) bool {
	return mode == "" || mode == "aes-256-gcm" || mode == "aes-256-gcm+xor-whitening"
}
func text(value any) string { result, _ := value.(string); return result }
func fields(value map[string]any, allowed ...string) bool {
	if value == nil {
		return false
	}
	keys := map[string]bool{}
	for _, key := range allowed {
		keys[key] = true
	}
	for key := range value {
		if !keys[key] {
			return false
		}
	}
	return true
}
func object(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaxSize {
		return nil, invalid
	}
	if _, err := nativesip003.Object(raw); err != nil {
		return nil, invalid
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil || result == nil {
		return nil, invalid
	}
	return result, nil
}
func copyMap(value map[string]any) (map[string]any, error) {
	if !validText(value, 0) {
		return nil, invalid
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, invalid
	}
	return object(raw)
}

// encoding/json replaces malformed Go strings with U+FFFD. Reject them before
// serialization so a frozen credential or node name cannot change silently.
func validText(value any, depth int) bool {
	if depth > 48 {
		return false
	}
	switch item := value.(type) {
	case string:
		return utf8.ValidString(item)
	case map[string]any:
		for name, child := range item {
			if !utf8.ValidString(name) || !validText(child, depth+1) {
				return false
			}
		}
	case []any:
		for _, child := range item {
			if !validText(child, depth+1) {
				return false
			}
		}
	case []string:
		for _, child := range item {
			if !utf8.ValidString(child) {
				return false
			}
		}
	}
	return true
}
func literal(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" || ip.Is4In6() {
		return false
	}
	return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}
func port(value any) bool {
	valueNumber, ok := value.(float64)
	return ok && valueNumber >= 1 && valueNumber <= 65535 && valueNumber == float64(int(valueNumber))
}
func key(value any, multiple bool) bool {
	encoded, ok := value.(string)
	if !ok || encoded == "" || len(encoded) > 4096 || !utf8.ValidString(encoded) {
		return false
	}
	parts := strings.Split(encoded, ":")
	if !multiple && len(parts) != 1 {
		return false
	}
	for _, part := range parts {
		raw, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != part {
			return false
		}
	}
	return true
}

func certificates(value any) bool {
	var source string
	switch data := value.(type) {
	case string:
		source = data
	case []any:
		for _, line := range data {
			part, ok := line.(string)
			if !ok {
				return false
			}
			source += part + "\n"
		}
	default:
		return false
	}
	if len(source) == 0 || len(source) > 256<<10 || !utf8.ValidString(source) {
		return false
	}
	raw := []byte(source)
	count := 0
	for len(bytes.TrimSpace(raw)) > 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, tail := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
		raw = tail
	}
	return count > 0
}

// ValidateOwner is also used by the actual native outbound factory. A composite
// always names two distinct children; no runtime selector can replace a lane.
func ValidateOwner(mode, node, root, tcp, udp string) error {
	if !Mode(mode) || !nodeID.MatchString(node) || !id.MatchString(root) || !id.MatchString(tcp) || !id.MatchString(udp) || tcp == udp || tcp == root || udp == root {
		return invalid
	}
	if !strings.HasSuffix(tcp, "tcp") || !strings.HasSuffix(udp, "udp") || strings.TrimSuffix(tcp, "tcp") != strings.TrimSuffix(udp, "udp") {
		return invalid
	}
	return nil
}

// ValidatePlan validates a private, non-runnable description. Its type is not
// registered in the core. Relabel is the only publication into runtime tags.
func ValidatePlan(plan map[string]any, mode, node, layer string) error {
	var err error
	plan, err = copyMap(plan)
	if err != nil {
		return err
	}
	if !Mode(mode) || !nodeID.MatchString(node) || !Layer(layer) || !fields(plan, "type", "mode", "node_id", "start_layer", "tcp", "udp", "start") || plan["type"] != PlanType || plan["mode"] != mode || plan["node_id"] != node || plan["start_layer"] != layer {
		return invalid
	}
	tcp, okTCP := plan["tcp"].(map[string]any)
	udp, okUDP := plan["udp"].(map[string]any)
	if !okTCP || !okUDP || tcp["tag"] != TCPTag || udp["tag"] != UDPTag {
		return invalid
	}
	via := ""
	if layer != "" {
		via = StartTag
	}
	for _, out := range []map[string]any{tcp, udp} {
		if via == "" && out["detour"] != nil || via != "" && out["detour"] != via {
			return invalid
		}
	}
	tcpCopy, err := copyMap(tcp)
	if err != nil {
		return invalid
	}
	delete(tcpCopy, "detour")
	var host string
	if mode == "ss-v2ray" {
		if nativesip003.ValidateTCPOutbound(tcpCopy) != nil {
			return invalid
		}
		host = text(tcpCopy["server"])
	} else {
		if len(tcpCopy) != 4 || !fields(tcpCopy, "type", "tag", "mode", "config_json") || tcpCopy["type"] != applexray.Type || tcpCopy["mode"] != mode {
			return invalid
		}
		prepared, err := applexray.Prepare(mode, []byte(text(tcpCopy["config_json"])))
		if err != nil {
			return invalid
		}
		host = prepared.ServerHost
	}
	if !literal(host) || host != udp["server"] || !fields(udp, "type", "tag", "server", "server_port", "password", "tls", "up_mbps", "down_mbps", "obfs", "detour") || udp["type"] != "hysteria2" || !port(udp["server_port"]) {
		return invalid
	}
	password, ok := udp["password"].(string)
	if !ok || password == "" || len(password) > 4096 || !utf8.ValidString(password) {
		return invalid
	}
	for _, name := range []string{"up_mbps", "down_mbps"} {
		if raw, exists := udp[name]; exists {
			value, ok := raw.(float64)
			if !ok || value <= 0 || value > 1000000 {
				return invalid
			}
		}
	}
	if raw, exists := udp["obfs"]; exists {
		obfs, ok := raw.(map[string]any)
		if !ok || len(obfs) != 2 || !fields(obfs, "type", "password") || obfs["type"] != "salamander" || text(obfs["password"]) == "" || len(text(obfs["password"])) > 4096 || !utf8.ValidString(text(obfs["password"])) {
			return invalid
		}
	}
	tls, ok := udp["tls"].(map[string]any)
	if !ok || !fields(tls, "enabled", "server_name", "insecure", "alpn", "certificate", "min_version", "max_version") || tls["enabled"] != true || tls["insecure"] != nil && tls["insecure"] != false || text(tls["server_name"]) == "" || !certificates(tls["certificate"]) {
		return invalid
	}
	if raw, exists := tls["alpn"]; exists {
		alpn, ok := raw.([]any)
		if !ok || len(alpn) != 1 || alpn[0] != "h3" {
			return invalid
		}
	}
	for _, name := range []string{"min_version", "max_version"} {
		if raw, exists := tls[name]; exists && raw != "1.3" {
			return invalid
		}
	}
	if layer == "" {
		if _, exists := plan["start"]; exists {
			return invalid
		}
		return nil
	}
	start, ok := plan["start"].(map[string]any)
	if !ok || len(start) != 6 || !fields(start, "type", "tag", "server", "server_port", "method", "password") || start["tag"] != StartTag || !literal(text(start["server"])) || !port(start["server_port"]) || start["method"] != "2022-blake3-aes-256-gcm" || !key(start["password"], true) {
		return invalid
	}
	private, _ := netip.ParseAddr(host)
	if !private.IsPrivate() || layer == "aes-256-gcm" && start["type"] != "shadowsocks" || layer == "aes-256-gcm+xor-whitening" && (start["type"] != "routervpn-aes-xor" || start["server_port"] != float64(8389)) {
		return invalid
	}
	return nil
}

// Relabel returns fresh runtime objects with disjoint child tags. Each physical
// TCP/UDP socket traverses via; with a Start Layer both traverse its owned AES.
func Relabel(plan map[string]any, mode, node, layer, root, prefix, via string) (map[string]any, []any, error) {
	if err := ValidatePlan(plan, mode, node, layer); err != nil {
		return nil, nil, err
	}
	tcpTag, udpTag, startTag := prefix+"tcp", prefix+"udp", prefix+"start"
	if ValidateOwner(mode, node, root, tcpTag, udpTag) != nil || !id.MatchString(startTag) || root == startTag || via == root || via == tcpTag || via == udpTag || via == startTag || via != "" && !id.MatchString(via) {
		return nil, nil, invalid
	}
	owner := map[string]any{"type": Type, "tag": root, "mode": mode, "node_id": node, "tcp": tcpTag, "udp": udpTag}
	outputs := make([]any, 0, 3)
	for _, name := range []string{"tcp", "udp", "start"} {
		value, exists := plan[name]
		if !exists {
			continue
		}
		out, err := copyMap(value.(map[string]any))
		if err != nil {
			return nil, nil, err
		}
		out["tag"] = prefix + name
		detour := via
		if name != "start" && layer != "" {
			detour = startTag
		}
		if detour == "" {
			delete(out, "detour")
		} else {
			out["detour"] = detour
		}
		outputs = append(outputs, out)
	}
	return owner, outputs, nil
}

// Extract validates a composite embedded in a larger graph. It checks both
// lane edges and every private field before returning a canonical private plan.
func Extract(graph map[string]any, mode, node, layer, root, prefix, via string) (map[string]any, error) {
	if via != "" && (!id.MatchString(via) || via == root || via == prefix+"tcp" || via == prefix+"udp" || via == prefix+"start") || !validText(graph, 0) {
		return nil, invalid
	}
	values, ok := graph["outbounds"].([]any)
	if !ok {
		return nil, invalid
	}
	byTag := map[string]map[string]any{}
	for _, raw := range values {
		out, ok := raw.(map[string]any)
		if !ok || !id.MatchString(text(out["tag"])) || byTag[text(out["tag"])] != nil {
			return nil, invalid
		}
		byTag[text(out["tag"])] = out
	}
	owner := byTag[root]
	if len(owner) != 6 || !fields(owner, "type", "tag", "mode", "node_id", "tcp", "udp") || owner["type"] != Type || owner["mode"] != mode || owner["node_id"] != node || owner["tcp"] != prefix+"tcp" || owner["udp"] != prefix+"udp" || ValidateOwner(mode, node, root, prefix+"tcp", prefix+"udp") != nil {
		return nil, invalid
	}
	plan := map[string]any{"type": PlanType, "mode": mode, "node_id": node, "start_layer": layer}
	for _, name := range []string{"tcp", "udp", "start"} {
		out := byTag[prefix+name]
		if name == "start" && layer == "" {
			if out != nil {
				return nil, invalid
			}
			continue
		}
		if out == nil {
			return nil, invalid
		}
		expectedVia := via
		if name != "start" && layer != "" {
			expectedVia = prefix + "start"
		}
		if expectedVia == "" && out["detour"] != nil || expectedVia != "" && out["detour"] != expectedVia {
			return nil, invalid
		}
		copied, err := copyMap(out)
		if err != nil {
			return nil, err
		}
		copied["tag"] = SourcePrefix + name
		if name != "start" && layer != "" {
			copied["detour"] = StartTag
		} else {
			delete(copied, "detour")
		}
		plan[name] = copied
	}
	for name := range byTag {
		if strings.HasPrefix(name, prefix) && name != prefix+"tcp" && name != prefix+"udp" && name != prefix+"start" {
			return nil, invalid
		}
	}
	if err := ValidatePlan(plan, mode, node, layer); err != nil {
		return nil, err
	}
	return plan, nil
}
