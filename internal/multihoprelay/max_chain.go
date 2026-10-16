package multihoprelay

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"strings"

	"router-vpn/internal/applexray"
)

// MAXTags names one complete, independently owned encryption chain. Entry and
// exit use distinct names even when their generated source uses identical tags.
type MAXTags struct{ Root, Middle, Outer, Start string }

func CompleteMAXMode(mode string) bool {
	switch mode {
	case "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg":
		return true
	}
	return false
}

func MAXBaseMode(mode string) string {
	if !CompleteMAXMode(mode) {
		return ""
	}
	if strings.HasSuffix(mode, "-awg") {
		return "awg2-pq"
	}
	return "wg-pq"
}

func (tags MAXTags) valid(via string) bool {
	seen := map[string]bool{}
	for _, tag := range []string{tags.Root, tags.Middle, tags.Outer, tags.Start} {
		if !ident.MatchString(tag) || seen[tag] || tag == via {
			return false
		}
		seen[tag] = true
	}
	return via == "" || ident.MatchString(via)
}

func maxFields(value map[string]any, keys ...string) bool {
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range value {
		if !allowed[key] {
			return false
		}
	}
	return value != nil
}

func maxAES(value map[string]any) bool {
	if value["method"] != "2022-blake3-aes-256-gcm" || !validPort(value["server_port"]) {
		return false
	}
	password, ok := value["password"].(string)
	if !ok || password == "" || len(password) > 4096 {
		return false
	}
	for _, part := range strings.Split(password, ":") {
		key, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != part {
			return false
		}
	}
	return true
}

// ValidateMAXChain checks all mandatory layers, not just the bottom PQ label.
// The only optional edge is an authenticated outermost Start Layer. Every wire
// address and credential remains in its own node's chain; via owns outer I/O.
// Neither this validator nor RelabelMAXChain creates a socket, key handle or VPN.
func ValidateMAXChain(base map[string]any, outputs []any, mode, node, layer string, tags MAXTags, via string) error {
	bad := errors.New("complete MAX lost its captured encryption chain or routing owner")
	if !CompleteMAXMode(mode) || !proofID.MatchString(node) || !tags.valid(via) {
		return bad
	}
	if layer == "off" {
		layer = ""
	}
	extra := layer != ""
	if extra && !ValidLayerMode(layer) {
		return bad
	}
	count := 2
	if extra {
		count++
	}
	if len(outputs) != count || base["tag"] != tags.Root || base["detour"] != tags.Middle || base["mode"] != MAXBaseMode(mode) || base["node_id"] != node {
		return bad
	}
	if !maxFields(base, "type", "tag", "mode", "node_id", "system", "mtu", "address", "private_key", "listen_port", "peers", "pq", "amnezia", "detour") {
		return bad
	}
	checked, err := copyMap(base)
	if err != nil {
		return bad
	}
	if system, exists := checked["system"]; exists {
		if system != false {
			return bad
		}
		delete(checked, "system")
	}
	if port, exists := checked["listen_port"]; exists {
		if port != float64(0) {
			return bad
		}
		delete(checked, "listen_port")
	}
	delete(checked, "detour")
	peers, ok := checked["peers"].([]any)
	if !ok || len(peers) != 1 {
		return bad
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return bad
	}
	host, ok := peer["address"].(string)
	if !ok {
		return bad
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsPrivate() || !literalServer(host) {
		return bad
	}
	if _, err = validateTransport(Exit{Mode: MAXBaseMode(mode), NodeID: node, DNS: host, Transport: checked}); err != nil {
		return bad
	}
	values := map[string]map[string]any{}
	for _, raw := range outputs {
		value, ok := raw.(map[string]any)
		if !ok {
			return bad
		}
		tag, ok := value["tag"].(string)
		if !ok || values[tag] != nil || tag != tags.Middle && tag != tags.Outer && (!extra || tag != tags.Start) {
			return bad
		}
		values[tag] = value
	}
	middle, outer := values[tags.Middle], values[tags.Outer]
	if middle == nil || outer == nil || middle["type"] != "shadowsocks" || middle["server"] != host || middle["detour"] != tags.Outer || !maxAES(middle) || !maxFields(middle, "type", "tag", "server", "server_port", "method", "password", "detour") {
		return bad
	}
	outerVia := via
	if extra {
		outerVia = tags.Start
	}
	if outerVia == "" && outer["detour"] != nil || outerVia != "" && outer["detour"] != outerVia {
		return bad
	}
	outerCopy, err := copyMap(outer)
	if err != nil {
		return bad
	}
	delete(outerCopy, "detour")
	var outerHost string
	if strings.HasPrefix(mode, "max-tls-") {
		if outerCopy["type"] != applexray.Type || outerCopy["mode"] != "reality-xhttp" || len(outerCopy) != 4 {
			return bad
		}
		text, ok := outerCopy["config_json"].(string)
		if !ok {
			return bad
		}
		plan, err := applexray.Prepare("reality-xhttp", []byte(text))
		if err != nil || !literalServer(plan.ServerHost) || !completeMAXTLS([]byte(text)) {
			return bad
		}
		outerHost = plan.ServerHost
	} else {
		if outerCopy["type"] != "hysteria2" {
			return bad
		}
		if _, err = validateTransport(Exit{Mode: "hysteria2", DNS: host, Transport: outerCopy}); err != nil {
			return bad
		}
		outerHost, _ = outerCopy["server"].(string)
		tls, ok := outerCopy["tls"].(map[string]any)
		if !ok || tls["certificate_path"] != nil {
			return bad
		}
		// The chain crosses bundle boundaries: its trust must be self-contained.
		if !maxInlineCertificates(tls["certificate"]) {
			return bad
		}
	}
	if !extra {
		return nil
	}
	start := values[tags.Start]
	if start == nil || outerHost != host || !maxFields(start, "type", "tag", "server", "server_port", "method", "password", "detour") || !maxAES(start) || !literalServer(start["server"]) || start["password"] != middle["password"] {
		return bad
	}
	if via == "" && start["detour"] != nil || via != "" && start["detour"] != via {
		return bad
	}
	if layer == "aes-256-gcm" {
		if start["type"] != "shadowsocks" || start["server_port"] != middle["server_port"] {
			return bad
		}
	} else if start["type"] != "routervpn-aes-xor" || start["server_port"] != float64(8389) {
		return bad
	}
	return nil
}

func completeMAXTLS(raw []byte) bool {
	object, err := applexray.Object(raw)
	if err != nil {
		return false
	}
	outs, ok := object["outbounds"].([]any)
	if !ok || len(outs) != 1 {
		return false
	}
	out, ok := outs[0].(map[string]any)
	if !ok {
		return false
	}
	stream, ok := out["streamSettings"].(map[string]any)
	if !ok {
		return false
	}
	reality, ok := stream["realitySettings"].(map[string]any)
	if !ok || reality["fingerprint"] != "chrome" {
		return false
	}
	mask, ok := stream["finalmask"].(map[string]any)
	if !ok {
		return false
	}
	tcp, ok := mask["tcp"].([]any)
	return ok && len(tcp) > 0
}

// RelabelMAXChain returns independent maps and rewrites only its owned tag/edge
// names. It never changes any encryption key, remote service, policy or peer.
func RelabelMAXChain(base map[string]any, outputs []any, mode, node, layer string, from, to MAXTags, fromVia, toVia string) (map[string]any, []any, error) {
	if err := ValidateMAXChain(base, outputs, mode, node, layer, from, fromVia); err != nil {
		return nil, nil, err
	}
	if !to.valid(toVia) {
		return nil, nil, errors.New("invalid complete MAX destination names")
	}
	all := map[string]any{"base": base, "outputs": outputs}
	copy, err := copyMap(all)
	if err != nil {
		return nil, nil, err
	}
	result := copy["base"].(map[string]any)
	outs := copy["outputs"].([]any)
	names := map[string]string{from.Root: to.Root, from.Middle: to.Middle, from.Outer: to.Outer, from.Start: to.Start}
	for _, item := range append([]any{result}, outs...) {
		value := item.(map[string]any)
		value["tag"] = names[value["tag"].(string)]
		if detour, ok := value["detour"].(string); ok {
			if changed, present := names[detour]; present {
				value["detour"] = changed
				continue
			}
		}
		if toVia == "" {
			delete(value, "detour")
		} else {
			value["detour"] = toVia
		}
	}
	if err = ValidateMAXChain(result, outs, mode, node, layer, to, toVia); err != nil {
		return nil, nil, err
	}
	return result, outs, nil
}

// MAXChainBytes is bounded wire-independent serialization for private pairing.
func MAXChainBytes(base map[string]any, outputs []any) ([]byte, error) {
	raw, err := json.Marshal(map[string]any{"endpoint": base, "outbounds": outputs})
	if err != nil || len(raw) > 4<<20 {
		return nil, errors.New("complete MAX chain exceeds its private bound")
	}
	return raw, nil
}

func maxInlineCertificates(value any) bool {
	certificates, ok := value.([]any)
	if !ok {
		if text, valid := value.(string); valid {
			certificates = []any{text}
		} else {
			return false
		}
	}
	if len(certificates) == 0 || len(certificates) > 16 {
		return false
	}
	total := 0
	for _, raw := range certificates {
		text, ok := raw.(string)
		if !ok || len(text) == 0 || len(text) > 512*1024 {
			return false
		}
		total += len(text)
		if total > 512*1024 {
			return false
		}
		remaining := []byte(text)
		found := false
		for len(bytes.TrimSpace(remaining)) > 0 {
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return false
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return false
			}
			found = true
			remaining = rest
		}
		if !found {
			return false
		}
	}
	return true
}
