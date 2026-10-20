package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"

	"router-vpn/internal/applexray"
	"router-vpn/internal/mobileperf"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativecomposite"
	"router-vpn/internal/nativesip003"
)

const externalEntryTag = "external-entry"

var externalPredecessorError = errors.New("external predecessor lost its complete captured native ownership")

// A predecessor is a complete already-compiled single-node runtime. It is
// parsed independently of the direct exit so neither side can smuggle in,
// overwrite or silently drop another transport, resolver or service owner.
type externalPredecessor struct {
	graph, tun, final map[string]any
	nodes, resolvers  map[string]map[string]any
	finalTag          string
	restrictions      []any
}

func predecessorText(value map[string]any, field string) string {
	text, _ := value[field].(string)
	return text
}

func predecessorCopy(value map[string]any) map[string]any {
	encoded, _ := json.Marshal(value)
	var copied map[string]any
	_ = json.Unmarshal(encoded, &copied)
	return copied
}

func newExternalPredecessor(selection externalPolicyCapture) (*externalPredecessor, error) {
	if selection.PredecessorConfig == "" {
		return nil, nil
	}
	bad := externalPredecessorError
	if selection.EntryTag != externalEntryTag || selection.Entry == nil || selection.Entry["node_kind"] != "router-vpn" {
		return nil, bad
	}
	if !proofID.MatchString(predecessorText(selection.Entry, "node_proof_id")) {
		return nil, bad
	}
	if _, err := privateAPI(predecessorText(selection.Entry, "router_api")); err != nil {
		return nil, bad
	}
	token := predecessorText(selection.Entry, "api_token")
	if token == "" || len(token) > 4096 || strings.TrimSpace(token) != token {
		return nil, bad
	}
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			return nil, bad
		}
	}
	p := &externalPredecessor{nodes: map[string]map[string]any{}, resolvers: map[string]map[string]any{}}
	if exactJSON([]byte(selection.PredecessorConfig), &p.graph, 4<<20) != nil ||
		!maxFields(p.graph, "log", "inbounds", "outbounds", "endpoints", "route", "dns", "services") {
		return nil, bad
	}
	ins, ok := p.graph["inbounds"].([]any)
	if !ok || len(ins) != 1 {
		return nil, bad
	}
	p.tun, ok = ins[0].(map[string]any)
	if !ok || p.tun["type"] != "tun" || p.tun["auto_route"] != true || p.tun["strict_route"] != true ||
		!exactID.MatchString(predecessorText(p.tun, "tag")) ||
		!maxFields(p.tun, "type", "tag", "interface_name", "address", "mtu", "stack", "auto_route", "strict_route", "route_address") {
		return nil, bad
	}
	if _, err := mtuNumber(p.tun["mtu"]); err != nil {
		return nil, err
	}
	route, ok := p.graph["route"].(map[string]any)
	if !ok || !maxFields(route, "final", "rules", "auto_detect_interface", "default_domain_resolver") {
		return nil, bad
	}
	if raw, exists := route["auto_detect_interface"]; exists && raw != true {
		return nil, bad
	}
	p.finalTag = predecessorText(route, "final")
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, ok := p.graph[family].([]any)
		if p.graph[family] != nil && !ok || len(rows) > 32 {
			return nil, bad
		}
		for _, raw := range rows {
			node, ok := raw.(map[string]any)
			tag := predecessorText(node, "tag")
			if !ok || !exactID.MatchString(tag) || p.nodes[tag] != nil || tag == ExternalFinalTag || strings.HasPrefix(tag, externalEntryTag) {
				return nil, bad
			}
			p.nodes[tag] = node
			if err := p.validateNode(node, family, selection.Entry); err != nil {
				return nil, err
			}
		}
	}
	p.final = p.nodes[p.finalTag]
	if p.final == nil || p.final["type"] == "direct" || p.final["type"] == "block" {
		return nil, bad
	}
	if err := p.validateFamily(selection.Entry); err != nil {
		return nil, err
	}
	if err := p.validateSelectedMode(selection.Profile); err != nil {
		return nil, err
	}
	if err := p.captureRules(route); err != nil {
		return nil, err
	}
	services, ok := p.graph["services"].([]any)
	if p.graph["services"] != nil && !ok || len(services) > 4 {
		return nil, bad
	}
	seen := map[string]bool{}
	for _, raw := range services {
		service, ok := raw.(map[string]any)
		tag := predecessorText(service, "tag")
		if !ok || service["type"] != mobileperf.CoverType || !exactID.MatchString(tag) || seen[tag] ||
			!maxFields(service, "type", "tag", "node_id", "api", "sink", "rate_kbps", "proof_tag", "packet_tag") {
			return nil, bad
		}
		seen[tag] = true
	}
	// Re-running the existing performance compiler must be an identity operation:
	// every requested cover service, target, identity, rate and Jumbo TUN value
	// was already frozen by the host's ordinary single-node preparation.
	pair, _ := json.Marshal(map[string]any{"entry": selection.Entry, "exit": selection.Entry})
	before, _ := json.Marshal(p.graph)
	after, err := mobileperf.Apply(string(before), string(pair))
	var checked map[string]any
	if err != nil || json.Unmarshal([]byte(after), &checked) != nil || !reflect.DeepEqual(p.graph, checked) {
		return nil, errors.New("external predecessor performance differs from its captured profile")
	}
	if err := p.captureDNS(route); err != nil {
		return nil, err
	}
	if err := p.validateDependencies(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *externalPredecessor) validateNode(node map[string]any, family string, profile map[string]any) error {
	bad := externalPredecessorError
	copy := predecessorCopy(node)
	detour := predecessorText(node, "detour")
	if raw, exists := node["detour"]; exists && (raw != detour || !exactID.MatchString(detour) || detour == node["tag"]) {
		return bad
	}
	delete(copy, "detour")
	delete(copy, "domain_resolver")
	kind := predecessorText(node, "type")
	endpoint := kind == "wireguard" || kind == AmneziaType || kind == PQType
	if endpoint != (family == "endpoints") {
		return bad
	}
	// A remote loopback is meaningful only behind its explicit encrypted parent.
	// Substitute a private validation address in this disposable copy; preserve
	// the actual address, keys and detour in the imported runtime object.
	if host, err := netip.ParseAddr(predecessorText(copy, "server")); err == nil && host.IsLoopback() && detour != "" {
		copy["server"] = "10.0.0.1"
	}
	switch kind {
	case "wireguard":
		if err := externalTransport(copy, "wireguard", "", family, true); err != nil {
			return err
		}
		peer := copy["peers"].([]any)[0].(map[string]any)
		if externalDigest([]byte("router-vpn-node-proof-v1\n"+predecessorText(peer, "public_key"))) != profile["node_proof_id"] {
			return errors.New("external predecessor WireGuard peer differs from its captured node")
		}
	case AmneziaType:
		encoded, _ := json.Marshal(node)
		_, err := AmneziaRuntimeConfig(string(encoded))
		return err
	case PQType:
		encoded, _ := json.Marshal(node)
		runtime, err := PQRuntimeConfig(string(encoded))
		runtime.PQ.Erase()
		if err != nil || node["node_id"] != profile["node_proof_id"] {
			return bad
		}
	case "shadowsocks":
		if node["plugin"] != nil {
			return nativesip003.ValidateTCPOutbound(copy)
		}
		return validateProxyEntry(copy, kind)
	case "hysteria2":
		return validateProxyEntry(copy, kind)
	case "routervpn-aes-xor":
		copy["type"] = "shadowsocks"
		if copy["method"] != NativeStartLayerMethod {
			return bad
		}
		return validateProxyEntry(copy, "shadowsocks")
	case applexray.Type:
		mode := predecessorText(node, "mode")
		if CompositeMode(mode) {
			if len(copy) != 4 || !maxFields(copy, "type", "tag", "mode", "config_json") {
				return bad
			}
			_, err := applexray.Prepare(mode, []byte(predecessorText(copy, "config_json")))
			return err
		}
		return validateXrayEntry(copy, mode)
	case "naive":
		mode := "naive-h2"
		if copy["quic"] == true {
			mode = "naive-h3"
		}
		return multihoprelay.ValidateNaiveTransport(copy, mode)
	case nativecomposite.Type:
		if len(node) != 6 || !maxFields(node, "type", "tag", "mode", "node_id", "tcp", "udp") || node["node_id"] != profile["node_proof_id"] ||
			nativecomposite.ValidateOwner(predecessorText(node, "mode"), predecessorText(node, "node_id"), predecessorText(node, "tag"), predecessorText(node, "tcp"), predecessorText(node, "udp")) != nil {
			return bad
		}
	case "direct", "block":
		if len(node) != 2 {
			return bad
		}
	default:
		return errors.New("external predecessor contains an unknown native transport owner")
	}
	return nil
}

func (p *externalPredecessor) validateFamily(profile map[string]any) error {
	layer, err := externalOptionalString(profile, "start_layer")
	if err != nil {
		return err
	}
	if layer == "off" {
		layer = ""
	}
	if !nativecomposite.Layer(layer) {
		return externalPredecessorError
	}
	node := predecessorText(profile, "node_proof_id")
	if p.final["type"] == nativecomposite.Type {
		_, err := nativecomposite.Extract(p.graph, predecessorText(p.final, "mode"), node, layer, p.finalTag, nativecomposite.SourcePrefix, "")
		return err
	}
	if p.nodes[MAXOuterTag] != nil || p.nodes[MAXShadowsocksTag] != nil {
		mode := "max-quic-wg"
		if p.nodes[MAXOuterTag]["type"] == applexray.Type {
			mode = "max-tls-wg"
		}
		if p.final["mode"] == "awg2-pq" {
			mode = strings.TrimSuffix(mode, "wg") + "awg"
		}
		return multihoprelay.ValidateMAXChain(p.final, p.graph["outbounds"].([]any), mode, node, layer, multihoprelay.MAXTags{Root: p.finalTag, Middle: MAXShadowsocksTag, Outer: MAXOuterTag, Start: MAXStartLayerTag}, "")
	}
	start := p.nodes[NativeStartLayerTag]
	if start != nil {
		if p.final["detour"] != NativeStartLayerTag || layer == "" || layer == "aes-256-gcm" && start["type"] != "shadowsocks" || layer == "aes-256-gcm+xor-whitening" && start["type"] != "routervpn-aes-xor" || start["method"] != NativeStartLayerMethod {
			return externalPredecessorError
		}
	} else if layer != "" {
		// Shadowsocks already supplies the selected AES layer; XOR adds its
		// native authenticated wrapper without duplicating the same service.
		if p.final["method"] != NativeStartLayerMethod || layer == "aes-256-gcm" && p.final["type"] != "shadowsocks" || layer == "aes-256-gcm+xor-whitening" && p.final["type"] != "routervpn-aes-xor" {
			return externalPredecessorError
		}
	} else if p.final["type"] == "routervpn-aes-xor" {
		return externalPredecessorError
	}
	return nil
}

func (p *externalPredecessor) validateSelectedMode(profile map[string]any) error {
	mode, err := externalOptionalString(profile, "multihop_entry_mode")
	if err != nil {
		return err
	}
	if mode == "" {
		return nil // Older captures have no separate saved mode label.
	}
	actual := predecessorText(p.final, "type")
	switch actual {
	case "wireguard":
		actual = "wg"
	case AmneziaType:
		// Fast and Strong are distinct imported asset selections. Their AWG
		// parameters are intentionally not universal constants; the host must
		// compile the exact selected asset and this merger preserves every byte.
		if mode == "awg2-fast" || mode == "awg2-strong" {
			return nil
		}
	case PQType:
		actual = predecessorText(p.final, "mode")
		if p.nodes[MAXOuterTag] != nil || p.nodes[MAXShadowsocksTag] != nil {
			actual = "max-quic-wg"
			if p.nodes[MAXOuterTag]["type"] == applexray.Type {
				actual = "max-tls-wg"
			}
			if p.final["mode"] == "awg2-pq" {
				actual = strings.TrimSuffix(actual, "wg") + "awg"
			}
		}
	case applexray.Type, nativecomposite.Type:
		actual = predecessorText(p.final, "mode")
	case "routervpn-aes-xor":
		actual = "shadowsocks"
	case "naive":
		actual = "naive-h2"
		if p.final["quic"] == true {
			actual = "naive-h3"
		}
	}
	if actual != mode {
		return errors.New("external predecessor differs from the captured entry mode")
	}
	return nil
}

func (p *externalPredecessor) captureRules(route map[string]any) error {
	rows, ok := route["rules"].([]any)
	if route["rules"] != nil && !ok || len(rows) > 64 {
		return externalPredecessorError
	}
	for _, raw := range rows {
		rule, ok := raw.(map[string]any)
		if !ok || !maxFields(rule, "action", "inbound", "ip_version", "ip_cidr", "protocol", "network", "port", "outbound") {
			return externalPredecessorError
		}
		switch rule["action"] {
		case "reject", "sniff":
			if rule["outbound"] != nil {
				return externalPredecessorError
			}
			p.restrictions = append(p.restrictions, rule)
		case "hijack-dns":
			if rule["outbound"] != nil || rule["protocol"] != "dns" && rule["port"] != float64(53) {
				return externalPredecessorError
			}
		case "route", nil:
			if rule["outbound"] != p.finalTag {
				return errors.New("external predecessor cannot retain a competing application route")
			}
		default:
			return externalPredecessorError
		}
		if raw, exists := rule["inbound"]; exists {
			rows, ok := raw.([]any)
			if !ok || len(rows) != 1 || rows[0] != p.tun["tag"] {
				return externalPredecessorError
			}
		}
	}
	return nil
}

func (p *externalPredecessor) applyMTU(tun, exit map[string]any, selection externalPolicyCapture) (int, int, string, error) {
	entry := predecessorCopy(p.final)
	switch entry["type"] {
	case AmneziaType, PQType:
		entry["type"] = "wireguard"
	}
	if entry["type"] != "wireguard" {
		// The full predecessor's proxy TUN value is an actual configured
		// baseline (including compatible Jumbo), never historical measurement.
		tun["mtu"] = p.tun["mtu"]
	}
	mtu, entryMTU, policy, err := externalMTUPolicy(tun, exit, entry, selection.Profile, selection.Entry)
	if err != nil {
		return 0, 0, "", err
	}
	if selection.Entry["jumbo_tun"] == true && mtu != 9000 {
		return 0, 0, "", errors.New("captured predecessor Jumbo TUN conflicts with the selected external exit")
	}
	if entryMTU != 0 {
		p.final["mtu"] = entryMTU
	}
	return mtu, entryMTU, policy, nil
}

func predecessorNamespace(family, tag string) string {
	return externalEntryTag + "-" + family + "-" + externalDigest([]byte(tag))[:24]
}

func (p *externalPredecessor) merge(graph, tun, exit map[string]any) error {
	bad := externalPredecessorError
	names := map[string]string{}
	for tag := range p.nodes {
		names[tag] = predecessorNamespace("node", tag)
	}
	names[p.finalTag] = externalEntryTag
	dnsNames := map[string]string{}
	for tag := range p.resolvers {
		dnsNames[tag] = predecessorNamespace("dns", tag)
	}
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := p.graph[family].([]any)
		for _, raw := range rows {
			node := raw.(map[string]any)
			node["tag"] = names[predecessorText(node, "tag")]
			for _, field := range []string{"detour", "tcp", "udp"} {
				if tag, exists := node[field]; exists {
					text, ok := tag.(string)
					if !ok || names[text] == "" {
						return bad
					}
					node[field] = names[text]
				}
			}
			if err := predecessorRelabelResolver(node, dnsNames); err != nil {
				return err
			}
		}
		original, _ := graph[family].([]any)
		graph[family] = append(original, rows...)
	}
	dns := graph["dns"].(map[string]any)
	servers, _ := dns["servers"].([]any)
	if original, ok := p.graph["dns"].(map[string]any); ok {
		rows, _ := original["servers"].([]any)
		for _, raw := range rows {
			server := raw.(map[string]any)
			server["tag"] = dnsNames[predecessorText(server, "tag")]
			if tag, exists := server["detour"]; exists {
				text, ok := tag.(string)
				if !ok || names[text] == "" {
					return bad
				}
				server["detour"] = names[text]
			}
			if err := predecessorRelabelResolver(server, dnsNames); err != nil {
				return err
			}
			servers = append(servers, server)
		}
	}
	dns["servers"] = servers
	if rows, ok := p.graph["services"].([]any); ok && len(rows) != 0 {
		for _, raw := range rows {
			service := raw.(map[string]any)
			service["tag"] = predecessorNamespace("service", predecessorText(service, "tag"))
			for _, field := range []string{"proof_tag", "packet_tag"} {
				name := names[predecessorText(service, field)]
				if name == "" {
					return bad
				}
				service[field] = name
			}
		}
		graph["services"] = rows
	}
	for _, raw := range p.restrictions {
		raw.(map[string]any)["inbound"] = []any{tun["tag"]}
	}
	route := graph["route"].(map[string]any)
	route["rules"] = append(p.restrictions, route["rules"].([]any)...)
	exit["detour"] = externalEntryTag
	return nil
}
