package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"router-vpn/internal/applexray"
	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/mobileperf"
	"router-vpn/internal/routechoice"
	"strconv"
	"strings"
)

// importedEntry is created only from the complete independently validated
// imported transport and paired final sources. Metadata cannot create it.
type importedEntry struct {
	source, metadata, profile, publicIP string
	openvpnTransport                    map[string]any
	openvpnMTU                          uint32
}

// NewImportedEntry composes a captured SOCKS5, SS2022, Hysteria2, WireGuard,
// AmneziaWG, HTTP/HTTPS CONNECT or OpenVPN predecessor and a compatible paired
// Shadowsocks, Hysteria2, WireGuard or AmneziaWG final. SOCKS5, SS2022, Hysteria2
// and HTTP/HTTPS CONNECT also support the paired REALITY/Vision final with
// independently captured Start Layers.
// Packet-to-packet
// composition requires the complete configured data/control envelope. SOCKS5's
// SS/Hysteria2/WG/AWG/REALITY finals retain independently provisioned Start Layers.
// HTTP/HTTPS CONNECT retains TCP-only SS2022 unless the captured final supplies
// exact configured UoT-v2 authority. Its independently captured REALITY final
// supplies VLESS datagrams over that stream without borrowing SS authority.
// Compilation proves neither live identity.
func NewImportedEntry(entryConfig, entryCapture, exitMode, exitFiles, exitProfile, exitStart, dnsBootstrap string) (*Controller, error) {
	bad := errors.New("imported entry requires a captured standalone SOCKS5, SS2022, Hysteria2, WireGuard, AmneziaWG, OpenVPN or HTTP/HTTPS CONNECT source and a compatible paired final in Local execution")
	var selection externalPolicyCapture
	if exactJSON([]byte(entryCapture), &selection, 8<<20) != nil {
		return nil, bad
	}
	socksXrayFinal := selection.Protocol == "socks5" && exitMode == "reality-vision"
	connectEntry := selection.Protocol == "http-connect" || selection.Protocol == "https-connect"
	proxyXrayFinal := socksXrayFinal || (selection.Protocol == "shadowsocks" || selection.Protocol == "hysteria2" || connectEntry) && exitMode == "reality-vision"
	if selection.Entry != nil || selection.EntryTag != "" || selection.PredecessorConfig != "" || selection.Execution != nil || (selection.Protocol != "shadowsocks" && selection.Protocol != "hysteria2" && selection.Protocol != "wireguard" && selection.Protocol != "amneziawg" && selection.Protocol != "socks5" && selection.Protocol != "http-connect" && selection.Protocol != "https-connect" && selection.Protocol != "openvpn") || selection.Profile["node_kind"] != "external" || (!proxyXrayFinal && exitMode != "shadowsocks" && exitMode != "hysteria2" && exitMode != "wg" && exitMode != "awg2-fast" && exitMode != "awg2-strong") {
		return nil, bad
	}

	// An imported operator address is a public-path proof, never a paired API.
	for _, key := range []string{"node_proof_id", "router_api", "api_token"} {
		if v := selection.Profile[key]; v != nil && v != "" {
			return nil, bad
		}
	}
	// The entry's standalone DNS selection does not govern application DNS in
	// this two-hop path. Validate its transport/layer using a private compiler
	// projection; retain the exact original input in the source digest below.
	transportSelection := selection
	transportSelection.Profile = predecessorCopy(selection.Profile)
	transportSelection.Profile["dns_mode"] = "rescue"
	transportSelection.DNSBootstrap = nil
	transportCapture, _ := json.Marshal(transportSelection)
	entry, err := NewExternalPolicy(entryConfig, string(transportCapture))
	if err != nil {
		return nil, err
	}
	var entryMeta externalPolicyMetadata
	if json.Unmarshal([]byte(entry.Metadata()), &entryMeta) != nil || entryMeta.Execution != "" && entryMeta.Execution != "local" {
		return nil, bad
	}
	// Legacy paired profiles predate node_kind. Normalize only that absent or
	// empty discriminator for compilation; pairing credentials remain mandatory
	// and the source digest below retains the exact original bytes.
	var finalProfile map[string]any
	if exactJSON([]byte(exitProfile), &finalProfile, 256<<10) != nil || finalProfile == nil {
		return nil, bad
	}
	if value, present := finalProfile["node_kind"]; present {
		kind, ok := value.(string)
		if !ok || (kind != "" && kind != "router-vpn") {
			return nil, bad
		}
	}
	finalProfile["node_kind"] = "router-vpn"
	normalizedFinal, _ := json.Marshal(finalProfile)
	exit, err := NewNodeProfile(exitMode, exitFiles, string(normalizedFinal), exitStart, dnsBootstrap)
	if err != nil {
		return nil, err
	}
	if selection.ExitID == exit.profile["id"] {
		return nil, bad
	}

	if raw := exit.profile["multihop_execution"]; raw != nil && raw != "" && raw != "local" {
		return nil, bad
	}
	var first, last map[string]any
	if json.Unmarshal([]byte(entry.Config()), &first) != nil || json.Unmarshal([]byte(exit.Config()), &last) != nil {
		return nil, bad
	}
	if selection.Protocol == "openvpn" {
		if err := importedOpenVPNLayerGraph(first, selection); err != nil {
			return nil, err
		}
	}
	// All predecessor edges were checked by ExternalPolicy; copy only its actual
	// transport closure. Its DNS and proof listener are not application policy.
	names := map[string]string{ExternalFinalTag: "entry-wg"}
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := first[family].([]any)
		for _, raw := range rows {
			node := raw.(map[string]any)
			tag := predecessorText(node, "tag")
			if tag != ExternalFinalTag {
				names[tag] = "imported-entry-" + tag
			}
		}
	}
	var original map[string]any
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := first[family].([]any)
		for _, raw := range rows {
			node := raw.(map[string]any)
			tag := predecessorText(node, "tag")
			if tag == ExternalFinalTag {
				original = node
			}
			node["tag"] = names[tag]
			if d := predecessorText(node, "detour"); d != "" {
				if names[d] == "" {
					return nil, bad
				}
				node["detour"] = names[d]
			}
		}
	}
	expectedType := selection.Protocol
	if selection.Protocol == "socks5" {
		expectedType = "socks"
	}
	if connectEntry {
		expectedType = "http"
	}
	if selection.Protocol == "openvpn" {
		expectedType = externalOpenVPNType
	}
	if selection.Protocol == "amneziawg" {
		expectedType = AmneziaType
	}
	if original == nil || original["type"] != expectedType || selection.Protocol == "shadowsocks" && !importedSS2022Method(predecessorText(original, "method")) {
		return nil, bad
	}
	if proxyXrayFinal && selection.Protocol == "shadowsocks" && !importedSS2022Credentials(predecessorText(original, "method"), predecessorText(original, "password")) {
		return nil, bad
	}
	// Each transport has its own authenticated layer. Attach the final's outer
	// edge, preserving an inner detour if its compiler produced one.
	var final map[string]any
	byTag := map[string]map[string]any{}
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := last[family].([]any)
		for _, raw := range rows {
			n := raw.(map[string]any)
			byTag[predecessorText(n, "tag")] = n
			if n["tag"] == "proxy" {
				final = n
			}
		}
	}
	if final == nil {
		return nil, bad
	}
	if proxyXrayFinal {
		// The original paired-node compiler owns the complete VLESS/REALITY
		// source and its separately captured same-node Start Layer. Validate
		// that exact inner edge before attaching the final's outermost edge to
		// the independently captured entry; arbitrary detours are never stripped.
		layer := predecessorText(exit.profile, "start_layer")
		if layer == "" || layer == "off" {
			err = applexray.ValidateSingleTransport(final, "reality-vision")
		} else {
			err = validateNestedXrayExit(final, "reality-vision", applexray.StartLayerTag)
		}
		if err != nil {
			return nil, err
		}
	}
	connectCapability := ""
	if connectEntry {
		connectCapability, err = importedCONNECTCapture(last, final, entryMeta.StartLayer, exitMode, exit.profile, exitFiles)
		if err != nil {
			return nil, err
		}
	}
	outer := final
	for i := 0; predecessorText(outer, "detour") != ""; i++ {
		if i > 1 {
			return nil, bad
		}
		outer = byTag[predecessorText(outer, "detour")]
		if outer == nil {
			return nil, bad
		}
	}
	if (exitMode == "wg" || exitMode == "awg2-fast" || exitMode == "awg2-strong") && predecessorText(final, "detour") != "" && predecessorText(outer, "server") != predecessorText(exit.profile, "endpoint") {
		return nil, errors.New("paired packet final and Start Layer belong to different node endpoints")
	}
	var nested *awgpolicy.PacketEnvelope
	if (selection.Protocol == "wireguard" || selection.Protocol == "amneziawg" || selection.Protocol == "openvpn") && awgpolicy.WireGuardFamily(exitMode) {
		var layer map[string]any
		if outer != nil && predecessorText(final, "detour") != "" {
			layer = outer
		}
		envelope, failure := awgpolicy.EndpointEnvelope(final, layer)
		if failure != nil {
			return nil, failure
		}
		nested = &envelope
	}
	requestedPacketMTU, effectivePacketMTU := 0, 0
	if nested != nil {
		requestedPacketMTU, err = mtuNumber(final["mtu"])
		if err != nil {
			return nil, err
		}
	}
	outer["detour"] = "entry-wg"
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := first[family].([]any)
		if len(rows) == 0 {
			continue
		}
		existing, _ := last[family].([]any)
		last[family] = append(existing, rows...)
	}
	tun := last["inbounds"].([]any)[0].(map[string]any)
	envelope := 0
	if nested != nil {
		envelope = nested.DataOverhead
	}
	mtu, entryMTU, policy, err := externalMTUPolicyWithPacketEnvelope(tun, final, original, exit.profile, selection.Profile, envelope)
	if err != nil {
		return nil, err
	}
	if nested != nil {
		requested := requestedPacketMTU
		if policy == "fixed" {
			requested = mtu
		}
		cap, failure := nested.Capacity(entryMTU, requested, policy == "fixed")
		if failure != nil {
			return nil, failure
		}
		final["mtu"] = cap
		effectivePacketMTU = cap
		mtu = min(mtu, cap)
	}
	tun["mtu"] = mtu
	selectedProfile := predecessorCopy(exit.profile)
	if selection.Profile["jumbo_tun"] == true {
		selectedProfile["jumbo_tun"] = true
	}
	if policy == "fixed" {
		selectedProfile["mtu_policy"] = "fixed"
		selectedProfile["manual_mtu"] = mtu
	}
	profileBytes, _ := json.Marshal(selectedProfile)
	profile := string(profileBytes)
	ipv6, _, err := externalDevicePolicy(exit.profile, selection.Profile)
	if err != nil {
		return nil, err
	}
	if ipv6 == "off" {
		last["dns"].(map[string]any)["strategy"] = "ipv4_only"
		route := last["route"].(map[string]any)
		route["rules"] = append([]any{map[string]any{"inbound": []any{tun["tag"]}, "ip_version": 6, "action": "reject"}}, route["rules"].([]any)...)
	}
	// Rebuild included LAN routes from the two original policies; the final
	// compiler's routes were derived policy, not caller-supplied routing.
	delete(tun, "route_address")
	pair, _ := json.Marshal(map[string]any{"entry": selection.Profile, "exit": exit.profile})
	encoded, _ := json.Marshal(last)
	// Performance uses the final paired sink; ordinary imported sources cannot
	// acquire a fabricated Router cover endpoint. Shared proxy Jumbo is already
	// resolved above and is normalized to its one actual TUN owner here.
	perfEntry, perfExit := predecessorCopy(selection.Profile), predecessorCopy(exit.profile)
	if perfEntry["jumbo_tun"] == true {
		perfEntry["jumbo_tun"] = false
		perfExit["jumbo_tun"] = true
	}
	perfPair, _ := json.Marshal(map[string]any{"entry": perfEntry, "exit": perfExit})
	configured, err := mobileperf.Apply(string(encoded), string(perfPair))
	if err != nil {
		return nil, err
	}
	configured, err = ApplyLANPolicy(configured, string(pair))
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(configured), &last) != nil {
		return nil, bad
	}
	if connectEntry && connectCapability == "tcp-only" {
		route := last["route"].(map[string]any)
		route["rules"] = append(route["rules"].([]any), map[string]any{"inbound": []string{tun["tag"].(string)}, "network": "udp", "action": "reject"})
	}
	// Final private proof is routed through the same selector as application
	// traffic. There is deliberately no imported-entry private proof listener.
	last["inbounds"] = append(last["inbounds"].([]any), map[string]any{"type": "mixed", "tag": "routervpn-proof", "listen": "127.0.0.1", "listen_port": 1099})
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := last[family].([]any)
		for _, raw := range rows {
			n := raw.(map[string]any)
			if n["tag"] == "proxy" {
				n["tag"] = LocalTag
			}
		}
	}
	last["outbounds"] = append(last["outbounds"].([]any), map[string]any{"type": "selector", "tag": "proxy", "outbounds": []string{LocalTag}, "default": LocalTag, "interrupt_exist_connections": true})
	encoded, err = json.Marshal(last)
	if len(encoded) > 4<<20 {
		return nil, bad
	}
	if err != nil {
		return nil, err
	}
	meta := Metadata{EntryKind: "external", EntryID: selection.ExitID, ExitID: predecessorText(exit.profile, "id"), ExitNodeID: predecessorText(exit.profile, "node_proof_id"), ExitAPI: predecessorText(exit.profile, "router_api"), ExitToken: predecessorText(exit.profile, "api_token"), EntryTag: "entry-wg", EntryMode: selection.Protocol, ExitMode: exitMode, Execution: "local", EntryStartLayer: entryMeta.StartLayer, ExitStartLayer: predecessorText(exit.profile, "start_layer")}
	if connectEntry {
		meta.TransportCapability = connectCapability
	}
	if nested != nil {
		meta.EntryPacketMTU = strconv.Itoa(entryMTU)
		meta.ExitPacketRequestedMTU = strconv.Itoa(requestedPacketMTU)
		meta.ExitPacketEffectiveMTU = strconv.Itoa(effectivePacketMTU)
		meta.PacketDataOverhead = strconv.Itoa(nested.DataOverhead)
		meta.PacketControlMax = strconv.Itoa(nested.ControlMax)
		meta.PacketMTUState = "configured-unmeasured"
	}
	if selection.Protocol == "socks5" && awgpolicy.WireGuardFamily(exitMode) && entryMeta.StartLayer != "" && entryMeta.StartLayer != "off" && meta.ExitStartLayer != "" && meta.ExitStartLayer != "off" {
		bound, failure := ImportedSOCKSPacketBounds(string(encoded))
		if failure != nil {
			return nil, failure
		}
		meta.SOCKSDatagramBoundState = "configured-unmeasured"
		meta.SOCKSDatagramDataMax = strconv.Itoa(bound.DataMax)
		meta.SOCKSDatagramControlMax = strconv.Itoa(bound.ControlMax)
	}
	metadata, _ := json.Marshal(meta)
	source, _ := json.Marshal([]string{"routervpn-imported-entry-v1", entryConfig, entryCapture, exitMode, exitFiles, exitProfile, exitStart, dnsBootstrap})
	c := &Controller{meta: meta, config: string(encoded), progress: Progress{Stage: "prepared", Measurements: []routechoice.Measurement{}}, imported: &importedEntry{source: externalDigest(source), metadata: string(metadata), profile: profile, publicIP: selection.ExpectedPublicIP}}
	if selection.Protocol == "openvpn" {
		// The exact compiled endpoint retains public remote identity through its
		// captured layer mapper. The complete original import and independent
		// private transport mapping remain in the source fingerprint above.
		c.imported.openvpnTransport = predecessorCopy(original)
		if entryMTU < 1280 {
			return nil, errors.New("imported OpenVPN entry lost its captured packet capacity")
		}
		c.imported.openvpnMTU = uint32(entryMTU)
	}
	c.generation.Store(1)
	return c, nil
}
func (c *Controller) Metadata() string {
	if c == nil {
		return ""
	}
	if c.imported != nil {
		return c.imported.metadata
	}
	raw, _ := json.Marshal(c.meta)
	return string(raw)
}
func (c *Controller) SourceSHA256() string {
	if c == nil || c.imported == nil {
		return ""
	}
	return c.imported.source
}
func (c *Controller) MTUProfile() string {
	if c == nil || c.imported == nil {
		return ""
	}
	return c.imported.profile
}

func importedSS2022Method(method string) bool {
	return method == "2022-blake3-aes-128-gcm" || method == "2022-blake3-aes-256-gcm" || method == "2022-blake3-chacha20-poly1305"
}

// Match the shipping sing-shadowsocks2 SS2022 constructor without rewriting
// the original key text. AES supports identity chains; ChaCha has a single
// PSK. Each key must have the exact cipher size. The outer Start Layer's
// separate legacy constructor does not govern this imported inner transport.
func importedSS2022Credentials(method, password string) bool {
	if !importedSS2022Method(method) || password == "" || len(password) > 4096 {
		return false
	}
	keys := strings.Split(password, ":")
	if method == "2022-blake3-chacha20-poly1305" && len(keys) != 1 {
		return false
	}
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	for _, raw := range keys {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != size {
			return false
		}
	}
	return true
}
