package mobilemultihop

import (
	"encoding/json"
	"errors"
	"router-vpn/internal/mobileperf"
	"router-vpn/internal/routechoice"
)

// importedEntry is created only from the complete independently validated
// imported transport and paired final sources. Metadata cannot create it.
type importedEntry struct {
	source, metadata, profile, publicIP string
}

// NewImportedEntry composes an imported SS2022 or Hysteria2 predecessor and a paired
// Shadowsocks or Hysteria2 final. Compilation proves neither identity.
func NewImportedEntry(entryConfig, entryCapture, exitMode, exitFiles, exitProfile, exitStart, dnsBootstrap string) (*Controller, error) {
	bad := errors.New("imported entry requires a captured standalone SS2022 or Hysteria2 source and paired Shadowsocks or Hysteria2 final in Local execution")
	var selection externalPolicyCapture
	if exactJSON([]byte(entryCapture), &selection, 8<<20) != nil || selection.Entry != nil || selection.EntryTag != "" || selection.PredecessorConfig != "" || selection.Execution != nil || (selection.Protocol != "shadowsocks" && selection.Protocol != "hysteria2") || selection.Profile["node_kind"] != "external" || (exitMode != "shadowsocks" && exitMode != "hysteria2") {
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
	// All predecessor edges were checked by ExternalPolicy; copy only its actual
	// transport closure. Its DNS and proof listener are not application policy.
	rows, _ := first["outbounds"].([]any)
	names := map[string]string{ExternalFinalTag: "entry-wg"}
	for _, raw := range rows {
		node := raw.(map[string]any)
		tag := predecessorText(node, "tag")
		if tag != ExternalFinalTag {
			names[tag] = "imported-entry-" + tag
		}
	}
	var original map[string]any
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
	if original == nil || selection.Protocol == "shadowsocks" && !importedSS2022Method(predecessorText(original, "method")) || selection.Protocol == "hysteria2" && original["type"] != "hysteria2" {
		return nil, bad
	}
	// Each transport has its own authenticated layer. Attach the final's outer
	// edge, preserving an inner detour if its compiler produced one.
	var final map[string]any
	outs, _ := last["outbounds"].([]any)
	byTag := map[string]map[string]any{}
	for _, raw := range outs {
		n := raw.(map[string]any)
		byTag[predecessorText(n, "tag")] = n
		if n["tag"] == "proxy" {
			final = n
		}
	}
	if final == nil {
		return nil, bad
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
	outer["detour"] = "entry-wg"
	last["outbounds"] = append(outs, rows...)
	tun := last["inbounds"].([]any)[0].(map[string]any)
	mtu, _, policy, err := externalMTUPolicy(tun, final, original, exit.profile, selection.Profile)
	if err != nil {
		return nil, err
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
	// Final private proof is routed through the same selector as application
	// traffic. There is deliberately no imported-entry private proof listener.
	last["inbounds"] = append(last["inbounds"].([]any), map[string]any{"type": "mixed", "tag": "routervpn-proof", "listen": "127.0.0.1", "listen_port": 1099})
	for _, raw := range last["outbounds"].([]any) {
		n := raw.(map[string]any)
		if n["tag"] == "proxy" {
			n["tag"] = LocalTag
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
	metadata, _ := json.Marshal(meta)
	source, _ := json.Marshal([]string{"routervpn-imported-entry-v1", entryConfig, entryCapture, exitMode, exitFiles, exitProfile, exitStart, dnsBootstrap})
	c := &Controller{meta: meta, config: string(encoded), progress: Progress{Stage: "prepared", Measurements: []routechoice.Measurement{}}, imported: &importedEntry{source: externalDigest(source), metadata: string(metadata), profile: profile, publicIP: selection.ExpectedPublicIP}}
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
