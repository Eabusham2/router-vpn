package mobilemultihop

import (
	"encoding/json"
	"reflect"
)

// The original compiler already authenticates the complete relay proposal.
// This additional boundary admits only its exact paired WG/SS2022 execution row
// set. Both candidates and their selector remain owned by that same execution.
func newDesktopExternalRouterServerPolicy(original *ExternalPolicy, capture ExternalDesktopCapture, session string) (*DesktopExternalPolicy, error) {
	bad := desktopExternalPolicyError
	p := original.capture
	final, _ := p.Profile["external"].(map[string]any)
	if (capture.Execution != "server" && capture.Execution != "local" && capture.Execution != "auto") || (p.Profile["multihop_execution"] != capture.Execution && p.Profile["multihop_execution"] != "auto") || p.Profile["multihop_entry_mode"] != "wg" ||
		p.Entry["node_kind"] != "router-vpn" || capture.EntryNodeID == "" || capture.EntryTag != externalEntryTag ||
		capture.PredecessorSHA256 == "" || capture.Protocol != "shadowsocks" || !desktopExternalSS2022Import(final) ||
		capture.StartLayer != "" || capture.EntryStartLayer != "" || len(capture.PhysicalRoots) != 1 ||
		(capture.KillSwitchPolicy != "on-connect" && capture.KillSwitchPolicy != "always") ||
		(capture.IPv6Mode != "on" && capture.IPv6Mode != "off") || p.Execution == nil || p.Execution.Selection != capture.Execution {
		return nil, bad
	}
	root := capture.PhysicalRoots[0]
	if root.Family != "endpoints" || root.Tag != externalEntryTag || root.Type != "wireguard" || root.DynamicSOCKSUDP {
		return nil, bad
	}
	var graph map[string]any
	if exactJSON([]byte(original.Config()), &graph, 4<<20) != nil || graph == nil {
		return nil, bad
	}
	if services, exists := graph["services"]; exists {
		rows, ok := services.([]any)
		if !ok || len(rows) != 0 {
			return nil, bad
		}
	}
	endpoints, ok := graph["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return nil, bad
	}
	physical, ok := endpoints[0].(map[string]any)
	if !ok || physical["tag"] != root.Tag || physical["type"] != root.Type || physical["detour"] != nil || desktopExternalObjectDigest(physical) != root.ConfigSHA256 {
		return nil, bad
	}
	rows, ok := graph["outbounds"].([]any)
	if !ok || len(rows) != 3 {
		return nil, bad
	}
	seen := map[string]bool{}
	api, err := privateAPI(p.Entry["router_api"].(string))
	if err != nil {
		return nil, bad
	}
	request := p.Execution.Request
	initial := ServerTag
	if capture.Execution != "server" {
		initial = LocalTag
	}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, bad
		}
		tag, _ := row["tag"].(string)
		if seen[tag] {
			return nil, bad
		}
		seen[tag] = true
		switch tag {
		case LocalTag:
			if row["type"] != "shadowsocks" || row["detour"] != capture.EntryTag {
				return nil, bad
			}
		case ServerTag:
			want := map[string]any{"type": "socks", "tag": ServerTag, "server": api.Hostname(), "server_port": float64(request.Port), "version": "5", "username": request.Username, "password": request.Password, "detour": capture.EntryTag}
			if !reflect.DeepEqual(row, want) {
				return nil, bad
			}
		case ExternalFinalTag:
			want := map[string]any{"type": "selector", "tag": ExternalFinalTag, "outbounds": []any{LocalTag, ServerTag}, "default": initial, "interrupt_exist_connections": true}
			if !reflect.DeepEqual(row, want) {
				return nil, bad
			}
		default:
			return nil, bad
		}
	}
	if !seen[LocalTag] || !seen[ServerTag] || !seen[ExternalFinalTag] {
		return nil, bad
	}
	meta := DesktopExternalMetadata{Schema: 1, SessionID: session, TargetOS: "windows", OriginalSourceSHA256: capture.SourceSHA256, OriginalConfigSHA256: capture.ConfigSHA256, OriginalMetadataSHA256: capture.MetadataSHA256, OriginalCaptureSHA256: capture.CaptureSHA256, Protocol: capture.Protocol, RootTag: root.Tag, RootType: root.Type, OriginalRootSHA256: root.ConfigSHA256, KillSwitchPolicy: capture.KillSwitchPolicy, IPv6Mode: capture.IPv6Mode, HomeLANAccess: capture.HomeLANAccess}
	meta.SourceSHA256 = desktopExternalObjectDigest(struct {
		Domain string                  `json:"domain"`
		Policy DesktopExternalMetadata `json:"policy"`
	}{"routervpn-desktop-external-source-v1", meta})
	if meta.SourceSHA256 == "" {
		return nil, bad
	}
	physical["detour"] = DesktopExternalPhysicalTag
	meta.DerivedRootSHA256 = desktopExternalObjectDigest(physical)
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return nil, bad
	}
	servers, ok := dns["servers"].([]any)
	if !ok {
		return nil, bad
	}
	selected := false
	for _, raw := range servers {
		server, ok := raw.(map[string]any)
		if !ok {
			return nil, bad
		}
		if server["tag"] == capture.SelectedDNS.Tag {
			if selected || capture.SelectedDNS.Physical || desktopExternalObjectDigest(server) != capture.SelectedDNS.ConfigSHA256 {
				return nil, bad
			}
			selected = true
		}
	}
	if !selected {
		return nil, bad
	}
	for _, bootstrap := range capture.BootstrapDNS {
		if !bootstrap.Physical {
			continue
		}
		found := false
		for _, raw := range servers {
			server := raw.(map[string]any)
			if server["tag"] != bootstrap.Tag {
				continue
			}
			if found || bootstrap.Tag == capture.SelectedDNS.Tag || server["detour"] != nil || desktopExternalObjectDigest(server) != bootstrap.ConfigSHA256 {
				return nil, bad
			}
			server["detour"], found = DesktopExternalPhysicalTag, true
		}
		if !found {
			return nil, bad
		}
	}
	graph["outbounds"] = append(rows, map[string]any{"type": DesktopExternalPhysicalType, "tag": DesktopExternalPhysicalTag, "session_id": session, "source_sha256": meta.SourceSHA256})
	graph["services"] = []any{map[string]any{"type": DesktopExternalNetworkType, "tag": DesktopExternalNetworkTag, "session_id": session, "source_sha256": meta.SourceSHA256}}
	body, err := json.Marshal(graph)
	if err != nil || len(body) > 4<<20 {
		return nil, bad
	}
	meta.ConfigSHA256 = externalDigest(body)
	policy := &DesktopExternalPolicy{original: original, config: string(body), metadata: meta}
	policy.seal = policy.currentSeal()
	if policy.Validate() != nil {
		return nil, bad
	}
	return policy, nil
}
