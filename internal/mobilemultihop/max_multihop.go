package mobilemultihop

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"router-vpn/internal/multihoprelay"
)

const MAXEntryPrefix = "routervpn-entry-max-"
const MAXExitPrefix = "routervpn-exit-max-"

func maxTags(root string, entry bool) multihoprelay.MAXTags {
	prefix := MAXExitPrefix
	if entry {
		prefix = MAXEntryPrefix
	}
	return multihoprelay.MAXTags{Root: root, Middle: prefix + "ss", Outer: prefix + "outer", Start: prefix + "start"}
}
func generatedMAXTags() multihoprelay.MAXTags {
	return multihoprelay.MAXTags{Root: "proxy", Middle: MAXShadowsocksTag, Outer: MAXOuterTag, Start: MAXStartLayerTag}
}

func standaloneMAXGraph(config, mode, node, layer string) (map[string]any, map[string]any, []any, error) {
	bad := errors.New("complete MAX source is not a bounded single-node native graph")
	var graph map[string]any
	if !MAXMode(mode) || exactJSON([]byte(config), &graph, 4<<20) != nil || graph == nil {
		return nil, nil, nil, bad
	}
	for key := range graph {
		switch key {
		case "log", "inbounds", "outbounds", "endpoints", "route", "dns":
		default:
			return nil, nil, nil, bad
		}
	}
	endpoints, ok := graph["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return nil, nil, nil, bad
	}
	base, ok := endpoints[0].(map[string]any)
	if !ok {
		return nil, nil, nil, bad
	}
	outs, ok := graph["outbounds"].([]any)
	if !ok {
		return nil, nil, nil, bad
	}
	ins, ok := graph["inbounds"].([]any)
	if !ok || len(ins) != 1 {
		return nil, nil, nil, bad
	}
	tun, ok := ins[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return nil, nil, nil, bad
	}
	for _, key := range []string{"route_address", "route_exclude_address", "route_address_set", "route_exclude_address_set", "include_interface", "exclude_interface", "include_uid", "exclude_uid", "include_package", "exclude_package"} {
		if _, exists := tun[key]; exists {
			return nil, nil, nil, bad
		}
	}
	route, ok := graph["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return nil, nil, nil, bad
	}
	for key, value := range route {
		switch key {
		case "final":
		case "auto_detect_interface":
			if value != true {
				return nil, nil, nil, bad
			}
		case "rules":
			rules, ok := value.([]any)
			if !ok {
				return nil, nil, nil, bad
			}
			for _, raw := range rules {
				r, ok := raw.(map[string]any)
				if !ok || len(r) != 2 || r["protocol"] != "dns" || r["action"] != "hijack-dns" {
					return nil, nil, nil, bad
				}
			}
		default:
			return nil, nil, nil, bad
		}
	}
	if err := multihoprelay.ValidateMAXChain(base, outs, mode, node, layer, generatedMAXTags(), ""); err != nil {
		return nil, nil, nil, err
	}
	return graph, base, outs, nil
}

// MAXMultihopBase returns a temporary graph-construction input. It is never a
// runnable representation of the selected MAX mode: New rejects MAX metadata
// until ComposeMAXMultihop restores and verifies all of the captured layers.
// Existing host proof-lane/DNS compilers can reuse their single-PQ logic without
// ever starting a downgraded tunnel or staging raw helper/configuration files.
func MAXMultihopBase(config, mode, node, layer string) (string, error) {
	graph, base, _, err := standaloneMAXGraph(config, mode, node, layer)
	if err != nil {
		return "", err
	}
	delete(base, "detour")
	graph["outbounds"] = []any{}
	raw, err := json.Marshal(graph)
	return string(raw), err
}

// ComposeMAXMultihop replaces only the exact builder-owned PQ placeholders.
// Entry and exit have disjoint internal tags; the exit's outermost encrypted
// socket traverses the entry. DNS and both proof lanes keep their existing tags.
// The source snapshots are consumed, not saved as another executable runtime.
func ComposeMAXMultihop(config, metadata, entrySource, exitSource string) (string, error) {
	var meta Metadata
	var graph map[string]any
	if exactJSON([]byte(metadata), &meta, 16384) != nil || exactJSON([]byte(config), &graph, 4<<20) != nil || graph == nil {
		return "", errors.New("invalid captured MAX multihop proposal")
	}
	if meta.EntryTag != "entry-wg" && meta.EntryTag != "routervpn-hop-entry" {
		return "", errors.New("MAX graph lost its owned entry tag")
	}
	if !MAXMode(meta.EntryMode) && !MAXMode(meta.ExitMode) {
		return "", errors.New("MAX composition requires a selected complete chain")
	}
	for _, entry := range []bool{true, false} {
		mode, node, source, tag, layer, via := meta.ExitMode, meta.ExitNodeID, exitSource, "proxy", meta.ExitStartLayer, meta.EntryTag
		if entry {
			mode, node, source, tag, layer, via = meta.EntryMode, meta.EntryNodeID, entrySource, meta.EntryTag, meta.EntryStartLayer, ""
		}
		if !MAXMode(mode) {
			if source != "" {
				return "", errors.New("unrequested MAX chain source")
			}
			continue
		}
		_, base, outputs, err := standaloneMAXGraph(source, mode, node, layer)
		if err != nil {
			return "", err
		}
		endpoints, ok := graph["endpoints"].([]any)
		if !ok {
			return "", errors.New("MAX graph lost its packet endpoint")
		}
		var selected map[string]any
		for _, raw := range endpoints {
			v, ok := raw.(map[string]any)
			if !ok {
				return "", errors.New("invalid MAX endpoint")
			}
			if v["tag"] == tag {
				if selected != nil {
					return "", errors.New("duplicate MAX packet owner")
				}
				selected = v
			}
		}
		if selected == nil {
			return "", errors.New("MAX base placeholder missing")
		}
		// Compare the entire endpoint (including every key and parameter), not
		// only its public node label. Only tag/detour are builder-owned changes.
		expected := map[string]any{}
		for key, value := range base {
			expected[key] = value
		}
		expected["tag"] = tag
		if via == "" {
			delete(expected, "detour")
		} else {
			expected["detour"] = via
		}
		if !reflect.DeepEqual(expected, selected) {
			return "", errors.New("MAX placeholder changed captured keys, node or native policy")
		}
		names := maxTags(tag, entry)
		outs, ok := graph["outbounds"].([]any)
		if !ok {
			return "", errors.New("MAX graph lost its outbound manager")
		}
		for _, raw := range outs {
			v, ok := raw.(map[string]any)
			if !ok {
				return "", errors.New("invalid MAX outbound")
			}
			name, _ := v["tag"].(string)
			if name == tag || name == names.Middle || name == names.Outer || name == names.Start {
				return "", errors.New("MAX names already have an owner")
			}
		}
		owned, added, err := multihoprelay.RelabelMAXChain(base, outputs, mode, node, layer, generatedMAXTags(), names, "", via)
		if err != nil {
			return "", err
		}
		for key := range selected {
			delete(selected, key)
		}
		for key, value := range owned {
			selected[key] = value
		}
		graph["outbounds"] = append(outs, added...)
	}
	if err := validateMAXGraphOwners(graph, meta); err != nil {
		return "", err
	}
	result, err := json.Marshal(graph)
	if err != nil || len(result) > 4<<20 {
		return "", errors.New("complete MAX graph exceeds its bound")
	}
	return string(result), nil
}

func graphMAXChain(graph map[string]any, meta Metadata, entry bool) (map[string]any, error) {
	mode, node, layer, tag, via, api := meta.ExitMode, meta.ExitNodeID, meta.ExitStartLayer, "proxy", meta.EntryTag, meta.ExitAPI
	if entry {
		mode, node, layer, tag, via, api = meta.EntryMode, meta.EntryNodeID, meta.EntryStartLayer, meta.EntryTag, "", meta.EntryAPI
	}
	if !MAXMode(mode) {
		return nil, errors.New("unselected MAX graph")
	}
	names := maxTags(tag, entry)
	var base map[string]any
	var owned []any
	seen := map[string]bool{}
	for _, list := range []string{"endpoints", "outbounds"} {
		values, ok := graph[list].([]any)
		if !ok {
			return nil, errors.New("invalid complete MAX manager")
		}
		for _, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid complete MAX component")
			}
			name, ok := value["tag"].(string)
			if !ok || seen[name] {
				return nil, errors.New("duplicate or absent MAX graph tag")
			}
			seen[name] = true
			if name == tag {
				if list != "endpoints" {
					return nil, errors.New("MAX base belongs to the packet manager")
				}
				base = value
			}
			if name == names.Middle || name == names.Outer || name == names.Start {
				if list != "outbounds" {
					return nil, errors.New("MAX layers belong to the outbound manager")
				}
				owned = append(owned, value)
			}
		}
	}
	if err := multihoprelay.ValidateMAXChain(base, owned, mode, node, layer, names, via); err != nil {
		return nil, err
	}
	address, err := privateAPI(api)
	if err != nil {
		return nil, err
	}
	if base["peers"].([]any)[0].(map[string]any)["address"] != address.Hostname() {
		return nil, errors.New("MAX private service differs from captured node API")
	}
	return base, nil
}

func validateMAXGraphOwners(graph map[string]any, meta Metadata) error {
	allowed := map[string]bool{}
	for _, entry := range []bool{true, false} {
		mode, tag := meta.ExitMode, "proxy"
		if entry {
			mode, tag = meta.EntryMode, meta.EntryTag
		}
		if !MAXMode(mode) {
			continue
		}
		if _, err := graphMAXChain(graph, meta, entry); err != nil {
			return err
		}
		names := maxTags(tag, entry)
		allowed[names.Middle] = true
		allowed[names.Outer] = true
		allowed[names.Start] = true
	}
	for _, list := range []string{"endpoints", "outbounds"} {
		values, _ := graph[list].([]any)
		for _, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok {
				return errors.New("invalid native graph component")
			}
			tag, _ := value["tag"].(string)
			if (strings.HasPrefix(tag, MAXEntryPrefix) || strings.HasPrefix(tag, MAXExitPrefix)) && !allowed[tag] {
				return errors.New("unrequested complete MAX component")
			}
		}
	}
	return nil
}

// maxMTUNormalize validates the complete chain before presenting its own packet
// interface to the existing conservative nested-MTU calculation. Only routing
// edges are temporarily translated; every extra layer stays in the graph and
// the original edges are restored before serialization.
func maxMTUNormalize(graph map[string]any) (func(), error) {
	if _, ok := graph["outbounds"].([]any); !ok {
		return nil, errors.New("invalid MAX MTU outbound manager")
	}
	entryTag := ""
	var endpoints []map[string]any
	for _, list := range []string{"endpoints", "outbounds"} {
		values, _ := graph[list].([]any)
		for _, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid MAX MTU component")
			}
			tag, _ := value["tag"].(string)
			if tag == "entry-wg" || tag == "routervpn-hop-entry" {
				if entryTag != "" {
					return nil, errors.New("ambiguous MAX MTU entry")
				}
				entryTag = tag
			}
			if list == "endpoints" {
				endpoints = append(endpoints, value)
			}
		}
	}
	type edge struct {
		value  map[string]any
		detour any
	}
	var restore []edge
	selected := map[string]bool{}
	for _, ep := range endpoints {
		tag, _ := ep["tag"].(string)
		entry := tag == entryTag
		if !entry && tag != "proxy" {
			continue
		}
		names := maxTags(tag, entry)
		if ep["detour"] != names.Middle {
			continue
		}
		if entryTag == "" {
			return nil, errors.New("MAX MTU has no captured entry")
		}
		kind, _ := ep["mode"].(string)
		mode := "max-quic-wg"
		if kind == "awg2-pq" {
			mode = "max-quic-awg"
		} else if kind != "wg-pq" {
			return nil, errors.New("MAX MTU lost its negotiated base")
		}
		layer := ""
		values, _ := graph["outbounds"].([]any)
		for _, raw := range values {
			out := raw.(map[string]any)
			if out["tag"] == names.Outer && out["type"] == "routervpn-xray" {
				mode = strings.Replace(mode, "max-quic-", "max-tls-", 1)
			}
			if out["tag"] == names.Start {
				switch out["type"] {
				case "shadowsocks":
					layer = "aes-256-gcm"
				case "routervpn-aes-xor":
					layer = "aes-256-gcm+xor-whitening"
				default:
					return nil, errors.New("MAX MTU has an unowned outer layer")
				}
			}
		}
		peers, ok := ep["peers"].([]any)
		if !ok || len(peers) != 1 {
			return nil, errors.New("MAX MTU lost its peer")
		}
		peer, ok := peers[0].(map[string]any)
		if !ok {
			return nil, errors.New("MAX MTU lost its peer")
		}
		host, ok := peer["address"].(string)
		if !ok {
			return nil, errors.New("MAX MTU lost its node address")
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		node, _ := ep["node_id"].(string)
		meta := Metadata{EntryTag: entryTag, ExitMode: mode, ExitNodeID: node, ExitStartLayer: layer, ExitAPI: "http://" + host + ":8787"}
		if entry {
			meta.EntryMode = mode
			meta.EntryNodeID = node
			meta.EntryStartLayer = layer
			meta.EntryAPI = meta.ExitAPI
		}
		if _, err := graphMAXChain(graph, meta, entry); err != nil {
			return nil, err
		}
		for _, n := range []string{names.Middle, names.Outer, names.Start} {
			selected[n] = true
		}
		restore = append(restore, edge{ep, ep["detour"]})
	}
	for _, raw := range graph["outbounds"].([]any) {
		out := raw.(map[string]any)
		tag, _ := out["tag"].(string)
		if (strings.HasPrefix(tag, MAXEntryPrefix) || strings.HasPrefix(tag, MAXExitPrefix)) && !selected[tag] {
			return nil, errors.New("MAX MTU cannot discard an unowned chain")
		}
	}
	// Validate every chain before translating any edge, so cross-chain validators
	// always inspect a complete frozen graph rather than a half-normalized one.
	for _, item := range restore {
		if item.value["tag"] == entryTag {
			delete(item.value, "detour")
		} else {
			item.value["detour"] = entryTag
		}
	}
	return func() {
		for _, item := range restore {
			item.value["detour"] = item.detour
		}
	}, nil
}
