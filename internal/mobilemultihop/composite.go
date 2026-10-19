package mobilemultihop

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"router-vpn/internal/nativecomposite"
)

const CompositeEntryPrefix = "routervpn-entry-composite-"
const CompositeExitPrefix = "routervpn-exit-composite-"

func CompositeMode(mode string) bool { return nativecomposite.Mode(mode) }

// CompileCompositeProfile retains both generated native protocol assets, the
// captured node identity and optional same-node Start Layer. All file trust is
// inlined before two nodes can be combined by a host builder.
func CompileCompositeProfile(mode, profile, metadata, start string) (string, error) {
	return nativecomposite.Compile(mode, profile, metadata, start)
}

// CompositeMultihopBase is a private construction input. Its unresolved child
// tags cannot start and New rejects it until ComposeCompositeMultihop restores
// both complete source lanes. No single real transport is used as a substitute.
func CompositeMultihopBase(config, mode, node, layer string) (string, error) {
	if _, err := nativecomposite.Plan(config, mode, node, layer); err != nil {
		return "", err
	}
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil {
		return "", errors.New("invalid captured composite graph")
	}
	graph["outbounds"] = graph["outbounds"].([]any)[:1]
	value, err := json.Marshal(graph)
	return string(value), err
}

func compositeTags(entry bool) string {
	if entry {
		return CompositeEntryPrefix
	}
	return CompositeExitPrefix
}

// ComposeCompositeMultihop replaces only exact captured placeholders. The exit
// root itself never has a generic detour: each real TCP/QUIC physical lane, or
// their shared AES outer layer, explicitly traverses the selected entry.
func ComposeCompositeMultihop(config, metadata, entrySource, exitSource string) (string, error) {
	var meta Metadata
	var graph map[string]any
	if exactJSON([]byte(metadata), &meta, 16384) != nil || exactJSON([]byte(config), &graph, 4<<20) != nil || graph == nil {
		return "", errors.New("invalid captured composite proposal")
	}
	if meta.EntryTag != "entry-wg" && meta.EntryTag != "routervpn-hop-entry" {
		return "", errors.New("composite lost its captured entry tag")
	}
	if !CompositeMode(meta.EntryMode) && !CompositeMode(meta.ExitMode) {
		return "", errors.New("no composite selected for this graph")
	}
	for _, entry := range []bool{true, false} {
		mode, node, layer, source, tag, via := meta.ExitMode, meta.ExitNodeID, meta.ExitStartLayer, exitSource, "proxy", meta.EntryTag
		if entry {
			mode, node, layer, source, tag, via = meta.EntryMode, meta.EntryNodeID, meta.EntryStartLayer, entrySource, meta.EntryTag, ""
		}
		if !CompositeMode(mode) {
			if source != "" {
				return "", errors.New("unrequested composite source")
			}
			continue
		}
		plan, err := nativecomposite.Plan(source, mode, node, layer)
		if err != nil {
			return "", err
		}
		var original map[string]any
		if exactJSON([]byte(source), &original, 4<<20) != nil {
			return "", errors.New("invalid original composite owner")
		}
		expected := original["outbounds"].([]any)[0].(map[string]any)
		expected["tag"] = tag
		if via != "" {
			expected["detour"] = via
		}
		values, ok := graph["outbounds"].([]any)
		if !ok {
			return "", errors.New("composite lost the native outbound manager")
		}
		selected := -1
		prefix := compositeTags(entry)
		for index, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok {
				return "", errors.New("invalid composite outbound")
			}
			name, _ := value["tag"].(string)
			if strings.HasPrefix(name, prefix) {
				return "", errors.New("composite child already has an owner")
			}
			if name == tag {
				if selected != -1 || !reflect.DeepEqual(expected, value) {
					return "", errors.New("composite placeholder changed node or either captured lane")
				}
				selected = index
			}
		}
		if selected == -1 {
			return "", errors.New("captured composite placeholder missing")
		}
		root, children, err := nativecomposite.Relabel(plan, mode, node, layer, tag, prefix, via)
		if err != nil {
			return "", err
		}
		values[selected] = root
		graph["outbounds"] = append(values, children...)
	}
	if err := validateCompositeGraphOwners(graph, meta); err != nil {
		return "", err
	}
	result, err := json.Marshal(graph)
	if err != nil || len(result) > 4<<20 {
		return "", errors.New("complete composite graph exceeds its bound")
	}
	return string(result), nil
}

func validateCompositeGraphOwners(graph map[string]any, meta Metadata) error {
	allowed := map[string]bool{}
	for _, entry := range []bool{true, false} {
		mode, node, layer, tag, via, api := meta.ExitMode, meta.ExitNodeID, meta.ExitStartLayer, "proxy", meta.EntryTag, meta.ExitAPI
		if entry {
			mode, node, layer, tag, via, api = meta.EntryMode, meta.EntryNodeID, meta.EntryStartLayer, meta.EntryTag, "", meta.EntryAPI
		}
		if !CompositeMode(mode) {
			continue
		}
		prefix := compositeTags(entry)
		plan, err := nativecomposite.Extract(graph, mode, node, layer, tag, prefix, via)
		if err != nil {
			return err
		}
		if layer != "" {
			address, err := privateAPI(api)
			if err != nil || plan["udp"].(map[string]any)["server"] != address.Hostname() {
				return errors.New("composite private service differs from captured node API")
			}
		}
		allowed[prefix+"tcp"] = true
		allowed[prefix+"udp"] = true
		if layer != "" {
			allowed[prefix+"start"] = true
		}
	}
	for _, list := range []string{"endpoints", "outbounds"} {
		values, _ := graph[list].([]any)
		for _, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok {
				return errors.New("invalid composite manager component")
			}
			tag, _ := value["tag"].(string)
			if strings.HasPrefix(tag, CompositeEntryPrefix) || strings.HasPrefix(tag, CompositeExitPrefix) {
				if list != "outbounds" || !allowed[tag] {
					return errors.New("unrequested or misplaced composite component")
				}
			}
		}
	}
	return nil
}

// The MTU projection sees a composite as a proxy over the one retained TUN,
// after revalidating both complete entry lanes. It owns no extra IP interface.
func validateCompositeMTUEntry(graph, entry map[string]any) error {
	mode, _ := entry["mode"].(string)
	node, _ := entry["node_id"].(string)
	tag, _ := entry["tag"].(string)
	layer := ""
	values, _ := graph["outbounds"].([]any)
	for _, raw := range values {
		value, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid composite MTU component")
		}
		if value["tag"] == CompositeEntryPrefix+"start" {
			switch value["type"] {
			case "shadowsocks":
				layer = "aes-256-gcm"
			case "routervpn-aes-xor":
				layer = "aes-256-gcm+xor-whitening"
			default:
				return errors.New("unowned composite MTU Start Layer")
			}
		}
	}
	_, err := nativecomposite.Extract(graph, mode, node, layer, tag, CompositeEntryPrefix, "")
	return err
}
