package mobilemultihop

import (
	"encoding/json"
	"errors"
	"regexp"

	"router-vpn/internal/multihoprelay"
)

const (
	DesktopExternalNetworkType  = "routervpn-desktop-external-network"
	DesktopExternalNetworkTag   = "routervpn-external-network-owner"
	DesktopExternalPhysicalType = "routervpn-desktop-external-physical"
	DesktopExternalPhysicalTag  = "routervpn-external-physical-egress"
	DesktopExternalSOCKSType    = "routervpn-desktop-external-socks5"
)

var desktopExternalSessionID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// DesktopExternalMetadata describes a deterministic desktop adaptation. Source
// identifies this session, target and complete original policy; Config identifies
// the actual adapted native graph. Neither string grants a socket capability.
// Native preparation must retain the original policy and the actual Box owners.
type DesktopExternalMetadata struct {
	Schema                      int    `json:"schema"`
	SessionID                   string `json:"session_id"`
	TargetOS                    string `json:"target_os"`
	SourceSHA256                string `json:"source_sha256"`
	ConfigSHA256                string `json:"config_sha256"`
	OriginalSourceSHA256        string `json:"original_source_sha256"`
	OriginalConfigSHA256        string `json:"original_config_sha256"`
	OriginalMetadataSHA256      string `json:"original_metadata_sha256"`
	OriginalCaptureSHA256       string `json:"original_capture_sha256"`
	Protocol                    string `json:"protocol"`
	RootTag                     string `json:"root_tag"`
	RootType                    string `json:"root_type"`
	OriginalRootSHA256          string `json:"original_root_sha256"`
	DerivedRootSHA256           string `json:"derived_root_sha256"`
	KillSwitchPolicy            string `json:"kill_switch_policy"`
	IPv6Mode                    string `json:"ipv6_mode"`
	HomeLANAccess               bool   `json:"home_lan_access"`
	SOCKSUDPAssociationRequired bool   `json:"socks_udp_association_required"`
	SOCKSUDPAssociationTunneled bool   `json:"socks_udp_association_tunneled,omitempty"`
}

// DesktopExternalPolicy can be constructed only from a valid ExternalPolicy.
// There is deliberately no JSON decoder or caller-supplied metadata constructor.
// Public desktop admission and actual OS support are separate from this plan.
type DesktopExternalPolicy struct {
	original *ExternalPolicy
	config   string
	metadata DesktopExternalMetadata
	seal     string
}

var desktopExternalPolicyError = errors.New("desktop external lower path requires its complete captured native policy")

// NewDesktopExternalPolicy derives the captured ordinary transport lower path.
// Darwin additionally admits the exact Local external WG/AWG entry -> SS, HTTP(S) CONNECT, Hysteria2 (with its captured exit AES/XOR layer), SOCKS5, WireGuard or AmneziaWG graph.
// Linux admits bounded Local WireGuard entry -> SS2022, HTTP(S) CONNECT or Hysteria2 finals, including the captured HY2 exit AES/XOR layer.
// Linux, Windows and Darwin retain an ordinary SS2022 entry -> SS2022,
// TCP-only HTTP(S) CONNECT or HY2 final with both layers Off. An SS2022 final
// additionally retains independently provisioned entry and final AES/XOR layers.
// It preserves selected DNS, all transport credentials/options and every device
// rule. A SOCKS5 graph retains an explicit unsatisfied UDP-association requirement
// until the native host proves that capability; it is not silently made TCP-only.
// Windows additionally retains the explicitly captured paired Router WG entry
// with an SS2022 final and Local/Server selector, with both Start Layers Off.
// This constructor alone cannot enable a mode or a privileged OS firewall owner.
func NewDesktopExternalPolicy(original *ExternalPolicy, sessionID, targetOS string) (*DesktopExternalPolicy, error) {
	if original == nil || !desktopExternalSessionID.MatchString(sessionID) ||
		(targetOS != "linux" && targetOS != "windows" && targetOS != "darwin") {
		return nil, desktopExternalPolicyError
	}
	capture, err := original.DesktopCapture()
	if err == nil && targetOS == "windows" && (capture.Execution == "server" || capture.Execution == "local" && original.capture.Execution != nil && original.capture.Entry["node_kind"] == "router-vpn") {
		return newDesktopExternalRouterServerPolicy(original, capture, sessionID)
	}
	entryKind := ""
	if err == nil && (targetOS == "darwin" || targetOS == "linux" || targetOS == "windows") {
		entryKind = desktopExternalEntryKind(original, capture, targetOS)
		if targetOS == "windows" && entryKind != "shadowsocks" {
			entryKind = ""
		}
		// Linux initially admits this exact independently captured Local pair.
		// Other entry/final/layer compositions retain their separate host gates.
		if targetOS == "linux" {
			final, _ := original.capture.Profile["external"].(map[string]any)
			supportedFinal := capture.Protocol == "shadowsocks" && desktopExternalSS2022Import(final) || capture.Protocol == "http-connect" || capture.Protocol == "https-connect" || capture.Protocol == "hysteria2"
			supportedSSPair := entryKind == "shadowsocks" &&
				(capture.Protocol == "shadowsocks" && desktopExternalSS2022Import(final) || capture.Protocol == "http-connect" || capture.Protocol == "https-connect" || capture.Protocol == "hysteria2")
			if !supportedSSPair && (entryKind != "wireguard" || !supportedFinal) {
				entryKind = ""
			}
		}
	}
	entry := entryKind != ""
	streamEntry := entryKind == "shadowsocks"
	packetFinal := entry && (capture.Protocol == "wireguard" || capture.Protocol == "amneziawg" || capture.Protocol == "openvpn")
	if err != nil || !entry && (capture.EntryID != "" || capture.EntryTag != "") || capture.PredecessorSHA256 != "" ||
		capture.Execution != "" || capture.EntryStartLayer != "" && !streamEntry ||
		(capture.KillSwitchPolicy != "on-connect" && capture.KillSwitchPolicy != "always") ||
		(capture.IPv6Mode != "on" && capture.IPv6Mode != "off") || len(capture.PhysicalRoots) != 1 {
		return nil, desktopExternalPolicyError
	}
	// A provisioned HY2 layer preserves its original private inner transport.
	// A direct layer owns physical intent; behind a packet entry it retains
	// its original detour and only that entry owns physical socket intent.
	// Native host admission still requires the complete independent capture.
	layered := capture.StartLayer != ""
	if layered && (capture.Protocol != "hysteria2" && !(streamEntry && capture.Protocol == "shadowsocks") || !multihoprelay.ValidLayerMode(capture.StartLayer)) {
		return nil, desktopExternalPolicyError
	}
	kinds := map[string]string{"socks5": "socks", "http-connect": "http", "https-connect": "http", "shadowsocks": "shadowsocks"}
	kind, supported := kinds[capture.Protocol]
	family := "outbounds"
	if capture.Protocol == "hysteria2" {
		// Hysteria2 opens its one captured UDP socket lazily, after the native
		// external owner activates. The sealed Darwin lower plan uses the same
		// original UDP tuple; native host admission remains a separate gate.
		// It needs no eager endpoint startup phase.
		kind, supported = "hysteria2", true
	}
	// Native packet endpoints retain their original table and complete captured lower
	// tuples. OpenVPN keeps every ordered TCP/UDP remote; it cannot collapse
	// fallback into one peer or borrow a Router node identity.
	if targetOS == "linux" || targetOS == "windows" || targetOS == "darwin" {
		switch capture.Protocol {
		case "wireguard":
			family, kind, supported = "endpoints", "wireguard", true
		case "amneziawg":
			family, kind, supported = "endpoints", AmneziaType, true
		case "openvpn":
			family, kind, supported = "endpoints", "openvpn-client", true
		}
	}
	root := capture.PhysicalRoots[0]
	rootTag, rootKind, rowCount := ExternalFinalTag, kind, 1
	if entry {
		family, rootTag, rootKind = "endpoints", capture.EntryTag, entryKind
		if streamEntry {
			family = "outbounds"
		}
		if packetFinal || streamEntry {
			rowCount = 2
		}
	}
	if streamEntry {
		if capture.EntryStartLayer != "" {
			rootTag, rootKind = ExternalEntryStartLayerTag, desktopExternalLayerKind(capture.EntryStartLayer)
			rowCount++
		}
		if layered {
			rowCount++
		}
	}
	if layered && !entry {
		rootTag, rootKind, rowCount = multihoprelay.ExitStartLayerTag, "shadowsocks", 2
		if capture.StartLayer == "aes-256-gcm+xor-whitening" {
			rootKind = "routervpn-aes-xor"
		}
	}
	if !supported || capture.FinalTag != ExternalFinalTag || root.Family != family || root.Tag != rootTag || root.Type != rootKind ||
		root.DynamicSOCKSUDP != (!entry && capture.Protocol == "socks5" && capture.UDPAvailable) ||
		root.DynamicSOCKSUDP && (root.SOCKSVersion != "5" || root.SOCKSControl == nil || root.SOCKSControl.Network != "tcp") {
		return nil, desktopExternalPolicyError
	}
	var graph map[string]any
	if exactJSON([]byte(original.Config()), &graph, 4<<20) != nil || graph == nil {
		return nil, desktopExternalPolicyError
	}
	if services, exists := graph["services"]; exists {
		rows, ok := services.([]any)
		if !ok || len(rows) != 0 {
			return nil, desktopExternalPolicyError
		}
	}
	rows, ok := graph[root.Family].([]any)
	if !ok || len(rows) != rowCount {
		return nil, desktopExternalPolicyError
	}
	var physical map[string]any
	if streamEntry {
		physical, err = desktopExternalSSRows(rows, capture, kind, root)
		if err != nil {
			return nil, err
		}
	} else {
		innerFound := false
		for _, row := range rows {
			object, ok := row.(map[string]any)
			if !ok {
				return nil, desktopExternalPolicyError
			}
			switch object["tag"] {
			case root.Tag:
				if physical != nil {
					return nil, desktopExternalPolicyError
				}
				physical = object
			case ExternalFinalTag:
				if !(layered && !entry || packetFinal || streamEntry) || innerFound || object["type"] != kind || object["detour"] != root.Tag {
					return nil, desktopExternalPolicyError
				}
				innerFound = true
			default:
				return nil, desktopExternalPolicyError
			}
		}
		if physical == nil || innerFound != (layered && !entry || packetFinal || streamEntry) || physical["type"] != root.Type || physical["detour"] != nil ||
			desktopExternalObjectDigest(physical) != root.ConfigSHA256 {
			return nil, desktopExternalPolicyError
		}

	}
	if root.DynamicSOCKSUDP {
		username, _ := physical["username"].(string)
		password, _ := physical["password"].(string)
		if len(username) > 255 || len(password) > 255 {
			return nil, desktopExternalPolicyError
		}
	}
	meta := DesktopExternalMetadata{
		Schema: 1, SessionID: sessionID, TargetOS: targetOS,
		OriginalSourceSHA256: capture.SourceSHA256, OriginalConfigSHA256: capture.ConfigSHA256,
		OriginalMetadataSHA256: capture.MetadataSHA256, OriginalCaptureSHA256: capture.CaptureSHA256,
		Protocol: capture.Protocol, RootTag: root.Tag, RootType: root.Type, OriginalRootSHA256: root.ConfigSHA256,
		KillSwitchPolicy: capture.KillSwitchPolicy, IPv6Mode: capture.IPv6Mode, HomeLANAccess: capture.HomeLANAccess,
		SOCKSUDPAssociationRequired: capture.Protocol == "socks5" && capture.UDPAvailable,
		SOCKSUDPAssociationTunneled: entry && capture.Protocol == "socks5" && capture.UDPAvailable,
	}
	// This pre-derivation descriptor is not a self-referential graph hash. It
	// binds the exact original source plus target/session before insertion into
	// the new native objects. ConfigSHA256 separately binds their actual bytes.
	meta.SourceSHA256 = desktopExternalObjectDigest(struct {
		Domain string                  `json:"domain"`
		Policy DesktopExternalMetadata `json:"policy"`
	}{"routervpn-desktop-external-source-v1", meta})
	if meta.SourceSHA256 == "" {
		return nil, desktopExternalPolicyError
	}
	physical["detour"] = DesktopExternalPhysicalTag
	if root.DynamicSOCKSUDP {
		// The original native SOCKS options remain sealed and unchanged. This
		// derived host creates a distinct native client/lower owner per call,
		// so a negotiated UDP relay cannot become another call's permission.
		physical["type"] = DesktopExternalSOCKSType
		physical["session_id"], physical["source_sha256"] = sessionID, meta.SourceSHA256
	}
	meta.DerivedRootSHA256 = desktopExternalObjectDigest(physical)
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return nil, desktopExternalPolicyError
	}
	servers, ok := dns["servers"].([]any)
	if !ok {
		return nil, desktopExternalPolicyError
	}
	selected := false
	for _, item := range servers {
		server, ok := item.(map[string]any)
		if !ok {
			return nil, desktopExternalPolicyError
		}
		if server["tag"] == capture.SelectedDNS.Tag {
			if selected || capture.SelectedDNS.Physical || desktopExternalObjectDigest(server) != capture.SelectedDNS.ConfigSHA256 {
				return nil, desktopExternalPolicyError
			}
			selected = true
		}
	}
	if !selected {
		return nil, desktopExternalPolicyError
	}
	for _, bootstrap := range capture.BootstrapDNS {
		if !bootstrap.Physical {
			continue
		}
		found := false
		for _, item := range servers {
			server := item.(map[string]any)
			if server["tag"] != bootstrap.Tag {
				continue
			}
			if found || bootstrap.Tag == capture.SelectedDNS.Tag || server["detour"] != nil ||
				desktopExternalObjectDigest(server) != bootstrap.ConfigSHA256 {
				return nil, desktopExternalPolicyError
			}
			server["detour"], found = DesktopExternalPhysicalTag, true
		}
		if !found {
			return nil, desktopExternalPolicyError
		}
	}
	outbounds := []any{}
	if value, exists := graph["outbounds"]; exists {
		var ok bool
		outbounds, ok = value.([]any)
		if !ok || family == "endpoints" && (!entry || packetFinal) && len(outbounds) != 0 {
			return nil, desktopExternalPolicyError
		}
	}
	if entry && !packetFinal && !streamEntry {
		count, finalDetour := 1, capture.EntryTag
		if layered {
			count, finalDetour = 2, multihoprelay.ExitStartLayerTag
		}
		if len(outbounds) != count {
			return nil, desktopExternalPolicyError
		}
		var exit, layer map[string]any
		for _, row := range outbounds {
			object, ok := row.(map[string]any)
			if !ok {
				return nil, desktopExternalPolicyError
			}
			switch object["tag"] {
			case ExternalFinalTag:
				if exit != nil {
					return nil, desktopExternalPolicyError
				}
				exit = object
			case multihoprelay.ExitStartLayerTag:
				if !layered || layer != nil {
					return nil, desktopExternalPolicyError
				}
				layer = object
			default:
				return nil, desktopExternalPolicyError
			}
		}
		if exit == nil || exit["type"] != kind || exit["detour"] != finalDetour {
			return nil, desktopExternalPolicyError
		}
		if layered {
			layerKind := "shadowsocks"
			if capture.StartLayer == "aes-256-gcm+xor-whitening" {
				layerKind = "routervpn-aes-xor"
			}
			if layer == nil || layer["type"] != layerKind || layer["detour"] != capture.EntryTag || layer["method"] != NativeStartLayerMethod {
				return nil, desktopExternalPolicyError
			}
		}
		if meta.SOCKSUDPAssociationTunneled {
			username, _ := exit["username"].(string)
			password, _ := exit["password"].(string)
			if len(username) > 255 || len(password) > 255 {
				return nil, desktopExternalPolicyError
			}
			exit["type"] = DesktopExternalSOCKSType
			exit["session_id"], exit["source_sha256"] = sessionID, meta.SourceSHA256
		}
	}
	graph["outbounds"] = append(outbounds, map[string]any{
		"type": DesktopExternalPhysicalType, "tag": DesktopExternalPhysicalTag,
		"session_id": sessionID, "source_sha256": meta.SourceSHA256,
	})
	graph["services"] = []any{map[string]any{
		"type": DesktopExternalNetworkType, "tag": DesktopExternalNetworkTag,
		"session_id": sessionID, "source_sha256": meta.SourceSHA256,
	}}
	body, err := json.Marshal(graph)
	if err != nil || len(body) > 4<<20 {
		return nil, desktopExternalPolicyError
	}
	meta.ConfigSHA256 = externalDigest(body)
	policy := &DesktopExternalPolicy{original: original, config: string(body), metadata: meta}
	policy.seal = policy.currentSeal()
	if policy.seal == "" || policy.Validate() != nil {
		return nil, desktopExternalPolicyError
	}
	return policy, nil
}

// The original compiler validates the full credentials and graph before this
// bounded admission. The actual first root must still match its exact digest;
// an entry descriptor cannot turn an unrelated transport into physical egress.
func desktopExternalPacketEntryExit(protocol string) bool {
	return protocol == "openvpn" || protocol == "wireguard" || protocol == "amneziawg" || protocol == "shadowsocks" || protocol == "http-connect" || protocol == "https-connect" || protocol == "hysteria2" || protocol == "socks5"
}

func desktopExternalEntryKind(original *ExternalPolicy, capture ExternalDesktopCapture, targetOS string) string {
	if original == nil || capture.EntryID == "" || capture.EntryTag != "external-entry" ||
		capture.EntryNodeID != "" || capture.PredecessorSHA256 != "" || capture.Execution != "" ||
		!desktopExternalPacketEntryExit(capture.Protocol) {
		return ""
	}
	entry := original.capture.Entry
	external, ok := entry["external"].(map[string]any)
	if !ok || entry["id"] != capture.EntryID || entry["node_kind"] != "external" {
		return ""
	}
	switch external["protocol"] {
	case "wireguard", "amneziawg":
		if capture.EntryStartLayer != "" || capture.StartLayer != "" && (capture.Protocol != "hysteria2" || !multihoprelay.ValidLayerMode(capture.StartLayer)) {
			return ""
		}
		if external["protocol"] == "wireguard" {
			return "wireguard"
		}
		return AmneziaType
	case "shadowsocks":
		final, ok := original.capture.Profile["external"].(map[string]any)
		if (capture.EntryStartLayer == "" || multihoprelay.ValidLayerMode(capture.EntryStartLayer)) &&
			(capture.StartLayer == "" || multihoprelay.ValidLayerMode(capture.StartLayer)) &&
			((capture.StartLayer == "" && capture.EntryStartLayer == "") || capture.Protocol == "shadowsocks" || capture.Protocol == "hysteria2") &&
			ok && desktopExternalSS2022Import(external) &&
			(capture.Protocol == "shadowsocks" && desktopExternalSS2022Import(final) || capture.Protocol == "http-connect" || capture.Protocol == "https-connect" || capture.Protocol == "hysteria2") {
			return "shadowsocks"
		}
	}
	return ""
}

func desktopExternalLayerKind(mode string) string {
	if mode == "aes-256-gcm+xor-whitening" {
		return "routervpn-aes-xor"
	}
	return "shadowsocks"
}

// The already validated original graph contains precisely two independent raw
// SS owners and zero, one or two provisioned wrappers. Only the first wrapper
// (or the raw entry when Off) can acquire the physical lower owner.
func desktopExternalSSRows(rows []any, capture ExternalDesktopCapture, kind string, root ExternalDesktopPhysicalRoot) (map[string]any, error) {
	expected := map[string]struct{ kind, detour string }{
		capture.EntryTag: {"shadowsocks", ""}, ExternalFinalTag: {kind, capture.EntryTag},
	}
	if capture.EntryStartLayer != "" {
		expected[capture.EntryTag] = struct{ kind, detour string }{"shadowsocks", ExternalEntryStartLayerTag}
		expected[ExternalEntryStartLayerTag] = struct{ kind, detour string }{desktopExternalLayerKind(capture.EntryStartLayer), ""}
	}
	if capture.StartLayer != "" {
		expected[ExternalFinalTag] = struct{ kind, detour string }{kind, multihoprelay.ExitStartLayerTag}
		expected[multihoprelay.ExitStartLayerTag] = struct{ kind, detour string }{desktopExternalLayerKind(capture.StartLayer), capture.EntryTag}
	}
	if len(rows) != len(expected) {
		return nil, desktopExternalPolicyError
	}
	var physical map[string]any
	seen := map[string]bool{}
	for _, row := range rows {
		object, ok := row.(map[string]any)
		if !ok {
			return nil, desktopExternalPolicyError
		}
		tag, _ := object["tag"].(string)
		want, ok := expected[tag]
		if !ok || seen[tag] || object["type"] != want.kind || want.detour == "" && object["detour"] != nil || want.detour != "" && object["detour"] != want.detour {
			return nil, desktopExternalPolicyError
		}
		seen[tag] = true
		if (tag == ExternalEntryStartLayerTag || tag == multihoprelay.ExitStartLayerTag) && object["method"] != NativeStartLayerMethod {
			return nil, desktopExternalPolicyError
		}
		if tag == root.Tag {
			physical = object
		}
	}
	if physical == nil || physical["type"] != root.Type || physical["detour"] != nil || desktopExternalObjectDigest(physical) != root.ConfigSHA256 {
		return nil, desktopExternalPolicyError
	}
	return physical, nil
}

func desktopExternalObjectDigest(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return externalDigest(body)
}

func (p *DesktopExternalPolicy) currentSeal() string {
	if p == nil || p.original == nil || p.config == "" {
		return ""
	}
	return desktopExternalObjectDigest(struct {
		Domain   string                  `json:"domain"`
		Config   string                  `json:"config"`
		Metadata DesktopExternalMetadata `json:"metadata"`
	}{"routervpn-desktop-external-plan-v1", p.config, p.metadata})
}

// Validate rechecks the retained original constructor authority as well as the
// exact derived bytes. A copied public description or stale/replaced field is
// never sufficient to initialize a native lower path.
func (p *DesktopExternalPolicy) Validate() error {
	if p == nil || p.original == nil || p.seal == "" || p.currentSeal() != p.seal ||
		p.metadata.Schema != 1 || p.metadata.ConfigSHA256 != externalDigest([]byte(p.config)) {
		return desktopExternalPolicyError
	}
	capture, err := p.original.DesktopCapture()
	if err != nil || capture.SourceSHA256 != p.metadata.OriginalSourceSHA256 || capture.ConfigSHA256 != p.metadata.OriginalConfigSHA256 ||
		capture.MetadataSHA256 != p.metadata.OriginalMetadataSHA256 || capture.CaptureSHA256 != p.metadata.OriginalCaptureSHA256 {
		return desktopExternalPolicyError
	}
	return nil
}

func (p *DesktopExternalPolicy) Config() string {
	if p.Validate() != nil {
		return ""
	}
	return p.config
}

func (p *DesktopExternalPolicy) Metadata() DesktopExternalMetadata {
	if p.Validate() != nil {
		return DesktopExternalMetadata{}
	}
	return p.metadata
}

func (p *DesktopExternalPolicy) OriginalPolicy() *ExternalPolicy {
	if p.Validate() != nil {
		return nil
	}
	return p.original
}

func (p *DesktopExternalPolicy) Capture() (ExternalDesktopCapture, error) {
	if p.Validate() != nil {
		return ExternalDesktopCapture{}, desktopExternalPolicyError
	}
	return p.original.DesktopCapture()
}

// This bounded new entry family retains both ordinary SS2022 imports. Other
// final families and legacy ciphers require their own complete native unit.
func desktopExternalSS2022Import(external map[string]any) bool {
	if external["protocol"] != "shadowsocks" {
		return false
	}
	value, ok := external["shadowsocks"].(map[string]any)
	if !ok {
		return false
	}
	switch value["method"] {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	}
	return false
}
