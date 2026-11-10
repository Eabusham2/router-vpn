package mobilemultihop

import (
	"encoding/json"
	"errors"
)

const (
	DesktopImportedSOCKSType      = "routervpn-desktop-imported-socks5"
	DesktopImportedEntryProofTag  = "multihop-entry-proof"
	DesktopImportedExitProofTag   = "multihop-proof"
	DesktopImportedEntryProofPort = 1098
	DesktopImportedExitProofPort  = 1099
)

type DesktopImportedRootMetadata struct {
	Family, Tag, Type             string
	OriginalSHA256, DerivedSHA256 string
}

// DesktopImportedMetadata names the actual imported entry and paired final;
// ProfileID is the final profile selected by the parent connection controller.
// Its private source hashes bind both originals, their exact graph, this native
// session, target and restored TUN value. They are comparison data, not proof.
type DesktopImportedMetadata struct {
	Schema                      int                           `json:"schema"`
	SessionID                   string                        `json:"session_id"`
	TargetOS                    string                        `json:"target_os"`
	SourceSHA256                string                        `json:"source_sha256"`
	ConfigSHA256                string                        `json:"config_sha256"`
	OriginalSourceSHA256        string                        `json:"original_source_sha256"`
	OriginalConfigSHA256        string                        `json:"original_config_sha256"`
	OriginalMetadataSHA256      string                        `json:"original_metadata_sha256"`
	OriginalCaptureSHA256       string                        `json:"original_capture_sha256"`
	ProfileID                   string                        `json:"profile_id"`
	EntryID                     string                        `json:"entry_id"`
	ExitID                      string                        `json:"exit_id"`
	ExitNodeID                  string                        `json:"exit_node_id"`
	EntryMode                   string                        `json:"entry_mode"`
	ExitMode                    string                        `json:"exit_mode"`
	EntryStartLayer             string                        `json:"entry_start_layer"`
	ExitStartLayer              string                        `json:"exit_start_layer"`
	EntryTag                    string                        `json:"entry_tag"`
	FinalTag                    string                        `json:"final_tag"`
	TUNTag                      string                        `json:"tun_tag"`
	OriginalTUNSHA256           string                        `json:"original_tun_sha256"`
	DerivedTUNSHA256            string                        `json:"derived_tun_sha256"`
	Roots                       []DesktopImportedRootMetadata `json:"roots"`
	KillSwitchPolicy            string                        `json:"kill_switch_policy"`
	IPv6Mode                    string                        `json:"ipv6_mode"`
	HomeLANAccess               bool                          `json:"home_lan_access"`
	SOCKSUDPAssociationRequired bool                          `json:"socks_udp_association_required"`
	RestoredMTU                 int                           `json:"restored_mtu,omitempty"`
}

// DesktopImportedPolicy has its own sealed constructor. A NodeProfile,
// ordinary final policy, graph document or metadata record cannot stand in
// for the independently captured imported entry and paired final sources.
type DesktopImportedPolicy struct {
	original *Controller
	config   string
	metadata DesktopImportedMetadata
	inputs   desktopNodePolicyInputs
	seal     string
}

var desktopImportedPolicyError = errors.New("protected desktop imported path requires its complete sealed entry and paired final")

func NewDesktopImportedPolicy(original *Controller, sessionID, targetOS string) (*DesktopImportedPolicy, error) {
	return NewDesktopImportedPolicyWithMTU(original, sessionID, targetOS, 0)
}

func NewDesktopImportedPolicyWithMTU(original *Controller, sessionID, targetOS string, restoredMTU int) (*DesktopImportedPolicy, error) {
	policy, err := deriveDesktopImportedPolicy(original, desktopNodePolicyInputs{sessionID, targetOS, restoredMTU}, nil)
	if err != nil || policy.Validate() != nil {
		return nil, desktopImportedPolicyError
	}
	return policy, nil
}

func deriveDesktopImportedPolicy(original *Controller, inputs desktopNodePolicyInputs, captured *ImportedDesktopCapture) (*DesktopImportedPolicy, error) {
	if original == nil || !desktopExternalSessionID.MatchString(inputs.sessionID) || (inputs.targetOS != "windows" && inputs.targetOS != "linux") {
		return nil, desktopImportedPolicyError
	}
	capture, err := original.ImportedDesktopCapture()
	if err != nil || (capture.KillSwitchPolicy != "on-connect" && capture.KillSwitchPolicy != "always") ||
		(capture.IPv6Mode != "on" && capture.IPv6Mode != "off") || capture.EntryID == "" || capture.ExitID == "" ||
		capture.EntryID == capture.ExitID || capture.EntryTag != "entry-wg" || capture.FinalTag != "proxy" ||
		len(capture.PhysicalRoots) == 0 || len(capture.PhysicalRoots) > 32 {
		return nil, desktopImportedPolicyError
	}
	// Linux initially admits only the packet entry and paired final whose native
	// retained lifecycle is implemented. Other graphs remain closed at compile.
	if inputs.targetOS == "linux" && (capture.EntryMode != "wireguard" || capture.ExitMode != "shadowsocks" ||
		capture.EntryStartLayer != "" || capture.ExitStartLayer != "") {
		return nil, desktopImportedPolicyError
	}
	if inputs.restoredMTU != 0 {
		var selected map[string]any
		if _, err := mtuNumber(float64(inputs.restoredMTU)); err != nil || exactJSON([]byte(original.imported.profile), &selected, 256<<10) != nil {
			return nil, desktopImportedPolicyError
		}
		jumbo, err := externalJumboPreference(selected)
		if err != nil || capture.MTUPolicy == "fixed" && inputs.restoredMTU != capture.ConfiguredMTU ||
			jumbo && (capture.ConfiguredMTU != 9000 || inputs.restoredMTU != capture.ConfiguredMTU) {
			return nil, desktopImportedPolicyError
		}
	}
	var graph map[string]any
	if exactJSON([]byte(original.config), &graph, 4<<20) != nil || graph == nil {
		return nil, desktopImportedPolicyError
	}
	for _, family := range []string{"inbounds", "outbounds", "endpoints", "services"} {
		if raw, exists := graph[family]; exists {
			rows, ok := raw.([]any)
			if !ok {
				return nil, desktopImportedPolicyError
			}
			for _, raw := range rows {
				value, ok := raw.(map[string]any)
				if !ok || value["tag"] == DesktopNodePhysicalTag || value["tag"] == DesktopNodeNetworkTag ||
					value["type"] == DesktopNodePhysicalType || value["type"] == DesktopNodeNetworkType || value["type"] == DesktopImportedSOCKSType ||
					value["tag"] == DesktopImportedEntryProofTag || value["tag"] == DesktopImportedExitProofTag {
					return nil, desktopImportedPolicyError
				}
			}
		}
	}
	ins := graph["inbounds"].([]any)
	tun := ins[0].(map[string]any)
	meta := DesktopImportedMetadata{
		Schema: 1, SessionID: inputs.sessionID, TargetOS: inputs.targetOS,
		OriginalSourceSHA256: capture.SourceSHA256, OriginalConfigSHA256: capture.ConfigSHA256,
		OriginalMetadataSHA256: capture.MetadataSHA256, OriginalCaptureSHA256: capture.CaptureSHA256,
		ProfileID: capture.ExitID, EntryID: capture.EntryID, ExitID: capture.ExitID, ExitNodeID: capture.ExitNodeID,
		EntryMode: capture.EntryMode, ExitMode: capture.ExitMode, EntryStartLayer: capture.EntryStartLayer, ExitStartLayer: capture.ExitStartLayer,
		EntryTag: capture.EntryTag, FinalTag: capture.FinalTag, TUNTag: capture.TUNTag,
		OriginalTUNSHA256: desktopExternalObjectDigest(tun), KillSwitchPolicy: capture.KillSwitchPolicy,
		IPv6Mode: capture.IPv6Mode, HomeLANAccess: capture.HomeLANAccess, RestoredMTU: inputs.restoredMTU,
	}
	physical := make([]map[string]any, 0, len(capture.PhysicalRoots))
	for _, root := range capture.PhysicalRoots {
		if (root.Family != "endpoints" && root.Family != "outbounds") || !proofID.MatchString(root.ConfigSHA256) || len(root.Destinations) == 0 {
			return nil, desktopImportedPolicyError
		}
		var found map[string]any
		rows, _ := graph[root.Family].([]any)
		for _, raw := range rows {
			value := raw.(map[string]any)
			if value["tag"] == root.Tag {
				if found != nil || value["type"] != root.Type || predecessorText(value, "detour") != "" || desktopExternalObjectDigest(value) != root.ConfigSHA256 {
					return nil, desktopImportedPolicyError
				}
				found = value
			}
		}
		if found == nil {
			return nil, desktopImportedPolicyError
		}
		if root.DynamicSOCKSUDP {
			if meta.SOCKSUDPAssociationRequired || capture.EntryMode != "socks5" || root.Tag != capture.EntryTag || root.Type != "socks" ||
				root.Family != "outbounds" || root.SOCKSVersion != "5" || root.SOCKSControl == nil || root.SOCKSControl.Network != "tcp" ||
				len(root.Destinations) != 1 || root.Destinations[0] != *root.SOCKSControl ||
				len(predecessorText(found, "username")) > 255 || len(predecessorText(found, "password")) > 255 {
				return nil, desktopImportedPolicyError
			}
			meta.SOCKSUDPAssociationRequired = true
		}
		physical = append(physical, found)
		meta.Roots = append(meta.Roots, DesktopImportedRootMetadata{Family: root.Family, Tag: root.Tag, Type: root.Type, OriginalSHA256: root.ConfigSHA256})
	}
	// The native owner identity precedes inserting its references. The final
	// graph digest separately seals all bytes, including both proof lanes.
	meta.SourceSHA256 = desktopExternalObjectDigest(struct {
		Domain string                  `json:"domain"`
		Policy DesktopImportedMetadata `json:"policy"`
	}{"routervpn-desktop-imported-source-v1", meta})
	if !proofID.MatchString(meta.SourceSHA256) {
		return nil, desktopImportedPolicyError
	}
	for index, root := range physical {
		root["detour"] = DesktopNodePhysicalTag
		if capture.PhysicalRoots[index].DynamicSOCKSUDP {
			root["type"] = DesktopImportedSOCKSType
			root["session_id"], root["source_sha256"] = inputs.sessionID, meta.SourceSHA256
		}
		meta.Roots[index].DerivedSHA256 = desktopExternalObjectDigest(root)
	}
	tun["interface_name"] = "router-vpn"
	if inputs.restoredMTU != 0 {
		tun["mtu"] = float64(inputs.restoredMTU)
	}
	meta.DerivedTUNSHA256 = desktopExternalObjectDigest(tun)
	if err := adaptDesktopPhysicalDNS(graph, capture.SelectedDNS, capture.BootstrapDNS); err != nil {
		return nil, desktopImportedPolicyError
	}
	graph["inbounds"] = []any{tun,
		map[string]any{"type": "mixed", "tag": DesktopImportedEntryProofTag, "listen": "127.0.0.1", "listen_port": DesktopImportedEntryProofPort},
		map[string]any{"type": "mixed", "tag": DesktopImportedExitProofTag, "listen": "127.0.0.1", "listen_port": DesktopImportedExitProofPort},
	}
	route, ok := graph["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return nil, desktopImportedPolicyError
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return nil, desktopImportedPolicyError
	}
	route["rules"] = append([]any{
		map[string]any{"inbound": []any{DesktopImportedEntryProofTag}, "outbound": capture.EntryTag},
		map[string]any{"inbound": []any{DesktopImportedExitProofTag}, "outbound": capture.FinalTag},
	}, rules...)
	rows, _ := graph["outbounds"].([]any)
	graph["outbounds"] = append(rows, map[string]any{
		"type": DesktopNodePhysicalType, "tag": DesktopNodePhysicalTag, "session_id": inputs.sessionID, "source_sha256": meta.SourceSHA256,
	})
	services, _ := graph["services"].([]any)
	graph["services"] = append(services, map[string]any{
		"type": DesktopNodeNetworkType, "tag": DesktopNodeNetworkTag, "session_id": inputs.sessionID, "source_sha256": meta.SourceSHA256,
	})
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return nil, desktopImportedPolicyError
	}
	meta.ConfigSHA256 = externalDigest(raw)
	policy := &DesktopImportedPolicy{original: original, config: string(raw), metadata: meta, inputs: inputs}
	policy.seal = policy.currentSeal()
	if policy.seal == "" {
		return nil, desktopImportedPolicyError
	}
	if captured != nil {
		*captured = capture
	}
	return policy, nil
}

func (p *DesktopImportedPolicy) currentSeal() string {
	if p == nil || p.original == nil || p.config == "" {
		return ""
	}
	return desktopExternalObjectDigest(struct {
		Domain   string                  `json:"domain"`
		Config   string                  `json:"config"`
		Metadata DesktopImportedMetadata `json:"metadata"`
	}{"routervpn-desktop-imported-plan-v1", p.config, p.metadata})
}

func (p *DesktopImportedPolicy) validatedCapture() (ImportedDesktopCapture, error) {
	var capture ImportedDesktopCapture
	if p == nil || p.original == nil || p.seal == "" || p.currentSeal() != p.seal || p.metadata.Schema != 1 || p.metadata.ConfigSHA256 != externalDigest([]byte(p.config)) {
		return capture, desktopImportedPolicyError
	}
	derived, err := deriveDesktopImportedPolicy(p.original, p.inputs, &capture)
	if err != nil || derived.config != p.config || derived.seal != p.seal {
		return ImportedDesktopCapture{}, desktopImportedPolicyError
	}
	return capture, nil
}

func (p *DesktopImportedPolicy) Validate() error { _, err := p.validatedCapture(); return err }

func (p *DesktopImportedPolicy) ReadValidated() (string, DesktopImportedMetadata, ImportedDesktopCapture, error) {
	capture, err := p.validatedCapture()
	if err != nil {
		return "", DesktopImportedMetadata{}, ImportedDesktopCapture{}, err
	}
	meta := p.metadata
	meta.Roots = append([]DesktopImportedRootMetadata(nil), meta.Roots...)
	return p.config, meta, capture, nil
}

func (p *DesktopImportedPolicy) Config() string {
	if p.Validate() != nil {
		return ""
	}
	return p.config
}
func (p *DesktopImportedPolicy) Metadata() DesktopImportedMetadata {
	_, meta, _, err := p.ReadValidated()
	if err != nil {
		return DesktopImportedMetadata{}
	}
	return meta
}
func (p *DesktopImportedPolicy) Capture() (ImportedDesktopCapture, error) {
	return p.validatedCapture()
}
func (p *DesktopImportedPolicy) OriginalController() *Controller {
	if p.Validate() != nil {
		return nil
	}
	return p.original
}
func (*DesktopImportedPolicy) desktopPhysicalPolicy() {}

func (p *DesktopImportedPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	config, meta, capture, err := p.ReadValidated()
	if err != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	return config, DesktopPhysicalMetadata{
			Kind: "imported", SessionID: meta.SessionID, TargetOS: meta.TargetOS, SourceSHA256: meta.SourceSHA256,
			ConfigSHA256: meta.ConfigSHA256, ProfileID: meta.ProfileID, KillSwitchPolicy: meta.KillSwitchPolicy,
			NodeID: meta.ExitNodeID, Mode: meta.ExitMode, StartLayer: meta.ExitStartLayer,
			IPv6Mode: meta.IPv6Mode, HomeLANAccess: meta.HomeLANAccess, RestoredMTU: meta.RestoredMTU,
		}, DesktopPhysicalCapture{
			TUNTag: capture.TUNTag, IPv6Mode: capture.IPv6Mode, ConfiguredMTU: capture.ConfiguredMTU,
			SelectedDNS: capture.SelectedDNS, BootstrapDNS: capture.BootstrapDNS, PhysicalRoots: capture.PhysicalRoots,
			PrivateDestinations: capture.PrivateDestinations,
		}, nil
}
