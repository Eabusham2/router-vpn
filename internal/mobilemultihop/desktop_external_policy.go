package mobilemultihop

import (
	"encoding/json"
	"errors"
	"regexp"
)

const (
	DesktopExternalNetworkType  = "routervpn-desktop-external-network"
	DesktopExternalNetworkTag   = "routervpn-external-network-owner"
	DesktopExternalPhysicalType = "routervpn-desktop-external-physical"
	DesktopExternalPhysicalTag  = "routervpn-external-physical-egress"
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

// NewDesktopExternalPolicy derives only the direct ordinary proxy lower path.
// It preserves selected DNS, all transport credentials/options and every device
// rule. A SOCKS5 graph retains an explicit unsatisfied UDP-association requirement
// until the native host proves that capability; it is not silently made TCP-only.
// This constructor alone cannot enable a mode or a privileged OS firewall owner.
func NewDesktopExternalPolicy(original *ExternalPolicy, sessionID, targetOS string) (*DesktopExternalPolicy, error) {
	if original == nil || !desktopExternalSessionID.MatchString(sessionID) ||
		(targetOS != "linux" && targetOS != "windows" && targetOS != "darwin") {
		return nil, desktopExternalPolicyError
	}
	capture, err := original.DesktopCapture()
	if err != nil || capture.EntryID != "" || capture.EntryTag != "" || capture.PredecessorSHA256 != "" ||
		capture.Execution != "" || capture.StartLayer != "" || capture.EntryStartLayer != "" ||
		(capture.KillSwitchPolicy != "on-connect" && capture.KillSwitchPolicy != "always") ||
		(capture.IPv6Mode != "on" && capture.IPv6Mode != "off") || len(capture.PhysicalRoots) != 1 {
		return nil, desktopExternalPolicyError
	}
	kinds := map[string]string{"socks5": "socks", "http-connect": "http", "https-connect": "http", "shadowsocks": "shadowsocks"}
	kind, supported := kinds[capture.Protocol]
	root := capture.PhysicalRoots[0]
	if !supported || root.Family != "outbounds" || root.Tag != capture.FinalTag || root.Tag != ExternalFinalTag || root.Type != kind ||
		root.DynamicSOCKSUDP != (capture.Protocol == "socks5" && capture.UDPAvailable) ||
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
	if !ok || len(rows) != 1 {
		return nil, desktopExternalPolicyError
	}
	physical, ok := rows[0].(map[string]any)
	if !ok || physical["tag"] != root.Tag || physical["type"] != root.Type || physical["detour"] != nil ||
		desktopExternalObjectDigest(physical) != root.ConfigSHA256 {
		return nil, desktopExternalPolicyError
	}
	meta := DesktopExternalMetadata{
		Schema: 1, SessionID: sessionID, TargetOS: targetOS,
		OriginalSourceSHA256: capture.SourceSHA256, OriginalConfigSHA256: capture.ConfigSHA256,
		OriginalMetadataSHA256: capture.MetadataSHA256, OriginalCaptureSHA256: capture.CaptureSHA256,
		Protocol: capture.Protocol, RootTag: root.Tag, RootType: root.Type, OriginalRootSHA256: root.ConfigSHA256,
		KillSwitchPolicy: capture.KillSwitchPolicy, IPv6Mode: capture.IPv6Mode, HomeLANAccess: capture.HomeLANAccess,
		SOCKSUDPAssociationRequired: root.DynamicSOCKSUDP,
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
	graph["outbounds"] = append(rows, map[string]any{
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
