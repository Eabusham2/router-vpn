package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
)

// This constructor captures the original literal HTTP/HTTPS CONNECT source.
// Its member is distinct from schema 2 SS and schema 3 SOCKS; it grants no
// native runtime or paired owner.
func NodeChainImportedCONNECTMemberInput(config, capture string) (string, error) {
	raw, err := json.Marshal(nodeChainImportedInput{
		Kind: "routervpn-node-chain-connect-member", Schema: 1, Config: config, Capture: capture,
	})
	if err != nil || len(raw) > NodeChainInputLimit {
		return "", nodeChainCONNECTSourceError
	}
	if _, err := parseNodeChainCONNECTMember(string(raw)); err != nil {
		return "", err
	}
	return string(raw), nil
}

type nodeChainCONNECTMember struct {
	input, source, seal string
	selection           externalPolicyCapture
	policy              *ExternalPolicy
}

var nodeChainCONNECTSourceError = errors.New("ordered CONNECT source requires its original bounded Local capture; native admission remains closed")

func parseNodeChainCONNECTMember(input string) (*nodeChainCONNECTMember, error) {
	bad := nodeChainCONNECTSourceError
	var record nodeChainImportedInput
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil ||
		record.Kind != "routervpn-node-chain-connect-member" || record.Schema != 1 {
		return nil, bad
	}
	canonical, err := json.Marshal(record)
	if err != nil || string(canonical) != input {
		return nil, bad
	}
	var selected externalPolicyCapture
	if exactJSON([]byte(record.Capture), &selected, 8<<20) != nil ||
		selected.Schema != 1 || (selected.Protocol != "http-connect" && selected.Protocol != "https-connect") || selected.Profile == nil ||
		selected.Profile["node_kind"] != "external" || selected.Entry != nil ||
		selected.EntryTag != "" || selected.PredecessorConfig != "" || selected.Execution != nil {
		return nil, bad
	}
	for _, key := range []string{"node_proof_id", "router_api", "api_token"} {
		if value := selected.Profile[key]; value != nil && value != "" {
			return nil, bad
		}
	}
	layer := predecessorText(selected.Profile, "start_layer")
	if layer != "" && layer != "off" {
		return nil, bad
	}
	// A literal middle has no transport lookup. Its standalone DNS remains
	// private provenance; only the final paired node supplies application DNS.
	transport := selected
	transport.Profile = predecessorCopy(selected.Profile)
	transport.Profile["dns_mode"] = "rescue"
	transport.DNSBootstrap = nil
	projected, err := json.Marshal(transport)
	if err != nil {
		return nil, bad
	}
	policy, err := NewExternalPolicy(record.Config, string(projected))
	if err != nil {
		return nil, bad
	}
	var meta externalPolicyMetadata
	if exactJSON([]byte(policy.Metadata()), &meta, 64<<10) != nil ||
		meta.Protocol != selected.Protocol || meta.StartLayer != "" || meta.EntryID != "" || meta.UDPAvailable {
		return nil, bad
	}
	graph := map[string]any{}
	if exactJSON([]byte(policy.Config()), &graph, 4<<20) != nil {
		return nil, bad
	}
	outs, ok := graph["outbounds"].([]any)
	ends, _ := graph["endpoints"].([]any)
	services, _ := graph["services"].([]any)
	if !ok || len(outs) != 1 || len(ends) != 0 || len(services) != 0 {
		return nil, bad
	}
	out, ok := outs[0].(map[string]any)
	if !ok || out["tag"] != ExternalFinalTag || out["type"] != "http" || out["detour"] != nil || out["domain_resolver"] != nil ||
		out["udp_over_tcp"] != nil || out["network"] != nil {
		return nil, bad
	}
	address, err := netip.ParseAddr(predecessorText(out, "server"))
	if err != nil || address.Zone() != "" || address.Is4In6() ||
		address.IsUnspecified() || address.IsMulticast() {
		return nil, bad
	}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-connect-member-v1", input})
	member := &nodeChainCONNECTMember{
		input: input, source: externalDigest(digest), selection: selected, policy: policy,
	}
	member.seal = member.digest()
	if member.validate() != nil {
		return nil, bad
	}
	return member, nil
}

func (m *nodeChainCONNECTMember) digest() string {
	if m == nil || m.policy == nil {
		return ""
	}
	raw, err := json.Marshal([]any{m.input, m.source, m.selection, m.policy.Config(), m.policy.Metadata()})
	if err != nil {
		return ""
	}
	return externalDigest(raw)
}

func (m *nodeChainCONNECTMember) validate() error {
	if m == nil || m.seal == "" || m.seal != m.digest() || m.policy == nil {
		return nodeChainCONNECTSourceError
	}
	if _, err := m.policy.DesktopCapture(); err != nil {
		return nodeChainCONNECTSourceError
	}
	return nil
}

func (m *nodeChainCONNECTMember) devicePolicy() (nodeChainImportedDevicePolicy, error) {
	if m.validate() != nil {
		return nodeChainImportedDevicePolicy{}, nodeChainCONNECTSourceError
	}
	capture, err := m.policy.DesktopCapture()
	if err != nil {
		return nodeChainImportedDevicePolicy{}, nodeChainCONNECTSourceError
	}
	return nodeChainImportedDevicePolicy{capture.KillSwitchPolicy, capture.IPv6Mode, capture.HomeLANAccess}, nil
}

func (m *nodeChainCONNECTMember) closure() (*externalPredecessor, error) {
	if m.validate() != nil {
		return nil, nodeChainCONNECTSourceError
	}
	graph := map[string]any{}
	if exactJSON([]byte(m.policy.Config()), &graph, 4<<20) != nil {
		return nil, nodeChainCONNECTSourceError
	}
	outs, ok := graph["outbounds"].([]any)
	if !ok || len(outs) != 1 {
		return nil, nodeChainCONNECTSourceError
	}
	final, ok := outs[0].(map[string]any)
	if !ok || final["type"] != "http" || final["tag"] != ExternalFinalTag {
		return nil, nodeChainCONNECTSourceError
	}
	var tun map[string]any
	inbounds, ok := graph["inbounds"].([]any)
	if !ok {
		return nil, nodeChainCONNECTSourceError
	}
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			return nil, nodeChainCONNECTSourceError
		}
		if inbound["type"] == "tun" {
			if tun != nil {
				return nil, nodeChainCONNECTSourceError
			}
			tun = inbound
		}
	}
	if tun == nil {
		return nil, nodeChainCONNECTSourceError
	}
	result := &externalPredecessor{
		graph: graph, tun: tun, final: final, finalTag: ExternalFinalTag,
		nodes: map[string]map[string]any{ExternalFinalTag: final}, resolvers: map[string]map[string]any{},
	}
	graph["dns"] = map[string]any{"servers": []any{}}
	route, ok := graph["route"].(map[string]any)
	if !ok {
		return nil, nodeChainCONNECTSourceError
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return nil, nodeChainCONNECTSourceError
	}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return nil, nodeChainCONNECTSourceError
		}
		if rule["action"] == "reject" {
			result.restrictions = append(result.restrictions, rule)
		}
	}
	return result, nil
}
