package mobilemultihop

import (
	"encoding/json"
	"errors"
	"router-vpn/internal/nativeopenvpn"
)

// This constructor captures the exact standalone OpenVPN source only. Schema 5
// admits one literal TCP/UDP remote between independent paired members; this
// member grants neither a physical socket nor a paired identity.
func NodeChainImportedOpenVPNMemberInput(config, capture string) (string, error) {
	raw, err := json.Marshal(nodeChainImportedInput{
		Kind: "routervpn-node-chain-openvpn-member", Schema: 1, Config: config, Capture: capture,
	})
	if err != nil || len(raw) > NodeChainInputLimit {
		return "", nodeChainOpenVPNSourceError
	}
	if _, err := parseNodeChainOpenVPNMember(string(raw)); err != nil {
		return "", err
	}
	return string(raw), nil
}

type nodeChainOpenVPNMember struct {
	input, source, seal string
	selection           externalPolicyCapture
	policy              *ExternalPolicy
}

var nodeChainOpenVPNSourceError = errors.New("ordered OpenVPN source requires its original bounded Local capture; native connected generation and capacity observation is required")

func parseNodeChainOpenVPNMember(input string) (*nodeChainOpenVPNMember, error) {
	bad := nodeChainOpenVPNSourceError
	var record nodeChainImportedInput
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil ||
		record.Kind != "routervpn-node-chain-openvpn-member" || record.Schema != 1 {
		return nil, bad
	}
	canonical, err := json.Marshal(record)
	if err != nil || string(canonical) != input {
		return nil, bad
	}
	var selected externalPolicyCapture
	if exactJSON([]byte(record.Capture), &selected, 8<<20) != nil ||
		selected.Schema != 1 || selected.Protocol != "openvpn" || selected.Profile == nil ||
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
		meta.Protocol != "openvpn" || meta.StartLayer != "" || meta.EntryID != "" || !meta.UDPAvailable {
		return nil, bad
	}
	graph := map[string]any{}
	if exactJSON([]byte(policy.Config()), &graph, 4<<20) != nil {
		return nil, bad
	}
	outs, ok := graph["outbounds"].([]any)
	ends, valid := graph["endpoints"].([]any)
	services, _ := graph["services"].([]any)
	if !ok || !valid || len(outs) != 0 || len(ends) != 1 || len(services) != 0 {
		return nil, bad
	}
	endpoint, ok := ends[0].(map[string]any)
	if !ok || endpoint["tag"] != ExternalFinalTag || endpoint["type"] != "openvpn-client" || endpoint["detour"] != nil {
		return nil, bad
	}
	remotes, err := nativeopenvpn.Remotes(endpoint)
	if err != nil || len(remotes) != 1 || remotes[0].Validate() != nil || predecessorText(selected.Profile, "endpoint") != remotes[0].Host {
		return nil, bad
	}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-openvpn-member-v1", input})
	member := &nodeChainOpenVPNMember{
		input: input, source: externalDigest(digest), selection: selected, policy: policy,
	}
	member.seal = member.digest()
	if member.validate() != nil {
		return nil, bad
	}
	return member, nil
}

func (m *nodeChainOpenVPNMember) digest() string {
	if m == nil || m.policy == nil {
		return ""
	}
	raw, err := json.Marshal([]any{m.input, m.source, m.selection, m.policy.Config(), m.policy.Metadata()})
	if err != nil {
		return ""
	}
	return externalDigest(raw)
}

func (m *nodeChainOpenVPNMember) validate() error {
	if m == nil || m.seal == "" || m.seal != m.digest() || m.policy == nil {
		return nodeChainOpenVPNSourceError
	}
	if _, err := m.policy.DesktopCapture(); err != nil {
		return nodeChainOpenVPNSourceError
	}
	return nil
}

func (m *nodeChainOpenVPNMember) devicePolicy() (nodeChainImportedDevicePolicy, error) {
	if m.validate() != nil {
		return nodeChainImportedDevicePolicy{}, nodeChainOpenVPNSourceError
	}
	capture, err := m.policy.DesktopCapture()
	if err != nil {
		return nodeChainImportedDevicePolicy{}, nodeChainOpenVPNSourceError
	}
	return nodeChainImportedDevicePolicy{capture.KillSwitchPolicy, capture.IPv6Mode, capture.HomeLANAccess}, nil
}

func (m *nodeChainOpenVPNMember) closure() (*externalPredecessor, error) {
	if m.validate() != nil {
		return nil, nodeChainOpenVPNSourceError
	}
	graph := map[string]any{}
	if exactJSON([]byte(m.policy.Config()), &graph, 4<<20) != nil {
		return nil, nodeChainOpenVPNSourceError
	}
	outs, ok := graph["endpoints"].([]any)
	if !ok || len(outs) != 1 {
		return nil, nodeChainOpenVPNSourceError
	}
	final, ok := outs[0].(map[string]any)
	if !ok || final["type"] != "openvpn-client" || final["tag"] != ExternalFinalTag {
		return nil, nodeChainOpenVPNSourceError
	}
	var tun map[string]any
	inbounds, ok := graph["inbounds"].([]any)
	if !ok {
		return nil, nodeChainOpenVPNSourceError
	}
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			return nil, nodeChainOpenVPNSourceError
		}
		if inbound["type"] == "tun" {
			if tun != nil {
				return nil, nodeChainOpenVPNSourceError
			}
			tun = inbound
		}
	}
	if tun == nil {
		return nil, nodeChainOpenVPNSourceError
	}
	result := &externalPredecessor{
		graph: graph, tun: tun, final: final, finalTag: ExternalFinalTag,
		nodes: map[string]map[string]any{ExternalFinalTag: final}, resolvers: map[string]map[string]any{},
	}
	graph["dns"] = map[string]any{"servers": []any{}}
	route, ok := graph["route"].(map[string]any)
	if !ok {
		return nil, nodeChainOpenVPNSourceError
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return nil, nodeChainOpenVPNSourceError
	}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return nil, nodeChainOpenVPNSourceError
		}
		if rule["action"] == "reject" {
			result.restrictions = append(result.restrictions, rule)
		}
	}
	return result, nil
}

func (m *nodeChainOpenVPNMember) id() string { return m.selection.ExitID }

func compileNodeChainOpenVPN(nodes []*NodeProfile, middle *nodeChainOpenVPNMember) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	fail := func(err error) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
		return "", nil, NodeChainDNSCapture{}, nil, err
	}
	if len(nodes) != 3 || nodes[0] == nil || nodes[1] != nil || nodes[2] == nil || !NodeChainPrefixMode(nodes[0].mode) || nodes[2].mode != "shadowsocks" || middle.validate() != nil {
		return fail(nodeChainError)
	}
	closures := make([]*externalPredecessor, 3)
	members := make([]nodeChainGraphMember, 3)
	for i, node := range nodes {
		var err error
		if i == 1 {
			closures[i], err = middle.closure()
			members[i] = nodeChainGraphMember{profile: middle.selection.Profile, source: middle.source, mode: "openvpn", imported: true}
		} else {
			closures[i], err = nodeMultihopPredecessor(node)
			members[i] = nodeChainGraphMember{profile: node.profile, source: node.source, mode: node.mode}
		}
		if err != nil {
			return fail(err)
		}
		if services, _ := closures[i].graph["services"].([]any); len(services) != 0 {
			return fail(nodeChainError)
		}
	}
	if closures[0].final["type"] != nodeChainPrefixType(nodes[0].mode) || (closures[2].final["type"] != "shadowsocks" && closures[2].final["type"] != "routervpn-aes-xor") || closures[2].final["method"] != NativeStartLayerMethod {
		return fail(nodeChainError)
	}
	physical, err := nodes[0].PhysicalEgress()
	if err != nil {
		return fail(err)
	}
	return compileNodeChainClosures(members, closures, physical)
}
