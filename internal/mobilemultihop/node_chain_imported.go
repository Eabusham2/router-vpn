package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

// This member retains the standalone original external source. It grants no
// Router pairing identity, API credential, physical socket or native owner.
type nodeChainImportedInput struct {
	Kind    string `json:"kind"`
	Schema  int    `json:"schema"`
	Config  string `json:"config"`
	Capture string `json:"capture"`
}
type nodeChainImportedMember struct {
	input, source, seal string
	selection           externalPolicyCapture
	policy              *ExternalPolicy
}

// NodeChainImportedMemberInput captures the only imported member admitted by
// schema 2: a literal, unlayered SS2022 middle between paired packet and SS
// members. Original standalone DNS is retained as source, but does not replace
// the ordered final member's selected application resolver.
func NodeChainImportedMemberInput(config, capture string) (string, error) {
	raw, err := json.Marshal(nodeChainImportedInput{"routervpn-node-chain-imported-member", 1, config, capture})
	if err != nil || len(raw) > NodeChainInputLimit {
		return "", nodeChainError
	}
	if _, err = parseNodeChainImportedMember(string(raw)); err != nil {
		return "", err
	}
	return string(raw), nil
}
func parseNodeChainImportedMember(input string) (*nodeChainImportedMember, error) {
	bad := errors.New("ordered imported middle requires its original literal unlayered SS2022 external source")
	var record nodeChainImportedInput
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil || record.Kind != "routervpn-node-chain-imported-member" || record.Schema != 1 {
		return nil, bad
	}
	canonical, _ := json.Marshal(record)
	if string(canonical) != input {
		return nil, bad
	}
	var selected externalPolicyCapture
	if exactJSON([]byte(record.Capture), &selected, 8<<20) != nil || selected.Schema != 1 || selected.Protocol != "shadowsocks" || selected.Profile == nil || selected.Profile["node_kind"] != "external" || selected.Entry != nil || selected.EntryTag != "" || selected.PredecessorConfig != "" || selected.Execution != nil {
		return nil, bad
	}
	for _, key := range []string{"node_proof_id", "router_api", "api_token"} {
		if v := selected.Profile[key]; v != nil && v != "" {
			return nil, bad
		}
	}
	layer := predecessorText(selected.Profile, "start_layer")
	if layer != "" && layer != "off" {
		return nil, bad
	}
	// As with the existing imported-entry constructor, only a private transport
	// projection uses rescue DNS. Exact original capture bytes remain immutable.
	transport := selected
	transport.Profile = predecessorCopy(selected.Profile)
	transport.Profile["dns_mode"] = "rescue"
	transport.DNSBootstrap = nil
	projected, _ := json.Marshal(transport)
	policy, err := NewExternalPolicy(record.Config, string(projected))
	if err != nil {
		return nil, err
	}
	var meta externalPolicyMetadata
	if json.Unmarshal([]byte(policy.Metadata()), &meta) != nil || meta.StartLayer != "" || meta.EntryID != "" || !meta.UDPAvailable {
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
	if !ok || out["tag"] != ExternalFinalTag || out["type"] != "shadowsocks" || out["method"] != NativeStartLayerMethod || strings.Contains(predecessorText(out, "password"), ":") || !importedSS2022Credentials(predecessorText(out, "method"), predecessorText(out, "password")) || out["detour"] != nil || out["domain_resolver"] != nil || out["udp_over_tcp"] != nil || out["network"] != nil {
		return nil, bad
	}
	addr, err := netip.ParseAddr(predecessorText(out, "server"))
	if err != nil || addr.Zone() != "" || addr.Is4In6() || addr.IsUnspecified() || addr.IsMulticast() {
		return nil, bad
	}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-imported-member-v1", input})
	result := &nodeChainImportedMember{input: input, source: externalDigest(digest), selection: selected, policy: policy}
	result.seal = result.digest()
	if result.validate() != nil {
		return nil, bad
	}
	return result, nil
}
func (m *nodeChainImportedMember) id() string { return m.selection.ExitID }
func (m *nodeChainImportedMember) digest() string {
	if m == nil || m.policy == nil {
		return ""
	}
	raw, _ := json.Marshal([]any{m.input, m.source, m.selection, m.policy.Config(), m.policy.Metadata()})
	return externalDigest(raw)
}
func (m *nodeChainImportedMember) validate() error {
	if m == nil || m.seal == "" || m.seal != m.digest() || m.policy == nil {
		return nodeChainError
	}
	_, err := m.policy.DesktopCapture()
	return err
}
func (m *nodeChainImportedMember) closure() (*externalPredecessor, error) {
	if m.validate() != nil {
		return nil, nodeChainError
	}
	graph := map[string]any{}
	if exactJSON([]byte(m.policy.Config()), &graph, 4<<20) != nil {
		return nil, nodeChainError
	}
	final := graph["outbounds"].([]any)[0].(map[string]any)
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	result := &externalPredecessor{graph: graph, tun: tun, final: final, finalTag: ExternalFinalTag, nodes: map[string]map[string]any{ExternalFinalTag: final}, resolvers: map[string]map[string]any{}}
	// Literal SS has no transport DNS dependency. Its standalone application DNS
	// is not installed into the chain; the final paired member owns that policy.
	graph["dns"] = map[string]any{"servers": []any{}}
	for _, raw := range graph["route"].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		if rule["action"] == "reject" {
			result.restrictions = append(result.restrictions, rule)
		}
	}
	return result, nil
}
func compileNodeChainImported(nodes []*NodeProfile, middle *nodeChainImportedMember) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
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
			members[i] = nodeChainGraphMember{profile: middle.selection.Profile, source: middle.source, mode: "shadowsocks", imported: true}
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
