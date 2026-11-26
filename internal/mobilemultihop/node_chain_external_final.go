package mobilemultihop

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
)

const externalFinalInputKind = "routervpn-node-chain-external-final"

// NodeChainExternalFinalEntryLayer accepts the original paired packet entry's layer.
// The imported streams and the independently captured public final require Off.
func NodeChainExternalFinalEntryLayer(layer string) bool {
	return layer == "" || layer == "off" || layer == "aes-256-gcm" || layer == "aes-256-gcm+xor-whitening"
}

func externalFinalLayerTransport(closure *externalPredecessor) (netip.AddrPort, string, error) {
	layer := closure.nodes[NativeStartLayerTag]
	if layer == nil {
		return netip.AddrPort{}, "", nil
	}
	if closure.final["detour"] != NativeStartLayerTag || layer["method"] != NativeStartLayerMethod {
		return netip.AddrPort{}, "", nodeChainError
	}
	peers, ok := closure.final["peers"].([]any)
	if !ok || len(peers) != 1 {
		return netip.AddrPort{}, "", nodeChainError
	}
	peer, ok := peers[0].(map[string]any)
	ip, err := netip.ParseAddr(predecessorText(peer, "address"))
	key := importedSS2022KeyIdentity(NativeStartLayerMethod, predecessorText(layer, "password"))
	if !ok || err != nil || ip.Zone() != "" || ip.Is4In6() || !externalPort(peer["port"]) || key == "" {
		return netip.AddrPort{}, "", nodeChainError
	}
	return netip.AddrPortFrom(ip, uint16(peer["port"].(float64))), key, nil
}

// NodeChainExternalFinalInput preserves the original authenticated Router-to-external
// policy. The ordered constructor separately binds its captured entry to position zero.
func NodeChainExternalFinalInput(config, capture string) (string, error) {
	raw, err := json.Marshal(nodeChainImportedInput{externalFinalInputKind, 1, config, capture})
	if err != nil || len(raw) > NodeChainInputLimit {
		return "", nodeChainError
	}
	if _, err := parseNodeChainExternalFinal(string(raw)); err != nil {
		return "", err
	}
	return string(raw), nil
}

func parseNodeChainExternalFinal(input string) (*nodeChainImportedMember, error) {
	var record nodeChainImportedInput
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil || record.Kind != externalFinalInputKind || record.Schema != 1 {
		return nil, nodeChainError
	}
	canonical, _ := json.Marshal(record)
	if string(canonical) != input {
		return nil, nodeChainError
	}
	policy, err := NewExternalPolicy(record.Config, record.Capture)
	if err != nil {
		return nil, err
	}
	s := policy.capture
	if s.Execution != nil || s.EntryTag != externalEntryTag || s.PredecessorConfig == "" || s.Protocol != "shadowsocks" ||
		s.Profile["node_kind"] != "external" || s.Entry["node_kind"] != "router-vpn" || s.Entry["id"] == s.ExitID {
		return nil, nodeChainError
	}
	for _, field := range []string{"node_proof_id", "router_api", "api_token"} {
		if v := s.Profile[field]; v != nil && v != "" {
			return nil, nodeChainError
		}
	}
	capture, err := policy.DesktopCapture()
	if err != nil || capture.Protocol != "shadowsocks" || capture.EntryTag != externalEntryTag || capture.ExpectedPublicIP != s.ExpectedPublicIP ||
		!NodeChainExternalFinalEntryLayer(capture.EntryStartLayer) || capture.StartLayer != "" && capture.StartLayer != "off" {
		return nil, nodeChainError
	}
	digest, _ := json.Marshal([]string{externalFinalInputKind, input})
	m := &nodeChainImportedMember{input: input, source: externalDigest(digest), selection: s, policy: policy, policyOwner: policy, policySeal: policy.desktopSeal}
	m.seal = m.digest()
	if _, _, err := externalFinalClosure(m, nil); err != nil {
		return nil, err
	}
	return m, nil
}

// Extract the exact external stream from the validated pair. Its original entry
// transport is present only as a witness; graph composition installs every
// selected predecessor instead. Application DNS uses the original final capture.
func externalFinalClosure(m *nodeChainImportedMember, intermediates []map[string]any) (*externalPredecessor, bool, error) {
	if m.validate() != nil {
		return nil, false, nodeChainError
	}
	var graph map[string]any
	if exactJSON([]byte(m.policy.Config()), &graph, 4<<20) != nil {
		return nil, false, nodeChainError
	}
	var final map[string]any
	for _, raw := range graph["outbounds"].([]any) {
		out := raw.(map[string]any)
		if out["tag"] == ExternalFinalTag {
			final = out
		}
	}
	if final == nil || final["type"] != "shadowsocks" || final["detour"] != externalEntryTag ||
		final["domain_resolver"] != nil || final["network"] != nil || final["udp_over_tcp"] != nil {
		return nil, false, nodeChainError
	}
	delete(final, "detour")
	if err := validateExtendedStreamClosures([]*externalPredecessor{{final: final}}); err != nil {
		return nil, false, err
	}
	ipv6, _, err := externalDevicePolicy(append(intermediates, m.selection.Profile, m.selection.Entry)...)
	if err != nil {
		return nil, false, err
	}
	dns, meta, err := externalSelectedDNS(m.selection, ipv6, true)
	if err != nil {
		return nil, false, err
	}
	graph["dns"] = predecessorCopy(dns)
	graph["outbounds"], graph["endpoints"], graph["services"] = []any{final}, []any{}, []any{}
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	p := &externalPredecessor{graph: graph, tun: tun, final: final, finalTag: ExternalFinalTag, nodes: map[string]map[string]any{ExternalFinalTag: final}, resolvers: map[string]map[string]any{}}
	for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
		row := raw.(map[string]any)
		p.resolvers[predecessorText(row, "tag")] = row
	}
	for _, raw := range graph["route"].(map[string]any)["rules"].([]any) {
		if row := raw.(map[string]any); row["action"] == "reject" {
			p.restrictions = append(p.restrictions, row)
		}
	}
	return p, meta.mode == "home", nil
}

func (r *nodeChainImportedNodes) compileExternalFinal(nodes []*NodeProfile) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
	fail := func(err error) (string, []NodeChainProof, NodeChainDNSCapture, []PhysicalEgress, error) {
		return "", nil, NodeChainDNSCapture{}, nil, err
	}
	if len(nodes) < 3 || len(nodes) > NodeChainExtendedLocalMaximumNodes || len(r.members) != len(nodes) || r.customEntry || r.members[0] != nil || nodes[0] == nil || !NodeChainPrefixMode(nodes[0].mode) {
		return fail(nodeChainError)
	}
	entry, last := nodes[0], len(nodes)-1
	final := r.members[last]
	if final == nil || entry.mode != "wg" && final.selection.Profile["multihop_entry_mode"] != entry.mode || final.selection.PredecessorConfig != entry.Config() || !reflect.DeepEqual(final.selection.Entry, entry.profile) {
		return fail(nodeChainError)
	}
	closures := make([]*externalPredecessor, len(nodes))
	members := make([]nodeChainGraphMember, len(nodes))
	var err error
	closures[0], err = nodeMultihopPredecessor(entry)
	if err != nil {
		return fail(err)
	}
	if closures[0].final["type"] != nodeChainPrefixType(entry.mode) {
		return fail(nodeChainError)
	}
	members[0] = nodeChainGraphMember{profile: entry.profile, source: entry.source, mode: entry.mode}
	var intermediates []map[string]any
	for i := 1; i <= last; i++ {
		m := r.members[i]
		if m == nil || m.hostname != nil || nodes[i] != nil {
			return fail(nodeChainError)
		}
		members[i] = nodeChainGraphMember{profile: m.selection.Profile, source: m.source, mode: "shadowsocks", imported: true}
		if i == last {
			closures[i], members[i].externalHome, err = externalFinalClosure(m, intermediates)
		} else {
			intermediates = append(intermediates, m.selection.Profile)
			closures[i], err = m.closure()
		}
		if err != nil {
			return fail(err)
		}
	}
	physical, err := entry.PhysicalEgress()
	if err != nil {
		return fail(err)
	}
	targets := make(map[netip.AddrPort]bool, len(physical))
	for _, root := range physical {
		addr, err := netip.ParseAddr(root.Host)
		if err != nil || root.Port <= 0 || root.Port > 65535 {
			return fail(nodeChainError)
		}
		targets[netip.AddrPortFrom(addr, uint16(root.Port))] = true
	}
	inner, layerKey, err := externalFinalLayerTransport(closures[0])
	if err != nil {
		return fail(err)
	}
	if inner.IsValid() {
		if targets[inner] {
			return fail(pairedStreamConflict)
		}
		targets[inner] = true
		for _, closure := range closures[1:] {
			if importedSS2022KeyIdentity(predecessorText(closure.final, "method"), predecessorText(closure.final, "password")) == layerKey {
				return fail(pairedStreamConflict)
			}
		}
	}
	if err := validateExtendedStreamTargets(closures[1:], targets, nil); err != nil {
		return fail(err)
	}
	config, proofs, dns, egress, err := compileNodeChainClosures(members, closures, physical)
	if err == nil && len(config) > NodeChainInputLimit/len(nodes) {
		return fail(nodeChainError)
	}
	return config, proofs, dns, egress, err
}

func externalFinalProofs(proofs []NodeChainProof) bool {
	if len(proofs) < 3 || len(proofs) > NodeChainExtendedLocalMaximumNodes {
		return false
	}
	for i, p := range proofs {
		if p.Position != i || !proofID.MatchString(p.SourceSHA256) || !exactID.MatchString(p.ProfileID) {
			return false
		}
		if i == 0 {
			if !NodeChainPrefixMode(p.Mode) || p.StartLayer == "" || !NodeChainExternalFinalEntryLayer(p.StartLayer) || p.NodeKind != "" || p.Kind != "" || !proofID.MatchString(p.NodeID) {
				return false
			}
		} else if p.StartLayer != "off" || p.Mode != "shadowsocks" || p.NodeKind != "external" || p.Kind != "public-path" || p.NodeID != "" {
			return false
		}
	}
	return true
}

// The source constructor checks every field of every proof. A frozen proof row
// may reuse that classification only while the complete inventory still matches.
func (r *nodeChainImportedNodes) externalFinalProofsCurrent(c *NodeChain) bool {
	if r.localSeal != nil {
		return r.localSeal.owner == c && r.localSeal.externalFinalProofs && slices.Equal(r.localSeal.proofs, c.proofs)
	}
	return externalFinalProofs(c.proofs)
}

func (c *NodeChain) HasExternalFinal() bool {
	return c != nil && c.importedNodes != nil && c.importedNodes.externalFinal && c.importedNodes.owner == c &&
		c.importedNodes.self == c.importedNodes && c.sourceJSON == c.importedNodes.sourceJSON && c.importedNodes.externalFinalProofsCurrent(c)
}

func (c *NodeChain) finalPreferences() map[string]any {
	last := len(c.nodes) - 1
	if c.HasExternalFinal() {
		return c.importedNodes.members[last].selection.Profile
	}
	return c.nodes[last].profile
}

func (c *NodeChain) finalDesktopCapture() (NodeDesktopCapture, error) {
	if c.HasExternalFinal() {
		capture, err := c.importedNodes.members[len(c.nodes)-1].policy.DesktopCapture()
		return NodeDesktopCapture{SelectedDNS: capture.SelectedDNS}, err
	}
	return c.nodes[len(c.nodes)-1].DesktopCapture()
}
