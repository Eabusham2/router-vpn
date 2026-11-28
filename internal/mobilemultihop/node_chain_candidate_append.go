package mobilemultihop

import (
	"encoding/json"
	"errors"
	"reflect"
)

const nodeChainCandidateAppendSourceKind = "routervpn-node-chain-candidate-append-source"
const nodeChainCandidateAppendPreparationKind = "routervpn-node-chain-candidate-append-preparation"
const nodeChainCandidateAppendPurpose = "draft-prefix-append"

// NodeChainCandidateAppendNextMode is only a source classifier for the distinct
// incomplete Local append purpose. It grants no complete or selected route.
func NodeChainCandidateAppendNextMode(mode string) bool {
	return NodeChainPrefixMode(mode) || nodeChainAppendProxyMode(mode)
}

// The device source is captured separately from the forwarding prefix. It
// contributes only device TUN/settings authority, never a final node or proof.
type nodeChainCandidateAppendSourceRecord struct {
	Kind              string   `json:"kind"`
	Schema            int      `json:"schema"`
	Execution         string   `json:"execution"`
	DraftRevision     string   `json:"draft_revision"`
	DeviceRevision    string   `json:"device_revision"`
	DeviceSource      string   `json:"device_source"`
	DeviceMTURevision string   `json:"device_mtu_revision,omitempty"`
	DeviceFixedMTU    int      `json:"device_fixed_mtu,omitempty"`
	NextMode          string   `json:"next_mode"`
	NextKind          string   `json:"next_kind,omitempty"`
	AppendPosition    int      `json:"append_position"`
	Nodes             []string `json:"nodes"`
	IdentitySources   []string `json:"identity_sources"`
}

// NodeChainCandidateAppendSource is a source-only incomplete Local prefix. It
// cannot be passed to a complete-chain, selected-execution or connected owner.
// Its configuration has closed application/DNS ingress before it is returned.
type NodeChainCandidateAppendSource struct {
	self                     *NodeChainCandidateAppendSource
	record                   nodeChainCandidateAppendSourceRecord
	device, originalDevice   *NodeProfile
	nodes, originalNodes     []*NodeProfile
	imports, originalImports []*nodeChainImportedMember
	importOwners             []*nodeChainAppendImportedSeal
	source, sourceSHA        string
	config, configSHA, seal  string
	proofs                   []NodeChainProof
	physical                 []PhysicalEgress
	mtu                      NodeChainMTUPlan
}

var nodeChainCandidateAppendError = errors.New("candidate append requires its original incomplete Local prefix, independent device policy and exact prospective transport closure")

// NewNodeChainCandidateAppendSource compiles only actual prefix members. The
// same graph compiler handles each accepted depth; the physical traversal and
// packet MTU budgets remain the bounds rather than an invented two-hop limit.
func NewNodeChainCandidateAppendSource(input string) (*NodeChainCandidateAppendSource, error) {
	var record nodeChainCandidateAppendSourceRecord
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil ||
		record.Kind != nodeChainCandidateAppendSourceKind || record.Schema != 1 && record.Schema != 2 && record.Schema != 3 || record.Execution != "local" ||
		!nodeChainIdentityText(record.DraftRevision) || !nodeChainIdentityText(record.DeviceRevision) ||
		len(record.DraftRevision) > 256 || len(record.DeviceRevision) > 256 ||
		!NodeChainCandidateAppendNextMode(record.NextMode) || record.NextKind != "" && (record.NextKind != "external" || record.NextMode != "shadowsocks") || len(record.Nodes) < 1 || len(record.Nodes) >= NodeChainExtendedLocalMaximumNodes ||
		record.AppendPosition != len(record.Nodes) || len(record.IdentitySources) != len(record.Nodes) ||
		record.Schema == 3 && record.NextKind != "" ||
		record.DeviceMTURevision != "" && (!nodeChainIdentityText(record.DeviceMTURevision) || len(record.DeviceMTURevision) > 256) ||
		record.DeviceFixedMTU != 0 && (record.DeviceMTURevision == "" || record.DeviceFixedMTU < 1280 || record.DeviceFixedMTU > 9000) {
		return nil, nodeChainCandidateAppendError
	}
	// Parse device policy before any candidate exists. No physical traversal,
	// resolver dial or proof is obtained from this separate control profile.
	device, err := ParseNodeLaunchInput(record.DeviceSource)
	if err != nil || device == nil {
		return nil, nodeChainCandidateAppendError
	}
	source := &NodeChainCandidateAppendSource{record: record, device: device, originalDevice: device}
	source.self = source
	if err := source.captureMembers(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, nodeChainCandidateAppendError
	}
	source.source = string(raw)
	domain, _ := json.Marshal([]string{nodeChainCandidateAppendSourceKind + "-v1", source.source})
	source.sourceSHA = externalDigest(domain)
	clear(domain)
	config, proofsInventory, physical, err := source.compileGraph(nil)
	if err != nil {
		return nil, errors.Join(err, nodeChainCandidateAppendError)
	}
	source.proofs, source.physical = proofsInventory, physical
	source.config, source.mtu, err = source.applyDevicePolicy(config, proofsInventory)
	if err != nil {
		return nil, err
	}
	source.configSHA = externalDigest([]byte(source.config))
	source.seal = source.digest()
	return source, source.validate()
}

// Retain the device's original addresses, settings and current override while
// aggregating prefix restrictions. A control profile's private API is not a
// prefix destination and its route is deliberately not added to this graph.
func (s *NodeChainCandidateAppendSource) applyDevicePolicy(config string, proofs []NodeChainProof) (string, NodeChainMTUPlan, error) {
	var graph, device map[string]any
	if s == nil || s.device == nil || exactJSON([]byte(config), &graph, 4<<20) != nil ||
		exactJSON([]byte(s.device.config), &device, 4<<20) != nil {
		return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	inbounds, ok := device["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	captured, ok := inbounds[0].(map[string]any)
	if !ok || captured["type"] != "tun" || captured["auto_route"] != true || captured["strict_route"] != true {
		return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	tun := predecessorCopy(captured)
	tun["tag"] = "routervpn-chain-tun"
	if s.record.DeviceFixedMTU != 0 {
		jumbo, err := externalJumboPreference(s.device.profile)
		if err != nil || jumbo && s.record.DeviceFixedMTU != 9000 {
			return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
		}
		tun["mtu"] = float64(s.record.DeviceFixedMTU)
	}
	actual, err := mtuNumber(tun["mtu"])
	if err != nil {
		return "", NodeChainMTUPlan{}, err
	}
	route, ok := graph["route"].(map[string]any)
	deviceRoute, deviceOK := device["route"].(map[string]any)
	if !ok || !deviceOK {
		return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	rules, ok := route["rules"].([]any)
	deviceRules, deviceOK := deviceRoute["rules"].([]any)
	if !ok || !deviceOK {
		return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	seen := make(map[string]bool)
	for _, raw := range rules {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
		}
		seen[string(encoded)] = true
	}
	for _, raw := range deviceRules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
		}
		switch rule["action"] {
		case "hijack-dns", "route":
			continue
		case "reject":
			rule = predecessorCopy(rule)
			rule["inbound"] = []any{tun["tag"]}
			encoded, err := json.Marshal(rule)
			if err != nil {
				return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
			}
			if !seen[string(encoded)] {
				rules = append(rules, rule)
				seen[string(encoded)] = true
			}
		default:
			return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
		}
	}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
		}
		if rule["action"] == "reject" && rule["ip_version"] == float64(6) {
			tun["route_address"] = []any{"0.0.0.0/0", "::/0"}
		}
	}
	graph["inbounds"], route["rules"] = []any{tun}, rules
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	// This validates every original endpoint's configured MTU separately from
	// the shared TUN ceiling; it never resizes a prefix to fit a candidate.
	families, err := s.appendHostnameFamilies(string(raw), proofs)
	if err != nil {
		return "", NodeChainMTUPlan{}, err
	}
	mtu, err := orderedPrefixMTUBoundsWithHostnameFamilies(string(raw), proofs, actual, "routervpn-chain-tun", families)
	if err != nil {
		return "", NodeChainMTUPlan{}, err
	}
	if err := nodeChainExecutionGate(graph); err != nil {
		return "", NodeChainMTUPlan{}, err
	}
	raw, err = json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return "", NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	return string(raw), mtu, nil
}

func (s *NodeChainCandidateAppendSource) digest() string {
	if s == nil || s.self != s || s.device == nil {
		return ""
	}
	nodes := make([]string, len(s.nodes))
	if s.memberCapturesCurrent() != nil {
		return ""
	}
	for i, node := range s.nodes {
		if member := s.imports[i]; member != nil {
			nodes[i] = member.seal
		} else {
			nodes[i] = node.desktopSeal
		}
	}
	raw, err := json.Marshal([]any{nodeChainCandidateAppendSourceKind, s.record, s.device.desktopSeal, nodes,
		s.source, s.sourceSHA, s.config, s.configSHA, s.proofs, s.physical, s.mtu})
	if err != nil {
		return ""
	}
	defer clear(raw)
	return externalDigest(raw)
}

func (s *NodeChainCandidateAppendSource) validate() error {
	if s == nil || s.self != s || s.device == nil || s.device != s.originalDevice ||
		s.device.validateNodeDesktopCapture() != nil || len(s.nodes) < 1 || len(s.nodes) >= NodeChainExtendedLocalMaximumNodes ||
		s.memberCapturesCurrent() != nil || len(s.proofs) != len(s.nodes) ||
		s.record.AppendPosition != len(s.nodes) || !NodeChainCandidateAppendNextMode(s.record.NextMode) ||
		s.record.NextKind != "" && (s.record.NextKind != "external" || s.record.NextMode != "shadowsocks") ||
		s.seal == "" || s.seal != s.digest() {
		return nodeChainCandidateAppendError
	}
	for i, node := range s.nodes {
		proof := s.proofs[i]
		if proof.Position != i {
			return nodeChainCandidateAppendError
		}
		if member := s.imports[i]; member != nil {
			if proof.SourceSHA256 != member.source || proof.ProfileID != member.id() || proof.NodeID != "" ||
				proof.Mode != "shadowsocks" || proof.StartLayer != "off" || proof.NodeKind != "external" || proof.Kind != "public-path" {
				return nodeChainCandidateAppendError
			}
			continue
		}
		layer := predecessorText(node.profile, "start_layer")
		if layer == "" {
			layer = "off"
		}
		if proof.SourceSHA256 != node.source || proof.ProfileID != predecessorText(node.profile, "id") ||
			proof.NodeID != predecessorText(node.profile, "node_proof_id") || proof.Mode != node.mode ||
			proof.StartLayer != layer || proof.NodeKind != "" || proof.Kind != "" {
			return nodeChainCandidateAppendError
		}
	}
	return nil
}

func (s *NodeChainCandidateAppendSource) Source() string {
	if s.validate() != nil {
		return ""
	}
	return s.source
}
func (s *NodeChainCandidateAppendSource) SourceSHA256() string {
	if s.validate() != nil {
		return ""
	}
	return s.sourceSHA
}
func (s *NodeChainCandidateAppendSource) Config() string {
	if s.validate() != nil {
		return ""
	}
	return s.config
}

func (s *NodeChainCandidateAppendSource) ConfigSHA256() string {
	if s.validate() != nil {
		return ""
	}
	return s.configSHA
}
func (s *NodeChainCandidateAppendSource) CandidateMode() string {
	if s.validate() != nil {
		return ""
	}
	return s.record.NextMode
}
func (s *NodeChainCandidateAppendSource) AppendPosition() int {
	if s.validate() != nil {
		return -1
	}
	return len(s.nodes)
}

// The source has no runnable/connected receipt. This public description omits
// endpoint addresses, launch bytes, credentials and device control contents.
func (s *NodeChainCandidateAppendSource) Metadata() string {
	if s.validate() != nil {
		return ""
	}
	metadata := map[string]any{
		"schema": 1, "purpose": nodeChainCandidateAppendPurpose,
		"source_sha256": s.sourceSHA, "config_sha256": s.configSHA,
		"draft_revision": s.record.DraftRevision, "device_revision": s.record.DeviceRevision,
		"device_source_sha256": s.device.source, "device_mtu_revision": s.record.DeviceMTURevision,
		"candidate_mode": s.record.NextMode, "append_position": len(s.nodes), "prefix_position": len(s.nodes) - 1,
		"prefixes": s.proofs, "mtu": s.mtu, "application_open": false, "dns_open": false, "ready": false,
	}
	if s.record.NextKind == "external" {
		metadata["candidate_kind"] = "external"
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return ""
	}
	return string(raw)
}

// Each candidate is compiled prospectively without changing or reopening the
// original prefix. Packet and stream candidates share this exact source check.
func (s *NodeChainCandidateAppendSource) candidateConfig(input string) (string, []NodeChainProof, error) {
	if s.validate() != nil || s.record.NextKind != "" {
		return "", nil, nodeChainCandidateAppendError
	}
	candidate, err := ParseNodeLaunchInput(input)
	if err != nil || candidate == nil || candidate.mode != s.record.NextMode {
		return "", nil, nodeChainCandidateAppendError
	}
	return s.candidateGraphConfig(candidate, nil)
}

// Compare the one prospective member against the same original append prefix.
// This never installs a candidate into the closed native preparation.
func (s *NodeChainCandidateAppendSource) candidateGraphConfig(candidate *NodeProfile, imported *nodeChainImportedMember) (string, []NodeChainProof, error) {
	if s.validate() != nil || candidate == nil && imported == nil || candidate != nil && imported != nil {
		return "", nil, nodeChainCandidateAppendError
	}
	config, proofs, physical, err := s.compileGraphCandidate(candidate, imported)
	if err != nil || len(proofs) != len(s.proofs)+1 || !reflect.DeepEqual(proofs[:len(s.proofs)], s.proofs) ||
		!nodeChainSamePhysical(physical, s.physical) {
		return "", nil, errors.Join(err, nodeChainCandidateAppendError)
	}
	config, mtu, err := s.applyDevicePolicy(config, proofs)
	if err != nil || mtu.Original != s.mtu.Original || len(mtu.Prefixes) != len(proofs) ||
		!reflect.DeepEqual(mtu.Prefixes[:len(s.proofs)], s.mtu.Prefixes) {
		return "", nil, errors.Join(err, nodeChainCandidateAppendError)
	}
	original, err := candidatePrefixClosure(s.config, s.proofs)
	if err != nil {
		return "", nil, err
	}
	prospective, err := candidatePrefixClosure(config, proofs[:len(s.proofs)])
	if err != nil || !reflect.DeepEqual(original, prospective) {
		return "", nil, nodeChainCandidateAppendError
	}
	return config, proofs, nil
}

func (s *NodeChainCandidateAppendSource) candidatePacketOptions(input string) (string, error) {
	if s.validate() != nil || !NodeChainPrefixMode(s.record.NextMode) {
		return "", nodeChainCandidateAppendError
	}
	config, proofs, err := s.candidateConfig(input)
	if err != nil {
		return "", err
	}
	endpoints, err := packetCandidateEndpoints(config)
	if err != nil {
		return "", err
	}
	endpoint := endpoints[proofs[len(s.nodes)].Tag]
	if endpoint == nil || endpoint["type"] != nodeChainPrefixType(s.record.NextMode) ||
		endpoint["detour"] != s.proofs[len(s.proofs)-1].Tag || !candidateUnboundPacket(endpoint) {
		return "", nodeChainCandidateAppendError
	}
	delete(endpoint, "detour") // Only the exact retained append prefix may supply this socket.
	endpoint["tag"] = "proxy"
	raw, err := json.Marshal(endpoint)
	return string(raw), err
}

func (s *NodeChainCandidateAppendSource) candidateSSResponse(input string) (candidateResponseSource, error) {
	var empty candidateResponseSource
	if s.validate() != nil || s.record.NextMode != "shadowsocks" {
		return empty, nodeChainCandidateAppendError
	}
	response, err := parseCandidateResponseSource(input)
	if err != nil {
		return empty, err
	}
	config, proofs, err := s.candidateConfig(input)
	if err != nil {
		return empty, err
	}
	node, err := ParseNodeLaunchInput(input)
	if err != nil || node == nil {
		return empty, nodeChainCandidateAppendError
	}
	closure, err := nodeMultihopPredecessor(node)
	if err != nil || !nodeChainAppendSSClosure(closure) {
		return empty, nodeChainCandidateAppendError
	}
	proof := proofs[len(s.proofs)]
	if proof.ProfileID != response.Target.ID || proof.SourceSHA256 != response.Target.SourceSHA256 ||
		proof.NodeID != response.NodeID || proof.Mode != "shadowsocks" || proof.StartLayer != "off" ||
		proof.NodeKind != "" || proof.Kind != "" {
		return empty, nodeChainCandidateAppendError
	}
	projected, err := candidatePrefixClosure(config, proofs)
	expected := predecessorCopy(closure.final)
	expected["tag"], expected["detour"] = proof.Tag, s.proofs[len(s.proofs)-1].Tag
	if err != nil || !reflect.DeepEqual(projected["outbounds/"+proof.Tag], expected) ||
		response.Method != predecessorText(closure.final, "method") || response.Password != predecessorText(closure.final, "password") {
		return empty, nodeChainCandidateAppendError
	}
	return response, nil
}
