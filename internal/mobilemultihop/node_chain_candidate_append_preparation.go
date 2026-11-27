package mobilemultihop

import (
	"encoding/json"
	"errors"
	"reflect"

	"router-vpn/internal/hopmeasure"
)

type nodeChainCandidateAppendPreparationSource struct {
	Kind           string `json:"kind"`
	Schema         int    `json:"schema"`
	PrefixSource   string `json:"prefix_source"`
	PrefixPosition int    `json:"prefix_position"`
	AppendPosition int    `json:"append_position"`
	Inventory      string `json:"inventory"`
}

// CandidateInputFitsSource is a socket-free per-row check. It performs the
// same cross-role identity and prospective whole-prefix/MTU validation used by
// the complete append inventory; it grants no native measurement owner.
func (s *NodeChainCandidateAppendSource) CandidateInputFitsSource(input string) bool {
	if s.validate() != nil || len(input) == 0 || len(input) > NodeChainInputLimit {
		return false
	}
	raw, err := json.Marshal(NodeChainCandidateInventory{Schema: 1, Revision: "append-candidate-row-preflight",
		Inputs: []string{input}, ResponseMode: s.record.NextMode})
	if err != nil {
		return false
	}
	defer clear(raw)
	_, err = s.newCandidatePlan(string(raw))
	return err == nil
}

func (s *NodeChainCandidateAppendSource) newCandidatePlan(inventory string) (*NodeChainCandidatePlan, error) {
	if s.validate() != nil {
		return nil, nodeChainCandidateAppendError
	}
	var record NodeChainCandidateInventory
	if exactJSON([]byte(inventory), &record, NodeChainInputLimit) != nil || record.Schema != 1 ||
		!nodeChainIdentityText(record.Revision) || len(record.Inputs) == 0 || record.ResponseMode != s.record.NextMode {
		return nil, nodeChainCandidateAppendError
	}
	p := &NodeChainCandidatePlan{appendSource: s, metadataPages: &nodeChainCandidateMetadataCache{},
		inventory: inventory, revision: record.Revision, prefix: s.proofs[len(s.proofs)-1],
		measurement:            hopmeasure.CandidatePrivateResponseMeasurement,
		preparedNativeResponse: true, responseMode: s.record.NextMode}
	ids, proofs, keys := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	for position, node := range s.nodes {
		if member := s.imports[position]; member != nil {
			ids[member.id()] = true
			continue
		}
		ids[predecessorText(node.profile, "id")] = true
		proofs[predecessorText(node.profile, "node_proof_id")] = true
		if NodeChainPrefixMode(node.mode) {
			client, server, err := nodeChainPacketKeys(node)
			if err != nil || client == server || keys[client] || keys[server] {
				return nil, nodeChainCandidateAppendError
			}
			keys[client], keys[server] = true, true
		}
	}
	for _, input := range record.Inputs {
		response, err := parseCandidateNativeResponseSource(input, s.record.NextMode)
		if err != nil || ids[response.Target.ID] || proofs[response.NodeID] ||
			response.ClientKey == response.ServerKey || keys[response.ClientKey] || keys[response.ServerKey] {
			return nil, nodeChainCandidateAppendError
		}
		response.PacketOptions, err = s.candidatePacketOptions(input)
		if err != nil {
			return nil, err
		}
		ids[response.Target.ID], proofs[response.NodeID] = true, true
		keys[response.ClientKey], keys[response.ServerKey] = true, true
		p.targets = append(p.targets, response.Target)
		p.responses = append(p.responses, response)
	}
	raw, err := json.Marshal([]any{nodeChainCandidateAppendPurpose, s.seal, s.sourceSHA, s.configSHA, p.prefix, inventory})
	if err != nil {
		return nil, nodeChainCandidateAppendError
	}
	p.capture = externalDigest(raw)
	clear(raw)
	p.seal = p.digest()
	return p, p.validate()
}

func (p *NodeChainCandidatePlan) appendDigest() string {
	if p == nil || p.appendSource == nil {
		return ""
	}
	raw, err := json.Marshal([]any{nodeChainCandidateAppendPurpose, p.appendSource.seal, p.inventory, p.revision,
		p.prefix, p.targets, p.responses, p.measurement, p.preparedNativeResponse, p.responseMode, p.capture})
	if err != nil {
		return ""
	}
	defer clear(raw)
	return externalDigest(raw)
}

func (p *NodeChainCandidatePlan) validateAppend() error {
	if p == nil || p.appendSource == nil || p.appendSource.validate() != nil ||
		p.chain != nil || p.multiple != nil || p.multipleSeal != nil || p.connectedFinalResponse ||
		!p.preparedNativeResponse || p.publicResponses != nil || p.measurement != hopmeasure.CandidatePrivateResponseMeasurement ||
		p.responseMode != p.appendSource.record.NextMode || p.prefix != p.appendSource.proofs[len(p.appendSource.proofs)-1] ||
		len(p.targets) == 0 || len(p.targets) != len(p.responses) || p.seal == "" || p.seal != p.appendDigest() {
		return nodeChainCandidateAppendError
	}
	return nil
}

func (p *NodeChainCandidatePlan) appendMetadata() string {
	if p.validateAppend() != nil || p.metadataPages == nil {
		return ""
	}
	p.metadataPages.mu.Lock()
	defer p.metadataPages.mu.Unlock()
	if p.metadataPages.full != "" {
		return p.metadataPages.full
	}
	targets := make([]map[string]string, len(p.targets))
	for i, target := range p.targets {
		targets[i] = map[string]string{"id": target.ID, "source_sha256": target.SourceSHA256}
	}
	s := p.appendSource
	raw, err := json.Marshal(map[string]any{
		"schema": 1, "purpose": nodeChainCandidateAppendPurpose, "capture_sha256": p.capture,
		"prefix_position": p.prefix.Position, "prefix_id": p.prefix.ProfileID, "append_position": len(s.nodes),
		"source_sha256": s.sourceSHA, "config_sha256": s.configSHA, "targets": targets,
		"measurement": p.measurement, "candidate_mode": p.responseMode,
		"draft_revision": s.record.DraftRevision, "device_revision": s.record.DeviceRevision,
		"device_source_sha256": s.device.source, "device_mtu_revision": s.record.DeviceMTURevision,
	})
	if err != nil {
		return ""
	}
	p.metadataPages.full = string(raw)
	return p.metadataPages.full
}

// NewNodeChainCandidateAppendPreparation retains a distinct append source and
// plan. No complete NodeChain is created, copied, shortened or filled with the
// proposed candidate. Its runtime graph is the original prefix alone.
func NewNodeChainCandidateAppendPreparation(prefixSource, inventory string) (*NodeChainCandidatePreparation, error) {
	source, err := NewNodeChainCandidateAppendSource(prefixSource)
	if err != nil {
		return nil, err
	}
	candidates, err := source.newCandidatePlan(inventory)
	if err != nil {
		return nil, err
	}
	p := &NodeChainCandidatePreparation{appendSource: source, candidates: candidates, position: len(source.nodes) - 1,
		config: source.config, configSHA: source.configSHA, proofs: append([]NodeChainProof(nil), source.proofs...),
		physical: append([]PhysicalEgress(nil), source.physical...), mtu: source.mtu}
	p.mtu.Prefixes = append([]NodeChainMTUBound(nil), source.mtu.Prefixes...)
	record := nodeChainCandidateAppendPreparationSource{Kind: nodeChainCandidateAppendPreparationKind, Schema: 1,
		PrefixSource: source.source, PrefixPosition: p.position, AppendPosition: len(source.nodes), Inventory: inventory}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, nodeChainCandidateAppendError
	}
	p.source = string(raw)
	domain, _ := json.Marshal([]string{nodeChainCandidateAppendPreparationKind + "-v1", p.source})
	p.sourceSHA = externalDigest(domain)
	clear(domain)
	capture, _ := json.Marshal([]string{p.sourceSHA, p.configSHA, candidates.capture})
	p.capture = externalDigest(capture)
	clear(capture)
	p.seal = p.digest()
	return p, p.validate()
}

func ParseNodeChainCandidateAppendPreparation(input string) (*NodeChainCandidatePreparation, error) {
	var record nodeChainCandidateAppendPreparationSource
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil ||
		record.Kind != nodeChainCandidateAppendPreparationKind || record.Schema != 1 {
		return nil, nodeChainCandidateAppendError
	}
	p, err := NewNodeChainCandidateAppendPreparation(record.PrefixSource, record.Inventory)
	if err != nil || p == nil || p.source != input || p.position != record.PrefixPosition ||
		len(p.proofs) != record.AppendPosition {
		return nil, errors.Join(err, nodeChainCandidateAppendError)
	}
	return p, nil
}

func (p *NodeChainCandidatePreparation) appendDigest() string {
	if p == nil || p.appendSource == nil || p.candidates == nil {
		return ""
	}
	raw, err := json.Marshal([]any{nodeChainCandidateAppendPreparationKind, p.appendSource.seal, p.candidates.seal,
		p.source, p.sourceSHA, p.config, p.configSHA, p.capture, p.position, p.proofs, p.physical, p.mtu})
	if err != nil {
		return ""
	}
	defer clear(raw)
	return externalDigest(raw)
}

func (p *NodeChainCandidatePreparation) validateAppend() error {
	if p == nil || p.appendSource == nil || p.appendSource.validate() != nil ||
		p.original != nil || p.typedOriginal != nil || p.multipleOriginal != nil || p.candidates == nil ||
		p.candidates.appendSource != p.appendSource || p.candidates.validateAppend() != nil ||
		p.position != len(p.appendSource.nodes)-1 || !reflect.DeepEqual(p.proofs, p.appendSource.proofs) ||
		!nodeChainSamePhysical(p.physical, p.appendSource.physical) || p.seal == "" || p.seal != p.appendDigest() {
		return nodeChainCandidateAppendError
	}
	return nil
}

func (p *NodeChainCandidatePreparation) IsAppend() bool {
	return p != nil && p.appendSource != nil && p.validateAppend() == nil
}
func (p *NodeChainCandidatePreparation) AppendPosition() int {
	if !p.IsAppend() {
		return -1
	}
	return len(p.appendSource.nodes)
}

// AppendSourceMetadata supplies the separately captured original prefix
// description. Candidate pages bind its digest rather than repeating all
// proof rows in every page, so deeper prefixes remain bounded on the wire.
func (p *NodeChainCandidatePreparation) AppendSourceMetadata() string {
	if !p.IsAppend() {
		return ""
	}
	return p.appendSource.Metadata()
}

func (p *NodeChainCandidatePreparation) appendMetadata() string {
	if p.validateAppend() != nil {
		return ""
	}
	var result map[string]any
	if json.Unmarshal([]byte(p.candidates.Metadata()), &result) != nil {
		return ""
	}
	s := p.appendSource
	proofs, _ := json.Marshal(p.proofs)
	mtu, _ := json.Marshal(p.mtu)
	result["capture_sha256"], result["source_sha256"], result["config_sha256"] = p.capture, p.sourceSHA, p.configSHA
	result["original_source_sha256"] = s.sourceSHA
	result["prefix_count"], result["prefixes_sha256"], result["mtu_sha256"] = len(p.proofs), externalDigest(proofs), externalDigest(mtu)
	result["append_source_metadata_sha256"] = externalDigest([]byte(s.Metadata()))
	result["application_open"], result["dns_open"], result["ready"] = false, false, false
	result["stage"], result["mtu_measurement"] = "pending-prefix-proof", "configured-bounds-only"
	raw, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(raw)
}

// These helpers select only from an already validated private purpose. They
// cannot turn an append prefix into a complete-source or imported registry.
func (p *NodeChainCandidatePreparation) prefixNode(position int) *NodeProfile {
	if p == nil || position < 0 || position >= len(p.proofs) {
		return nil
	}
	if p.appendSource != nil {
		return p.appendSource.nodes[position]
	}
	if p.original == nil || position >= len(p.original.nodes) {
		return nil
	}
	return p.original.nodes[position]
}
func (p *NodeChainCandidatePreparation) importedPrefix(position int) *nodeChainImportedMember {
	if p == nil || position < 0 || position >= len(p.proofs) {
		return nil
	}
	if p.appendSource != nil {
		if position >= len(p.appendSource.imports) {
			return nil
		}
		return p.appendSource.imports[position]
	}
	if p.original == nil {
		return nil
	}
	return p.original.importedSSMemberAt(position)
}
func (p *NodeChainCandidatePreparation) candidateMTU(graph map[string]any) (NodeChainMTUPlan, error) {
	if p.appendSource == nil {
		return candidatePreparationMTU(graph, p.proofs, p.original)
	}
	if p.appendSource.validate() != nil || !reflect.DeepEqual(p.proofs, p.appendSource.proofs) {
		return NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	inbounds, ok := graph["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return NodeChainMTUPlan{}, nodeChainCandidateAppendError
	}
	actual, err := mtuNumber(tun["mtu"])
	if err != nil {
		return NodeChainMTUPlan{}, err
	}
	raw, err := json.Marshal(graph)
	if err != nil {
		return NodeChainMTUPlan{}, err
	}
	return orderedPrefixMTUBounds(string(raw), p.proofs, actual, predecessorText(tun, "tag"))
}
