package mobilemultihop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

const nodeChainAppendExecutionKind = "routervpn-node-chain-append-execution-source"

var errNodeChainAppendExecution = errors.New("append execution requires its original packet-head prefix with an optional paired SS tail, independent registered suffix and current native owner")

type nodeChainAppendExecutionSource struct {
	Kind        string `json:"kind"`
	Schema      int    `json:"schema"`
	Execution   string `json:"execution"`
	LocalSource string `json:"local_source"`
	Inventory   string `json:"inventory"`
}

// This purpose retains a real Local append preparation; it is not a shortened
// complete NodeChain. Authenticated runtime discovery, never a UI descriptor,
// binds the independent remote source and its proposed listener separately.
type NodeChainCandidateAppendExecutionPolicy struct {
	self                                  *NodeChainCandidateAppendExecutionPolicy
	record                                nodeChainAppendExecutionSource
	original, capturedOriginal            *NodeChainCandidatePreparation
	localMembers                          []multihoprelay.NodeChainPrefixMember
	candidates                            []multihoprelay.NodeChainPrefixCandidate
	inputs                                []string
	packetCandidates                      []nodeChainAppendExecutionPacketIdentity
	source, sourceSHA, inventorySHA, seal string
	metadata                              string
	projection                            *DesktopNodeCandidatePreparationPolicy
	originalPolicy                        *NodeChainCandidateAppendExecutionPolicy
}

func nodeChainAppendExecutionDigest(domain string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", errNodeChainAppendExecution
	}
	defer clear(raw)
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain + "\x00"))
	_, _ = hash.Write(raw)
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func NewNodeChainCandidateAppendExecutionPolicy(input string) (*NodeChainCandidateAppendExecutionPolicy, error) {
	var record nodeChainAppendExecutionSource
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil || record.Kind != nodeChainAppendExecutionKind || record.Schema != 1 ||
		record.Execution != "server" && record.Execution != "auto" {
		return nil, errNodeChainAppendExecution
	}
	original, err := NewNodeChainCandidateAppendPreparation(record.LocalSource, record.Inventory)
	if err != nil || original == nil || original.validateAppend() != nil {
		return nil, errors.Join(err, errNodeChainAppendExecution)
	}
	source := original.appendSource
	schema, schemaErr := nodeChainPrefixLocalSchema(source.nodes)
	packetNext := nodeChainAppendExecutionPacketMode(source.record.NextMode)
	if schemaErr != nil || source.record.Schema != schema || source.record.Execution != "local" || source.record.NextKind != "" || source.record.NextMode != "shadowsocks" && !packetNext || packetNext && schema != 1 ||
		source.source != record.LocalSource || len(source.nodes) < 1 || len(source.nodes) > multihoprelay.NodeChainPrefixMaximumMembers ||
		len(original.candidates.responses) < 1 || len(original.candidates.responses) > multihoprelay.NodeChainPrefixMaximumCandidates ||
		original.candidates.measurement != hopmeasure.CandidatePrivateResponseMeasurement || original.candidates.preparedNativeResponse != packetNext {
		return nil, errNodeChainAppendExecution
	}
	var inventory NodeChainCandidateInventory
	if exactJSON([]byte(record.Inventory), &inventory, NodeChainInputLimit) != nil || inventory.Schema != 1 || inventory.ResponseMode != source.record.NextMode || len(inventory.Inputs) != len(original.candidates.responses) {
		return nil, errNodeChainAppendExecution
	}
	p := &NodeChainCandidateAppendExecutionPolicy{record: record, original: original, capturedOriginal: original, inputs: append([]string(nil), inventory.Inputs...)}
	p.self = p
	for position, node := range source.nodes {
		proof := source.proofs[position]
		if node == nil || source.imports[position] != nil || proof.StartLayer != "off" || proof.NodeKind != "" || proof.Kind != "" {
			return nil, errNodeChainAppendExecution
		}
		member, err := nodeChainPrefixCapturedMember(node, source.record.IdentitySources[position], position, schema)
		if err != nil || member.ProfileID != proof.ProfileID || member.NodeID != proof.NodeID || member.Mode != proof.Mode || member.SourceSHA256 != proof.SourceSHA256 {
			return nil, errNodeChainAppendExecution
		}
		p.localMembers = append(p.localMembers, member)
	}
	for i, response := range original.candidates.responses {
		candidate, err := ParseNodeLaunchInput(inventory.Inputs[i])
		if err != nil || candidate == nil || candidate.mode != source.record.NextMode || candidate.source != response.Target.SourceSHA256 ||
			predecessorText(candidate.profile, "node_proof_id") != response.NodeID || !packetNext && response.Method != NativeStartLayerMethod ||
			source.CandidateInputFitsSource(inventory.Inputs[i]) == false {
			return nil, errNodeChainAppendExecution
		}
		if packetNext {
			identity, err := nodeChainAppendExecutionPacketIdentityFromNode(len(source.nodes), candidate)
			if err != nil || identity.ProfileID != response.Target.ID || identity.NodeID != response.NodeID ||
				identity.SourceSHA256 != response.Target.SourceSHA256 || identity.ClientPublicKey != response.ClientKey ||
				identity.PeerPublicKey != response.ServerKey || response.PacketOptions == "" || response.Method != "" || response.Password != "" {
				return nil, errNodeChainAppendExecution
			}
			p.packetCandidates = append(p.packetCandidates, identity)
		}
		p.candidates = append(p.candidates, multihoprelay.NodeChainPrefixCandidate{ProfileID: response.Target.ID, NodeID: response.NodeID, Mode: source.record.NextMode, StartLayer: "off", SourceSHA256: response.Target.SourceSHA256})
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, errNodeChainAppendExecution
	}
	p.source = string(raw)
	p.sourceSHA, err = nodeChainAppendExecutionDigest("routervpn-append-execution-source-v1", record)
	if err != nil {
		return nil, err
	}
	p.inventorySHA, err = nodeChainAppendExecutionDigest("routervpn-append-prefix-inventory-v1", record.Inventory)
	if err != nil {
		return nil, err
	}
	p.seal = p.digest()
	if p.seal == "" {
		return nil, errNodeChainAppendExecution
	}
	p.metadata = p.buildMetadata()
	if p.metadata == "" {
		return nil, errNodeChainAppendExecution
	}
	p.seal = p.digest()
	return p, p.validate()
}
func (p *NodeChainCandidateAppendExecutionPolicy) digest() string {
	if p == nil || p.original == nil {
		return ""
	}
	projection, original := "", ""
	if p.projection != nil {
		projection = p.projection.seal
	}
	if p.originalPolicy != nil {
		original = p.originalPolicy.seal
	}
	values := []any{p.record, p.original.seal, p.localMembers, p.candidates, p.inputs, p.source, p.sourceSHA, p.inventorySHA, p.metadata, projection, original}
	domain := "routervpn-append-execution-policy-seal-v1"
	if len(p.packetCandidates) != 0 {
		domain = "routervpn-append-execution-packet-policy-seal-v1"
		values = append(values, p.packetCandidates)
	}
	value, err := nodeChainAppendExecutionDigest(domain, values)
	if err != nil {
		return ""
	}
	return value
}
func (p *NodeChainCandidateAppendExecutionPolicy) validate() error {
	if p == nil || p.self != p || p.original == nil || p.original != p.capturedOriginal || p.original.validateAppend() != nil || p.seal == "" || p.seal != p.digest() ||
		p.record.LocalSource != p.original.appendSource.source || p.record.Inventory != p.original.candidates.inventory ||
		len(p.localMembers) != len(p.original.proofs) || len(p.candidates) != len(p.original.candidates.responses) || len(p.inputs) != len(p.candidates) {
		return errNodeChainAppendExecution
	}
	if p.projection != nil {
		if p.originalPolicy == nil || p.originalPolicy == p || p.originalPolicy.validate() != nil || p.projection.Validate() != nil || p.projection.original != p.originalPolicy.original || p.projection.preparation != p.original || p.source != p.originalPolicy.source || p.sourceSHA != p.originalPolicy.sourceSHA || !reflect.DeepEqual(p.record, p.originalPolicy.record) || !reflect.DeepEqual(p.localMembers, p.originalPolicy.localMembers) || !reflect.DeepEqual(p.candidates, p.originalPolicy.candidates) || !reflect.DeepEqual(p.packetCandidates, p.originalPolicy.packetCandidates) {
			return errNodeChainAppendExecution
		}
	} else if p.originalPolicy != nil {
		return errNodeChainAppendExecution
	}
	packetNext := nodeChainAppendExecutionPacketMode(p.original.candidates.responseMode)
	if packetNext != p.original.candidates.preparedNativeResponse ||
		packetNext && (p.original.appendSource.record.Schema != 1 || len(p.packetCandidates) != len(p.candidates)) ||
		!packetNext && (p.original.candidates.responseMode != "shadowsocks" || p.packetCandidates != nil) {
		return errNodeChainAppendExecution
	}
	for i, identity := range p.packetCandidates {
		response, candidate := p.original.candidates.responses[i], p.candidates[i]
		if identity.Position != len(p.localMembers) || identity.ProfileID != candidate.ProfileID || identity.NodeID != candidate.NodeID ||
			identity.Mode != candidate.Mode || identity.Mode != p.original.candidates.responseMode ||
			identity.SourceSHA256 != candidate.SourceSHA256 || identity.ClientPublicKey != response.ClientKey || identity.PeerPublicKey != response.ServerKey ||
			!proofID.MatchString(identity.TransportSHA256) || response.PacketOptions == "" {
			return errNodeChainAppendExecution
		}
	}
	for i, member := range p.localMembers {
		proof := p.original.proofs[i]
		if member.Position != i || member.ProfileID != proof.ProfileID || member.NodeID != proof.NodeID || member.SourceSHA256 != proof.SourceSHA256 || member.Mode != proof.Mode || proof.StartLayer != "off" || proof.NodeKind != "" || proof.Kind != "" {
			return errNodeChainAppendExecution
		}
	}
	return nil
}
func (p *NodeChainCandidateAppendExecutionPolicy) buildMetadata() string {
	if p.validate() != nil {
		return ""
	}
	var metadata map[string]any
	if json.Unmarshal([]byte(p.original.Metadata()), &metadata) != nil {
		return ""
	}
	metadata["purpose"] = multihoprelay.NodeChainPrefixPurpose
	metadata["source_sha256"], metadata["execution_source_sha256"] = p.sourceSHA, p.sourceSHA
	metadata["capture_sha256"], metadata["execution_capture_sha256"] = "", ""
	metadata["requested_execution"] = p.record.Execution
	metadata["original_preparation_source_sha256"], metadata["original_preparation_capture_sha256"] = p.original.sourceSHA, p.original.capture
	raw, err := json.Marshal(metadata)
	if err != nil || len(raw) > nodeChainCandidateLegacyMetadataBytes {
		return ""
	}
	return string(raw)
}
func (p *NodeChainCandidateAppendExecutionPolicy) Source() string {
	if p.validate() != nil {
		return ""
	}
	return p.source
}
func (p *NodeChainCandidateAppendExecutionPolicy) SourceSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.sourceSHA
}
func (p *NodeChainCandidateAppendExecutionPolicy) LocalSource() string {
	if p.validate() != nil {
		return ""
	}
	return p.record.LocalSource
}
func (p *NodeChainCandidateAppendExecutionPolicy) OriginalSourceSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.original.appendSource.sourceSHA
}
func (p *NodeChainCandidateAppendExecutionPolicy) Config() string {
	if p.validate() != nil {
		return ""
	}
	return p.original.config
}
func (p *NodeChainCandidateAppendExecutionPolicy) ConfigSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.original.configSHA
}
func (p *NodeChainCandidateAppendExecutionPolicy) Metadata() string {
	if p.validate() != nil {
		return ""
	}
	return p.metadata
}
func (p *NodeChainCandidateAppendExecutionPolicy) AppendSourceMetadata() string {
	if p.validate() != nil {
		return ""
	}
	return p.original.AppendSourceMetadata()
}
func (p *NodeChainCandidateAppendExecutionPolicy) CandidateMode() string {
	if p.validate() != nil {
		return ""
	}
	return p.original.candidates.responseMode
}
func (p *NodeChainCandidateAppendExecutionPolicy) CandidateKind() string {
	if p.validate() != nil {
		return ""
	}
	return "router-vpn"
}
func (p *NodeChainCandidateAppendExecutionPolicy) CandidateMeasurement() string {
	if p.validate() != nil {
		return ""
	}
	return hopmeasure.CandidatePrivateResponseMeasurement
}
func (p *NodeChainCandidateAppendExecutionPolicy) AppendPosition() int {
	if p.validate() != nil {
		return -1
	}
	return len(p.localMembers)
}
func (p *NodeChainCandidateAppendExecutionPolicy) Execution() string {
	if p.validate() != nil {
		return ""
	}
	return p.record.Execution
}
func (p *NodeChainCandidateAppendExecutionPolicy) CandidateInputFitsSource(input string) bool {
	if p.validate() != nil {
		return false
	}
	found := false
	for _, original := range p.inputs {
		if original == input {
			found = true
			break
		}
	}
	return found && p.original.appendSource.CandidateInputFitsSource(input)
}
func (p *NodeChainCandidateAppendExecutionPolicy) matchesDescriptor(s multihoprelay.NodeChainPrefixDescriptor) bool {
	if p.validate() != nil || s.Validate() != nil || !reflect.DeepEqual(s.LocalPrefix, p.localMembers) {
		return false
	}
	packetNext := len(p.packetCandidates) != 0
	if packetNext && s.PacketCandidateMode() != p.original.candidates.responseMode || !packetNext && s.Schema == 3 {
		return false
	}
	for index, candidate := range p.candidates {
		count := 0
		for i, registered := range s.Candidates {
			if candidate == registered {
				if packetNext && (i >= len(s.PacketCandidatePairs) || !p.packetCandidates[index].matches(s.PacketCandidatePairs[i])) {
					return false
				}
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}

type NodeChainCandidateAppendExecutionPreparation struct {
	self                   *NodeChainCandidateAppendExecutionPreparation
	policy, capturedPolicy *NodeChainCandidateAppendExecutionPolicy
	original               *NodeChainCandidatePreparation
}

func NewNodeChainCandidateAppendExecutionPreparation(input string) (*NodeChainCandidateAppendExecutionPreparation, error) {
	policy, err := NewNodeChainCandidateAppendExecutionPolicy(input)
	if err != nil {
		return nil, err
	}
	p := &NodeChainCandidateAppendExecutionPreparation{policy: policy, capturedPolicy: policy, original: policy.original}
	p.self = p
	return p, p.validate()
}
func ParseNodeChainCandidateAppendExecutionPreparationCapture(input string) (*NodeChainCandidateAppendExecutionPreparation, error) {
	p, err := NewNodeChainCandidateAppendExecutionPreparation(input)
	if err != nil || p == nil || p.Source() != input {
		return nil, errors.Join(err, errNodeChainAppendExecution)
	}
	return p, nil
}
func (p *NodeChainCandidateAppendExecutionPreparation) validate() error {
	if p == nil || p.self != p || p.policy == nil || p.policy != p.capturedPolicy || p.policy.validate() != nil || p.original != p.policy.original {
		return errNodeChainAppendExecution
	}
	return nil
}
func (p *NodeChainCandidateAppendExecutionPreparation) OriginalPreparation() *NodeChainCandidatePreparation {
	if p.validate() != nil {
		return nil
	}
	return p.original
}
func (p *NodeChainCandidateAppendExecutionPreparation) Source() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.Source()
}
func (p *NodeChainCandidateAppendExecutionPreparation) SourceSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.SourceSHA256()
}
func (p *NodeChainCandidateAppendExecutionPreparation) LocalSource() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.LocalSource()
}
func (p *NodeChainCandidateAppendExecutionPreparation) OriginalSourceSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.OriginalSourceSHA256()
}
func (p *NodeChainCandidateAppendExecutionPreparation) Config() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.Config()
}
func (p *NodeChainCandidateAppendExecutionPreparation) ConfigSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.ConfigSHA256()
}
func (p *NodeChainCandidateAppendExecutionPreparation) Metadata() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.Metadata()
}
func (p *NodeChainCandidateAppendExecutionPreparation) MetadataPage(offset int32) string {
	if offset != 0 {
		return ""
	}
	return p.Metadata()
}
func (p *NodeChainCandidateAppendExecutionPreparation) AppendSourceMetadata() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.AppendSourceMetadata()
}
func (p *NodeChainCandidateAppendExecutionPreparation) CandidateMode() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.CandidateMode()
}
func (p *NodeChainCandidateAppendExecutionPreparation) CandidateKind() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.CandidateKind()
}
func (p *NodeChainCandidateAppendExecutionPreparation) CandidateMeasurement() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.CandidateMeasurement()
}
func (p *NodeChainCandidateAppendExecutionPreparation) AppendPosition() int {
	if p.validate() != nil {
		return -1
	}
	return p.policy.AppendPosition()
}
func (p *NodeChainCandidateAppendExecutionPreparation) Execution() string {
	if p.validate() != nil {
		return ""
	}
	return p.policy.Execution()
}

func (p *NodeChainCandidateAppendExecutionPreparation) CandidateInputFitsSource(input string) bool {
	if p.validate() != nil {
		return false
	}
	return p.policy.CandidateInputFitsSource(input)
}
