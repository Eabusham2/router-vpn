package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"router-vpn/internal/multihoprelay"
)

// This owner carries the execution purpose beside the unchanged closed Local
// physical projection. A projected preparation cannot be supplied by a caller.
type DesktopNodeCandidateAppendExecutionPolicy struct {
	self                       *DesktopNodeCandidateAppendExecutionPolicy
	original, capturedOriginal *NodeChainCandidateAppendExecutionPreparation
	local, capturedLocal       *DesktopNodeCandidatePreparationPolicy
	execution                  *NodeChainCandidateAppendExecutionPreparation
	source, seal               string
}
type desktopNodeCandidateAppendExecutionSource struct {
	Kind                  string `json:"kind"`
	Schema                int    `json:"schema"`
	Preparation           string `json:"preparation"`
	LocalPolicy           string `json:"local_policy"`
	SessionID             string `json:"session_id"`
	TargetOS              string `json:"target_os"`
	RestoredMTU           int    `json:"restored_mtu,omitempty"`
	SourceSHA256          string `json:"source_sha256"`
	ConfigSHA256          string `json:"config_sha256"`
	CaptureSHA256         string `json:"capture_sha256"`
	ExecutionSourceSHA256 string `json:"execution_source_sha256"`
}

func NewDesktopNodeCandidateAppendExecutionPolicy(original *NodeChainCandidateAppendExecutionPreparation, sessionID, targetOS string, restoredMTU int) (*DesktopNodeCandidateAppendExecutionPolicy, error) {
	if original == nil || original.validate() != nil || original.policy.projection != nil {
		return nil, errNodeChainAppendExecution
	}
	local, err := NewDesktopNodeCandidatePreparationPolicy(original.original, sessionID, targetOS, restoredMTU)
	if err != nil {
		return nil, err
	}
	old := original.policy
	policy := &NodeChainCandidateAppendExecutionPolicy{record: old.record, original: local.preparation, capturedOriginal: local.preparation,
		localMembers: append([]multihoprelay.NodeChainPrefixMember(nil), old.localMembers...), candidates: append([]multihoprelay.NodeChainPrefixCandidate(nil), old.candidates...), inputs: append([]string(nil), old.inputs...),
		source: old.source, sourceSHA: old.sourceSHA, inventorySHA: old.inventorySHA, projection: local, originalPolicy: old}
	policy.self = policy
	policy.seal = policy.digest()
	policy.metadata = policy.buildMetadata()
	policy.seal = policy.digest()
	if policy.metadata == "" || policy.validate() != nil {
		return nil, errNodeChainAppendExecution
	}
	execution := &NodeChainCandidateAppendExecutionPreparation{policy: policy, capturedPolicy: policy, original: local.preparation}
	execution.self = execution
	p := &DesktopNodeCandidateAppendExecutionPolicy{original: original, capturedOriginal: original, local: local, capturedLocal: local, execution: execution}
	p.self = p
	m := local.Metadata()
	raw, err := json.Marshal(desktopNodeCandidateAppendExecutionSource{Kind: "routervpn-desktop-node-candidate-append-execution", Schema: 1, Preparation: original.Source(), LocalPolicy: local.Source(), SessionID: sessionID, TargetOS: targetOS, RestoredMTU: restoredMTU, SourceSHA256: m.SourceSHA256, ConfigSHA256: m.ConfigSHA256, CaptureSHA256: m.CaptureSHA256, ExecutionSourceSHA256: original.SourceSHA256()})
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, errNodeChainAppendExecution
	}
	p.source = string(raw)
	p.seal = p.digest()
	return p, p.Validate()
}
func (p *DesktopNodeCandidateAppendExecutionPolicy) digest() string {
	if p == nil || p.original == nil || p.local == nil || p.execution == nil || p.execution.policy == nil {
		return ""
	}
	return desktopExternalObjectDigest([]any{"routervpn-desktop-append-execution-policy-v1", p.original.policy.seal, p.local.seal, p.execution.policy.seal, p.source})
}
func (p *DesktopNodeCandidateAppendExecutionPolicy) Validate() error {
	if p == nil || p.self != p || p.original == nil || p.original != p.capturedOriginal || p.original.validate() != nil || p.local == nil || p.local != p.capturedLocal || p.local.Validate() != nil || p.execution == nil || p.execution.validate() != nil ||
		p.local.original != p.original.original || p.execution.original != p.local.preparation || p.execution.policy.originalPolicy != p.original.policy || p.execution.policy.projection != p.local ||
		p.source == "" || p.seal == "" || p.seal != p.digest() || !reflect.DeepEqual(p.original.policy.localMembers, p.execution.policy.localMembers) {
		return errNodeChainAppendExecution
	}
	return nil
}
func (*DesktopNodeCandidateAppendExecutionPolicy) desktopPhysicalPolicy() {}
func (p *DesktopNodeCandidateAppendExecutionPolicy) Source() string {
	if p.Validate() != nil {
		return ""
	}
	return p.source
}
func (p *DesktopNodeCandidateAppendExecutionPolicy) Config() string {
	if p.Validate() != nil {
		return ""
	}
	return p.local.Config()
}
func (p *DesktopNodeCandidateAppendExecutionPolicy) Metadata() DesktopNodeCandidatePreparationMetadata {
	if p.Validate() != nil {
		return DesktopNodeCandidatePreparationMetadata{}
	}
	return p.local.Metadata()
}
func (p *DesktopNodeCandidateAppendExecutionPolicy) LocalPolicy() *DesktopNodeCandidatePreparationPolicy {
	if p.Validate() != nil {
		return nil
	}
	return p.local
}
func (p *DesktopNodeCandidateAppendExecutionPolicy) Preparation() *NodeChainCandidatePreparation {
	if p.Validate() != nil {
		return nil
	}
	return p.local.preparation
}
func (p *DesktopNodeCandidateAppendExecutionPolicy) ExecutionPreparation() *NodeChainCandidateAppendExecutionPreparation {
	if p.Validate() != nil {
		return nil
	}
	return p.execution
}
func (p *DesktopNodeCandidateAppendExecutionPolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	if p.Validate() != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, errNodeChainAppendExecution
	}
	return p.local.PhysicalReadValidated()
}
func ParseDesktopNodeCandidateAppendExecutionPolicy(input string) (*DesktopNodeCandidateAppendExecutionPolicy, error) {
	var record desktopNodeCandidateAppendExecutionSource
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil || record.Kind != "routervpn-desktop-node-candidate-append-execution" || record.Schema != 1 {
		return nil, errNodeChainAppendExecution
	}
	original, err := ParseNodeChainCandidateAppendExecutionPreparationCapture(record.Preparation)
	if err != nil {
		return nil, err
	}
	p, err := NewDesktopNodeCandidateAppendExecutionPolicy(original, record.SessionID, record.TargetOS, record.RestoredMTU)
	if err != nil || p == nil || p.Source() != input {
		return nil, errNodeChainAppendExecution
	}
	return p, nil
}
