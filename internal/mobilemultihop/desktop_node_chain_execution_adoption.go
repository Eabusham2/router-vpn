package mobilemultihop

import (
	"bytes"
	"encoding/json"

	"router-vpn/internal/multihoprelay"
)

const DesktopNodeChainExecutionAdoptionRecordLimit = 64 << 10

// This private receipt transfers the dynamically discovered execution proposal
// back to the original desktop parent. It is evidence, not process, socket,
// lease or TUN authority. Read it only through the retained child's protected
// runtime directory, bracketed by the original native ownership check.
// LocalSource is deliberately not repeated: reconstruction always uses the
// parent's exact captured preparation, including DNS, StartLayers and MTU.
type DesktopNodeChainExecutionAdoptionRecord struct {
	Schema                  int                               `json:"schema"`
	Kind                    string                            `json:"kind"`
	PreparationSourceSHA256 string                            `json:"preparation_source_sha256"`
	PreparationConfigSHA256 string                            `json:"preparation_config_sha256"`
	PhysicalSourceSHA256    string                            `json:"physical_source_sha256"`
	TransferSHA256          string                            `json:"transfer_sha256"`
	Identity                NodeChainIdentity                 `json:"identity"`
	Server                  multihoprelay.NodeChainDescriptor `json:"server"`
	Request                 multihoprelay.NodeChainRequest    `json:"request"`
	FirstPort               int                               `json:"first_port"`
	LastPort                int                               `json:"last_port"`
}

// NewDesktopNodeChainExecutionAdoptionRecord can describe only the actual
// projected graph. A preparation graph or generic mobile graph cannot stand in
// for the native child's selected execution identity.
func NewDesktopNodeChainExecutionAdoptionRecord(p *NodeChainExecutionProjection, identity NodeChainIdentity, transfer string) (DesktopNodeChainExecutionAdoptionRecord, error) {
	var empty DesktopNodeChainExecutionAdoptionRecord
	if p.validateCapture() != nil || p.preparation.desktop == nil || !proofID.MatchString(transfer) {
		return empty, nodeChainExecutionError
	}
	physical, err := p.DesktopPhysicalPolicy()
	if err != nil {
		return empty, err
	}
	_, meta, _, err := physical.PhysicalReadValidated()
	if err != nil || identity.SessionID != meta.SessionID || identity.SourceSHA256 != p.SourceSHA256() ||
		identity.ConfigSHA256 != p.ConfigSHA256() || !nodeChainIdentityText(identity.EngineID) || !nodeChainIdentityText(identity.NetworkID) {
		return empty, nodeChainExecutionError
	}
	r := DesktopNodeChainExecutionAdoptionRecord{Schema: 1, Kind: "routervpn-node-chain-execution-adoption-v1",
		PreparationSourceSHA256: p.preparation.SourceSHA256(), PreparationConfigSHA256: p.preparation.ConfigSHA256(),
		PhysicalSourceSHA256: meta.SourceSHA256, TransferSHA256: transfer, Identity: identity,
		Server: p.policy.source.Server, Request: p.policy.source.Request, FirstPort: p.policy.source.FirstPort, LastPort: p.policy.source.LastPort}
	// Detach the descriptor/request slices from the sealed runtime policy.
	raw, err := json.Marshal(r)
	r = empty
	if err != nil || len(raw) > DesktopNodeChainExecutionAdoptionRecordLimit || json.Unmarshal(raw, &r) != nil {
		return empty, nodeChainExecutionError
	}
	return r, nil
}

// ParseDesktopNodeChainExecutionAdoptionRecord repeats the closed compiler on
// the original preparation pointer. The returned projection retains that exact
// physical policy. It cannot authorize adopting a different native process.
func ParseDesktopNodeChainExecutionAdoptionRecord(raw []byte, preparation *NodeChainExecutionPreparation, transfer string) (*NodeChainExecutionProjection, NodeChainIdentity, error) {
	var r DesktopNodeChainExecutionAdoptionRecord
	bad := func() (*NodeChainExecutionProjection, NodeChainIdentity, error) {
		return nil, NodeChainIdentity{}, nodeChainExecutionError
	}
	if preparation.validateCapture() != nil || preparation.desktop == nil || !proofID.MatchString(transfer) ||
		len(raw) == 0 || len(raw) > DesktopNodeChainExecutionAdoptionRecordLimit || json.Unmarshal(raw, &r) != nil ||
		r.Schema != 1 || r.Kind != "routervpn-node-chain-execution-adoption-v1" || r.TransferSHA256 != transfer ||
		r.PreparationSourceSHA256 != preparation.SourceSHA256() || r.PreparationConfigSHA256 != preparation.ConfigSHA256() {
		return bad()
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return bad()
	}
	source, err := json.Marshal(NodeChainExecutionSource{Schema: 1, Execution: preparation.Execution(), LocalSource: preparation.LocalSource(),
		Server: r.Server, Request: r.Request, FirstPort: r.FirstPort, LastPort: r.LastPort})
	if err != nil {
		return bad()
	}
	policy, err := NewNodeChainExecutionPolicy(string(source))
	clear(source)
	if err != nil {
		return bad()
	}
	projection, err := preparation.BindExecution(policy)
	if err != nil {
		return bad()
	}
	expected, err := NewDesktopNodeChainExecutionAdoptionRecord(projection, r.Identity, transfer)
	if err != nil {
		return bad()
	}
	canonical, err = json.Marshal(expected)
	if err != nil || !bytes.Equal(raw, canonical) {
		return bad()
	}
	return projection, r.Identity, nil
}

// A later heartbeat must come from the same native Box, physical network and
// session as the once-pinned adoption. The parent must also check freshness,
// selected epoch and native MTU readback inside its original process guard.
func ParseDesktopNodeChainExecutionAdoptedReadyRecord(raw []byte, projection *NodeChainExecutionProjection, identity NodeChainIdentity, transfer string) (DesktopNodeChainExecutionReadyRecord, error) {
	record, err := ParseDesktopNodeChainExecutionReadyRecord(raw, projection, transfer)
	if err != nil || record.Identity != identity {
		return DesktopNodeChainExecutionReadyRecord{}, nodeChainExecutionError
	}
	return record, nil
}
