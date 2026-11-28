package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"errors"

	"router-vpn/internal/multihoprelay"
)

const DesktopNodeCandidateAppendExecutionReadyLimit = 4096

// The authenticated execution discovery is observed beside the same original
// Local native reader. It grants no application ingress, DNS, selected lane or
// complete-chain readiness. Hosts retain the original process and fresh Local
// receipt independently of this bounded, atomically refreshed sidecar.
type DesktopNodeCandidateAppendExecutionReadyRecord struct {
	NodeChainCandidateAppendExecutionDiscovery
	Kind           string `json:"kind"`
	TransferSHA256 string `json:"transfer_sha256"`
	Reader         uint64 `json:"reader"`
}

func (r DesktopNodeCandidateAppendExecutionReadyRecord) Validate(policy *DesktopNodeCandidateAppendExecutionPolicy, transfer string, local DesktopNodeCandidatePreparationReadyRecord) error {
	bad := errors.New("append execution discovery differs from its original closed native owner")
	if policy == nil || policy.Validate() != nil || !proofID.MatchString(transfer) || local.Validate(policy.LocalPolicy(), transfer) != nil {
		return bad
	}
	p := policy.ExecutionPreparation()
	if p == nil || r.Schema != 1 || r.Purpose != multihoprelay.NodeChainPrefixPurpose || r.Kind != "routervpn-node-candidate-append-execution-ready-v1" ||
		r.ExecutionSourceSHA256 != p.SourceSHA256() || !proofID.MatchString(r.ExecutionCaptureSHA256) ||
		r.OriginalSourceSHA256 != p.OriginalSourceSHA256() || r.OriginalPreparationSourceSHA256 != p.OriginalPreparation().SourceSHA256() ||
		r.OriginalPreparationCaptureSHA256 != p.OriginalPreparation().CaptureSHA256() || r.ConfigSHA256 != p.ConfigSHA256() ||
		r.RequestedExecution != p.Execution() || !proofID.MatchString(r.DescriptorSHA256) || !proofID.MatchString(r.RegistrySHA256) ||
		r.Identity != local.Identity || r.TransferSHA256 != transfer || r.Reader == 0 || r.Reader != local.Reader ||
		r.OriginalPreparationSourceSHA256 != local.SourceSHA256 || r.OriginalPreparationCaptureSHA256 != local.CaptureSHA256 ||
		r.ObservedAt <= 0 || !r.Prepared || r.ApplicationOpen || r.DNSOpen {
		return bad
	}
	return nil
}

func CanonicalDesktopNodeCandidateAppendExecutionReadyRecord(record DesktopNodeCandidateAppendExecutionReadyRecord, policy *DesktopNodeCandidateAppendExecutionPolicy, transfer string, local DesktopNodeCandidatePreparationReadyRecord) ([]byte, error) {
	if err := record.Validate(policy, transfer, local); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > DesktopNodeCandidateAppendExecutionReadyLimit {
		return nil, errors.New("append execution discovery exceeds its bounded private record")
	}
	return raw, nil
}

func ParseDesktopNodeCandidateAppendExecutionReadyRecord(raw []byte, policy *DesktopNodeCandidateAppendExecutionPolicy, transfer string, local DesktopNodeCandidatePreparationReadyRecord) (DesktopNodeCandidateAppendExecutionReadyRecord, error) {
	var record DesktopNodeCandidateAppendExecutionReadyRecord
	if len(raw) == 0 || len(raw) > DesktopNodeCandidateAppendExecutionReadyLimit || json.Unmarshal(raw, &record) != nil {
		return DesktopNodeCandidateAppendExecutionReadyRecord{}, errors.New("append execution discovery is not a bounded private record")
	}
	canonical, err := CanonicalDesktopNodeCandidateAppendExecutionReadyRecord(record, policy, transfer, local)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DesktopNodeCandidateAppendExecutionReadyRecord{}, errors.New("append execution discovery is not canonical and complete")
	}
	return record, nil
}
