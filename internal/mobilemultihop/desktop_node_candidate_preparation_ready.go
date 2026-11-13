package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
)

const DesktopNodeCandidatePreparationReadyLimit = 8192

// This receipt observes private prefix proof and the original native TUN. It
// cannot represent full-path readiness, a selected-DNS proof or permission to
// open application ingress. A host additionally owns the exact child, physical
// protection and fresh MTU reader before accepting any such observation.
type DesktopNodeCandidatePreparationReadyRecord struct {
	Schema          int                       `json:"schema"`
	Kind            string                    `json:"kind"`
	SourceSHA256    string                    `json:"source_sha256"`
	CaptureSHA256   string                    `json:"capture_sha256"`
	TransferSHA256  string                    `json:"transfer_sha256"`
	Identity        NodeChainIdentity         `json:"identity"`
	Generation      uint64                    `json:"proof_generation"`
	Reader          uint64                    `json:"reader"`
	InterfaceName   string                    `json:"interface_name"`
	InterfaceIndex  uint32                    `json:"interface_index"`
	MTU             int                       `json:"mtu"`
	ObservedAt      int64                     `json:"observed_at"`
	Prepared        bool                      `json:"prepared"`
	ApplicationOpen bool                      `json:"application_open"`
	DNSOpen         bool                      `json:"dns_open"`
	Prefixes        []NodeChainPrefixProgress `json:"prefixes"`
}

func (r DesktopNodeCandidatePreparationReadyRecord) Validate(policy *DesktopNodeCandidatePreparationPolicy, transfer string) error {
	bad := errors.New("candidate prefix heartbeat differs from its original closed native owner")
	if policy == nil || policy.Validate() != nil || !proofID.MatchString(transfer) {
		return bad
	}
	meta := policy.Metadata()
	plan, err := policy.Preparation().MTUPlan()
	if err != nil || r.Schema != 1 || r.Kind != "routervpn-node-candidate-prefix-ready-v1" ||
		r.SourceSHA256 != meta.SourceSHA256 || r.CaptureSHA256 != meta.CaptureSHA256 || r.TransferSHA256 != transfer ||
		!desktopNodeChainReadyInterface(meta.TargetOS, r.InterfaceName) ||
		!nodeChainIdentityText(r.Identity.EngineID) || !nodeChainIdentityText(r.Identity.NetworkID) ||
		r.Identity.SessionID != meta.SessionID || r.Identity.SourceSHA256 != meta.SourceSHA256 || r.Identity.ConfigSHA256 != meta.ConfigSHA256 ||
		r.Generation == 0 || r.Reader == 0 || r.InterfaceIndex == 0 || r.MTU < 1280 || r.MTU > plan.Ceiling || r.ObservedAt <= 0 ||
		!r.Prepared || r.ApplicationOpen || r.DNSOpen || len(r.Prefixes) != meta.PrefixPosition+1 || len(r.Prefixes) != len(meta.Prefixes) {
		return bad
	}
	for i, proof := range r.Prefixes {
		if proof.Position != i || proof.ProfileID != meta.Prefixes[i].ProfileID || !proof.Proven ||
			proof.ResponseMS <= 0 || math.IsNaN(proof.ResponseMS) || math.IsInf(proof.ResponseMS, 0) {
			return bad
		}
	}
	return nil
}

func CanonicalDesktopNodeCandidatePreparationReadyRecord(record DesktopNodeCandidatePreparationReadyRecord, policy *DesktopNodeCandidatePreparationPolicy, transfer string) ([]byte, error) {
	if err := record.Validate(policy, transfer); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > DesktopNodeCandidatePreparationReadyLimit {
		return nil, errors.New("candidate prefix heartbeat exceeds its bounded private record")
	}
	return raw, nil
}

func ParseDesktopNodeCandidatePreparationReadyRecord(raw []byte, policy *DesktopNodeCandidatePreparationPolicy, transfer string) (DesktopNodeCandidatePreparationReadyRecord, error) {
	var record DesktopNodeCandidatePreparationReadyRecord
	if len(raw) == 0 || len(raw) > DesktopNodeCandidatePreparationReadyLimit || json.Unmarshal(raw, &record) != nil {
		return DesktopNodeCandidatePreparationReadyRecord{}, errors.New("candidate prefix heartbeat is not a bounded private record")
	}
	canonical, err := CanonicalDesktopNodeCandidatePreparationReadyRecord(record, policy, transfer)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DesktopNodeCandidatePreparationReadyRecord{}, errors.New("candidate prefix heartbeat is not canonical and complete")
	}
	return record, nil
}
