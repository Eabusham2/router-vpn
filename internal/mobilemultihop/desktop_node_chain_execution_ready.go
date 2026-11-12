package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
)

const DesktopNodeChainExecutionReadyRecordLimit = 16384

// This private observation belongs to a retained preparation, its authenticated
// in-place projection, and one selected native epoch. It grants no Box, TUN,
// process or lease authority. The host must independently retain that owner and
// match the reader/interface/MTU against its fresh native readback.
type DesktopNodeChainExecutionReadyRecord struct {
	Schema                  int                        `json:"schema"`
	Kind                    string                     `json:"kind"`
	SourceSHA256            string                     `json:"source_sha256"`
	PreparationSourceSHA256 string                     `json:"preparation_source_sha256"`
	PreparationConfigSHA256 string                     `json:"preparation_config_sha256"`
	TransferSHA256          string                     `json:"transfer_sha256"`
	DNSConfigSHA256         string                     `json:"dns_config_sha256"`
	Identity                NodeChainIdentity          `json:"identity"`
	SelectionEpoch          uint64                     `json:"selection_epoch"`
	Generation              uint64                     `json:"proof_generation"`
	Reader                  uint64                     `json:"reader"`
	InterfaceName           string                     `json:"interface_name"`
	InterfaceIndex          uint32                     `json:"interface_index"`
	MTU                     int                        `json:"mtu"`
	ObservedAt              int64                      `json:"observed_at"`
	Progress                NodeChainExecutionProgress `json:"progress"`
}

func (r DesktopNodeChainExecutionReadyRecord) Validate(p *NodeChainExecutionProjection, transfer string) error {
	bad := errors.New("ordered execution heartbeat differs from its original selected native owner")
	if p == nil || p.validateCapture() != nil || p.preparation.desktop == nil || !proofID.MatchString(transfer) {
		return bad
	}
	physical, err := p.DesktopPhysicalPolicy()
	if err != nil {
		return bad
	}
	_, meta, capture, err := physical.PhysicalReadValidated()
	if err != nil {
		return bad
	}
	plan, err := p.MTUPlan()
	if err != nil {
		return bad
	}
	progress := r.Progress
	if progress.Execution != "server" && (progress.Execution != "local" || p.Execution() != "auto") {
		return bad
	}
	proofs, err := p.ProofInventory(progress.Execution)
	dns, dnsErr := p.DNSCapture(progress.Execution)
	if err != nil || dnsErr != nil || len(proofs) < 2 || len(progress.Prefixes) != len(proofs) {
		return bad
	}
	if r.Schema != 1 || r.Kind != "routervpn-node-chain-execution-ready-v1" ||
		r.SourceSHA256 != meta.SourceSHA256 || r.PreparationSourceSHA256 != p.preparation.SourceSHA256() ||
		r.PreparationConfigSHA256 != p.preparation.ConfigSHA256() || r.TransferSHA256 != transfer ||
		r.DNSConfigSHA256 != capture.SelectedDNS.ConfigSHA256 ||
		!nodeChainIdentityText(r.Identity.EngineID) || !nodeChainIdentityText(r.Identity.NetworkID) ||
		r.Identity.SessionID != meta.SessionID || r.Identity.SourceSHA256 != p.SourceSHA256() || r.Identity.ConfigSHA256 != p.ConfigSHA256() ||
		r.Generation == 0 || r.SelectionEpoch == 0 || r.Reader == 0 || !desktopNodeChainReadyInterface(meta.TargetOS, r.InterfaceName) ||
		r.InterfaceIndex == 0 || r.MTU < 1280 || r.MTU > plan.Ceiling || r.ObservedAt <= 0 ||
		progress.Stage != "selected" || !progress.Complete || !progress.Ready || !progress.DNSProven || !progress.PublicProven || progress.Failure != "" ||
		dns.SelectedTag != proofs[len(proofs)-1].Tag {
		return bad
	}
	finite := func(v float64) bool { return v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }
	for i, row := range progress.Prefixes {
		if row.Position != proofs[i].Position || row.ProfileID != proofs[i].ProfileID || !row.Proven || !finite(row.ResponseMS) ||
			row.Kind != "" && row.Kind != "private-node" || row.Label != "" {
			return bad
		}
	}
	result := progress.Comparison
	if !nodeChainExecutionTarget(result.Target) || result.Winner == nil || result.Final == nil || !result.Winner.Valid() ||
		string(result.Winner.Execution) != progress.Execution || result.Winner.EntryID != proofs[0].ProfileID ||
		result.Winner.ExitID != proofs[len(proofs)-1].ProfileID || result.Winner.Transport != "ordered-node-chain" ||
		result.Final.Candidate != *result.Winner || !result.Final.Eligible || result.Final.Failure != "" ||
		!finite(result.Final.LastNodeMS) || !finite(result.Final.ExternalMS) || result.Final.ScoreMS == nil ||
		!finite(*result.Final.ScoreMS) || math.Abs(*result.Final.ScoreMS-(result.Final.LastNodeMS/2+result.Final.ExternalMS/2)) > 0.000001 || len(result.Measurements) > 2 {
		return bad
	}
	seen := map[string]bool{}
	for _, measured := range result.Measurements {
		choice := measured.Candidate
		execution := string(choice.Execution)
		if !choice.Valid() || seen[execution] || choice.Transport != "ordered-node-chain" ||
			choice.EntryID != proofs[0].ProfileID || choice.ExitID != proofs[len(proofs)-1].ProfileID ||
			math.IsNaN(measured.LastNodeMS) || math.IsInf(measured.LastNodeMS, 0) || measured.LastNodeMS < 0 ||
			math.IsNaN(measured.ExternalMS) || math.IsInf(measured.ExternalMS, 0) || measured.ExternalMS < 0 || len(measured.Failure) > 4096 {
			return bad
		}
		seen[execution] = true
		if measured.Eligible {
			if measured.Failure != "" || !finite(measured.LastNodeMS) || !finite(measured.ExternalMS) || measured.ScoreMS == nil ||
				!finite(*measured.ScoreMS) || math.Abs(*measured.ScoreMS-(measured.LastNodeMS/2+measured.ExternalMS/2)) > 0.000001 {
				return bad
			}
		} else if measured.ScoreMS != nil || measured.Failure == "" {
			return bad
		}
	}
	return nil
}

func CanonicalDesktopNodeChainExecutionReadyRecord(r DesktopNodeChainExecutionReadyRecord, p *NodeChainExecutionProjection, transfer string) ([]byte, error) {
	if err := r.Validate(p, transfer); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > DesktopNodeChainExecutionReadyRecordLimit {
		return nil, errors.New("ordered execution heartbeat exceeds its private record bound")
	}
	return raw, nil
}

func ParseDesktopNodeChainExecutionReadyRecord(raw []byte, p *NodeChainExecutionProjection, transfer string) (DesktopNodeChainExecutionReadyRecord, error) {
	var r DesktopNodeChainExecutionReadyRecord
	if len(raw) == 0 || len(raw) > DesktopNodeChainExecutionReadyRecordLimit || json.Unmarshal(raw, &r) != nil {
		return r, errors.New("ordered execution heartbeat is not a bounded private record")
	}
	canonical, err := CanonicalDesktopNodeChainExecutionReadyRecord(r, p, transfer)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DesktopNodeChainExecutionReadyRecord{}, errors.New("ordered execution heartbeat is not canonical and complete")
	}
	return r, nil
}
