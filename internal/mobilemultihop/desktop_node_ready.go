package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
)

const DesktopNodeReadyRecordLimit = 2048

// DesktopNodeReadyRecord reports a fresh query through the running native DNS
// router after the exact physical/TUN owner was activated. It is a constrained
// private receipt, not permission to contact a node or change kernel policy.
// The host must still own/join the native process, check its live handoff and
// selected-node proof, and independently verify protection at retirement.
type DesktopNodeReadyRecord struct {
	Schema          int     `json:"schema"`
	Kind            string  `json:"kind"`
	SessionID       string  `json:"session_id"`
	SourceSHA256    string  `json:"source_sha256"`
	ConfigSHA256    string  `json:"config_sha256"`
	TransferSHA256  string  `json:"transfer_sha256"`
	DNSConfigSHA256 string  `json:"dns_config_sha256"`
	InterfaceName   string  `json:"interface_name"`
	InterfaceIndex  uint32  `json:"interface_index"`
	MTU             int     `json:"mtu"`
	ProvedAt        int64   `json:"proved_at"`
	DNSMilliseconds float64 `json:"dns_milliseconds"`
}

func (r DesktopNodeReadyRecord) Validate(policy *DesktopNodePolicy, transfer string) error {
	if policy == nil || policy.Validate() != nil || !proofID.MatchString(transfer) {
		return errors.New("native Router readiness lost its captured policy")
	}
	meta := policy.Metadata()
	capture, err := policy.Capture()
	if err != nil {
		return errors.New("native Router readiness lost its original source")
	}
	mtu := capture.ConfiguredMTU
	if meta.RestoredMTU != 0 {
		mtu = meta.RestoredMTU
	}
	if r.Schema != 1 || r.Kind != "routervpn-node-ready-v1" || meta.TargetOS != "windows" ||
		r.SessionID != meta.SessionID || r.SourceSHA256 != meta.SourceSHA256 || r.ConfigSHA256 != meta.ConfigSHA256 ||
		r.TransferSHA256 != transfer || r.DNSConfigSHA256 != capture.SelectedDNS.ConfigSHA256 ||
		r.InterfaceName != "router-vpn" || r.InterfaceIndex == 0 || r.MTU != mtu || r.ProvedAt <= 0 ||
		r.DNSMilliseconds <= 0 || r.DNSMilliseconds > 5000 || math.IsNaN(r.DNSMilliseconds) || math.IsInf(r.DNSMilliseconds, 0) {
		return errors.New("native Router readiness differs from its captured path")
	}
	return nil
}

func CanonicalDesktopNodeReadyRecord(record DesktopNodeReadyRecord, policy *DesktopNodePolicy, transfer string) ([]byte, error) {
	if err := record.Validate(policy, transfer); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > DesktopNodeReadyRecordLimit {
		return nil, errors.New("native Router readiness exceeds its private record bound")
	}
	return raw, nil
}

func ParseDesktopNodeReadyRecord(raw []byte, policy *DesktopNodePolicy, transfer string) (DesktopNodeReadyRecord, error) {
	var record DesktopNodeReadyRecord
	if len(raw) == 0 || len(raw) > DesktopNodeReadyRecordLimit || json.Unmarshal(raw, &record) != nil {
		return DesktopNodeReadyRecord{}, errors.New("native Router readiness is not a bounded private record")
	}
	canonical, err := CanonicalDesktopNodeReadyRecord(record, policy, transfer)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DesktopNodeReadyRecord{}, errors.New("native Router readiness is not canonical and complete")
	}
	return record, nil
}
