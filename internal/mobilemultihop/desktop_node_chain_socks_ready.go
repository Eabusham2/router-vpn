package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"errors"
)

const DesktopNodeChainSOCKSReadyRecordLimit = 8192

// DesktopNodeChainSOCKSReadyRecord is a fresh observation of one running typed proof
// controller and the existing native MTU reader. It grants no process, socket,
// protection or TUN ownership. The parent must also retain its original process
// and physical owner, and match Reader/Interface/MTU to that owner's fresh MTU
// receipt before accepting a heartbeat or a completed MTU transaction.
type DesktopNodeChainSOCKSReadyRecord struct {
	Schema          int               `json:"schema"`
	Kind            string            `json:"kind"`
	SourceSHA256    string            `json:"source_sha256"`
	TransferSHA256  string            `json:"transfer_sha256"`
	DNSConfigSHA256 string            `json:"dns_config_sha256"`
	Identity        NodeChainIdentity `json:"identity"`
	Generation      uint64            `json:"proof_generation"`
	Reader          uint64            `json:"reader"`
	InterfaceName   string            `json:"interface_name"`
	InterfaceIndex  uint32            `json:"interface_index"`
	MTU             int               `json:"mtu"`
	ObservedAt      int64             `json:"observed_at"`
}

func (r DesktopNodeChainSOCKSReadyRecord) Validate(policy *DesktopNodeChainSOCKSPolicy, transfer string) error {
	bad := errors.New("ordered SOCKS heartbeat differs from its captured native owner")
	if policy == nil || !proofID.MatchString(transfer) {
		return bad
	}
	_, meta, capture, err := policy.ReadValidated()
	if err != nil {
		return bad
	}
	native, err := policy.NativeSource()
	if err != nil {
		return bad
	}
	_, source, err := native.ReadValidated()
	if err != nil {
		return bad
	}
	plan := source.MTU
	if r.Schema != 1 || r.Kind != "routervpn-node-chain-socks-ready-v1" ||
		!desktopNodeChainReadyInterface(meta.TargetOS, r.InterfaceName) ||
		r.SourceSHA256 != meta.SourceSHA256 || r.TransferSHA256 != transfer ||
		r.DNSConfigSHA256 != capture.SelectedDNS.ConfigSHA256 ||
		!nodeChainIdentityText(r.Identity.EngineID) || !nodeChainIdentityText(r.Identity.NetworkID) ||
		r.Identity.SessionID != meta.SessionID || r.Identity.SourceSHA256 != meta.OriginalSourceSHA256 ||
		r.Identity.ConfigSHA256 != meta.ConfigSHA256 || r.Generation == 0 || r.Reader == 0 ||
		r.InterfaceIndex == 0 || r.MTU < 1280 || r.MTU > plan.Ceiling ||
		r.ObservedAt <= 0 {
		return bad
	}
	return nil
}

func CanonicalDesktopNodeChainSOCKSReadyRecord(record DesktopNodeChainSOCKSReadyRecord, policy *DesktopNodeChainSOCKSPolicy, transfer string) ([]byte, error) {
	if err := record.Validate(policy, transfer); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > DesktopNodeChainSOCKSReadyRecordLimit {
		return nil, errors.New("ordered SOCKS heartbeat exceeds its bounded private record")
	}
	return raw, nil
}

func ParseDesktopNodeChainSOCKSReadyRecord(raw []byte, policy *DesktopNodeChainSOCKSPolicy, transfer string) (DesktopNodeChainSOCKSReadyRecord, error) {
	var record DesktopNodeChainSOCKSReadyRecord
	if len(raw) == 0 || len(raw) > DesktopNodeChainSOCKSReadyRecordLimit || json.Unmarshal(raw, &record) != nil {
		return DesktopNodeChainSOCKSReadyRecord{}, errors.New("ordered SOCKS heartbeat is not a bounded private record")
	}
	canonical, err := CanonicalDesktopNodeChainSOCKSReadyRecord(record, policy, transfer)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DesktopNodeChainSOCKSReadyRecord{}, errors.New("ordered SOCKS heartbeat is not canonical and complete")
	}
	return record, nil
}
