package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"errors"
)

const DesktopNodeChainCONNECTReadyRecordLimit = 8192

// DesktopNodeChainCONNECTReadyRecord is a fresh observation of one running typed proof
// controller and the existing native MTU reader. It grants no process, socket,
// protection or TUN ownership. The parent must also retain its original process
// and physical owner, and match Reader/Interface/MTU to that owner's fresh MTU
// receipt before accepting a heartbeat or a completed MTU transaction.
type DesktopNodeChainCONNECTReadyRecord struct {
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

func (r DesktopNodeChainCONNECTReadyRecord) Validate(policy *DesktopNodeChainCONNECTPolicy, transfer string) error {
	bad := errors.New("ordered CONNECT heartbeat differs from its captured native owner")
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
	if r.Schema != 1 || r.Kind != "routervpn-node-chain-connect-ready-v1" ||
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

func CanonicalDesktopNodeChainCONNECTReadyRecord(record DesktopNodeChainCONNECTReadyRecord, policy *DesktopNodeChainCONNECTPolicy, transfer string) ([]byte, error) {
	if err := record.Validate(policy, transfer); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > DesktopNodeChainCONNECTReadyRecordLimit {
		return nil, errors.New("ordered CONNECT heartbeat exceeds its bounded private record")
	}
	return raw, nil
}

func ParseDesktopNodeChainCONNECTReadyRecord(raw []byte, policy *DesktopNodeChainCONNECTPolicy, transfer string) (DesktopNodeChainCONNECTReadyRecord, error) {
	var record DesktopNodeChainCONNECTReadyRecord
	if len(raw) == 0 || len(raw) > DesktopNodeChainCONNECTReadyRecordLimit || json.Unmarshal(raw, &record) != nil {
		return DesktopNodeChainCONNECTReadyRecord{}, errors.New("ordered CONNECT heartbeat is not a bounded private record")
	}
	canonical, err := CanonicalDesktopNodeChainCONNECTReadyRecord(record, policy, transfer)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DesktopNodeChainCONNECTReadyRecord{}, errors.New("ordered CONNECT heartbeat is not canonical and complete")
	}
	return record, nil
}
