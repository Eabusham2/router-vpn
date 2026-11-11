package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

const DesktopNodeChainReadyRecordLimit = 8192

// DesktopNodeChainReadyRecord is a fresh observation of one running proof
// controller and the existing native MTU reader. It grants no process, socket,
// protection or TUN ownership. The parent must also retain its original process
// and physical owner, and match Reader/Interface/MTU to that owner's fresh MTU
// receipt before accepting a heartbeat or a completed MTU transaction.
type DesktopNodeChainReadyRecord struct {
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

func (r DesktopNodeChainReadyRecord) Validate(policy *DesktopNodeChainPolicy, transfer string) error {
	bad := errors.New("ordered chain heartbeat differs from its captured native owner")
	if policy == nil || !proofID.MatchString(transfer) {
		return bad
	}
	_, meta, capture, err := policy.ReadValidated()
	if err != nil {
		return bad
	}
	chain := policy.NodeChain()
	if chain == nil {
		return bad
	}
	plan, err := chain.MTUPlan()
	if err != nil {
		return bad
	}
	if r.Schema != 1 || r.Kind != "routervpn-node-chain-ready-v1" ||
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

// This is the native interface shape for the already validated original target.
// Darwin's allocated name is still only an observation: the host must match the
// retained control, live kernel interface and original reader/MTU generation.
// The native PF guardian uses the same utun-plus-ASCII-digits shape before its
// independent descriptor and kernel checks.
func desktopNodeChainReadyInterface(target, name string) bool {
	switch target {
	case "linux", "windows":
		return name == "router-vpn"
	case "darwin":
		unit, found := strings.CutPrefix(name, "utun")
		if !found || unit == "" {
			return false
		}
		for _, digit := range unit {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func CanonicalDesktopNodeChainReadyRecord(record DesktopNodeChainReadyRecord, policy *DesktopNodeChainPolicy, transfer string) ([]byte, error) {
	if err := record.Validate(policy, transfer); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > DesktopNodeChainReadyRecordLimit {
		return nil, errors.New("ordered chain heartbeat exceeds its bounded private record")
	}
	return raw, nil
}

func ParseDesktopNodeChainReadyRecord(raw []byte, policy *DesktopNodeChainPolicy, transfer string) (DesktopNodeChainReadyRecord, error) {
	var record DesktopNodeChainReadyRecord
	if len(raw) == 0 || len(raw) > DesktopNodeChainReadyRecordLimit || json.Unmarshal(raw, &record) != nil {
		return DesktopNodeChainReadyRecord{}, errors.New("ordered chain heartbeat is not a bounded private record")
	}
	canonical, err := CanonicalDesktopNodeChainReadyRecord(record, policy, transfer)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DesktopNodeChainReadyRecord{}, errors.New("ordered chain heartbeat is not canonical and complete")
	}
	return record, nil
}
