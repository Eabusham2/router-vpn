package mobiletor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const DesktopProtectionTransferRecordLimit = 2048

// DesktopProtectionTransferRecord binds a private native launch to one exact
// retained predecessor or explicit initial absence. These are constraints,
// not firewall authority: the native constructor must independently verify
// the same BFE state before its atomic replacement.
type DesktopProtectionTransferRecord struct {
	Schema       int                             `json:"schema"`
	Kind         string                          `json:"kind"`
	SessionID    string                          `json:"session_id"`
	SourceSHA256 string                          `json:"source_sha256"`
	ConfigSHA256 string                          `json:"config_sha256"`
	Policy       string                          `json:"policy"`
	Predecessor  *DesktopWindowsProtectionTarget `json:"predecessor"`
}

func (r DesktopProtectionTransferRecord) Validate() error {
	if r.Schema != 1 || r.Kind != "routervpn-windows-protection-transfer-v1" || !desktopSocketHex(r.SessionID, 32) ||
		!desktopSocketHex(r.SourceSHA256, 64) || !desktopSocketHex(r.ConfigSHA256, 64) || r.Policy != "on-connect" && r.Policy != "always" {
		return errors.New("Windows protection transfer lost its captured native launch")
	}
	if r.Predecessor != nil && (r.Predecessor.Validate() != nil || r.Predecessor.Capture.SessionID == r.SessionID) {
		return errors.New("Windows protection transfer cannot reuse or substitute its predecessor")
	}
	return nil
}

func CanonicalDesktopProtectionTransferRecord(record DesktopProtectionTransferRecord) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > DesktopProtectionTransferRecordLimit {
		return nil, errors.New("Windows protection transfer exceeds its private record bound")
	}
	return raw, nil
}

func ParseDesktopProtectionTransferRecord(raw []byte) (DesktopProtectionTransferRecord, error) {
	var record DesktopProtectionTransferRecord
	if len(raw) == 0 || len(raw) > DesktopProtectionTransferRecordLimit || json.Unmarshal(raw, &record) != nil {
		return DesktopProtectionTransferRecord{}, errors.New("Windows protection transfer is not a bounded private record")
	}
	canonical, err := CanonicalDesktopProtectionTransferRecord(record)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DesktopProtectionTransferRecord{}, errors.New("Windows protection transfer is not canonical and complete")
	}
	return record, nil
}

func DesktopProtectionTransferRecordSHA256(record DesktopProtectionTransferRecord) (string, error) {
	raw, err := CanonicalDesktopProtectionTransferRecord(record)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// DesktopProtectionRetirementRecord reports only a joined command's exact
// retained successor or unchanged expected predecessor/absence. The parent
// must still join that captured process and independently read the BFE state.
// A private-file receipt cannot itself authorize deletion or replacement.
type DesktopProtectionRetirementRecord struct {
	Schema         int                             `json:"schema"`
	Kind           string                          `json:"kind"`
	TransferSHA256 string                          `json:"transfer_sha256"`
	Target         *DesktopWindowsProtectionTarget `json:"target"`
}

func (r DesktopProtectionRetirementRecord) Validate(expected DesktopProtectionTransferRecord) error {
	digest, err := DesktopProtectionTransferRecordSHA256(expected)
	if err != nil || r.Schema != 1 || r.Kind != "routervpn-windows-protection-retired-v1" || r.TransferSHA256 != digest {
		return errors.New("Windows protection retirement belongs to another captured launch")
	}
	if r.Target == nil {
		if expected.Predecessor != nil {
			return errors.New("Windows protection retirement lost its captured deny baseline")
		}
		return nil
	}
	if r.Target.Validate() != nil {
		return errors.New("Windows protection retirement has an invalid native target")
	}
	if expected.Predecessor != nil && *r.Target == *expected.Predecessor {
		return nil
	}
	if r.Target.Capture.SessionID != expected.SessionID || r.Target.Capture.SourceSHA256 != expected.SourceSHA256 || r.Target.Policy != expected.Policy {
		return errors.New("Windows protection retirement substituted a native owner")
	}
	return nil
}

func CanonicalDesktopProtectionRetirementRecord(record DesktopProtectionRetirementRecord, expected DesktopProtectionTransferRecord) ([]byte, error) {
	if err := record.Validate(expected); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > DesktopProtectionTransferRecordLimit {
		return nil, errors.New("Windows protection retirement exceeds its private record bound")
	}
	return raw, nil
}

func ParseDesktopProtectionRetirementRecord(raw []byte, expected DesktopProtectionTransferRecord) (DesktopProtectionRetirementRecord, error) {
	var record DesktopProtectionRetirementRecord
	if len(raw) == 0 || len(raw) > DesktopProtectionTransferRecordLimit || json.Unmarshal(raw, &record) != nil {
		return DesktopProtectionRetirementRecord{}, errors.New("Windows protection retirement is not a bounded private record")
	}
	canonical, err := CanonicalDesktopProtectionRetirementRecord(record, expected)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DesktopProtectionRetirementRecord{}, errors.New("Windows protection retirement is not canonical and complete")
	}
	return record, nil
}
