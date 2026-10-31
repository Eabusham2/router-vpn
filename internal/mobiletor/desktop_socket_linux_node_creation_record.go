package mobiletor

import "errors"

// DesktopLinuxNodeCreationRecord compares the original parent's exclusive
// baseline creation with the later guardian's prepared inventory. It contains
// no process authority and cannot reconstruct the original creator or adopt a
// same-name table after an interrupted or uncertain operation.
type DesktopLinuxNodeCreationRecord struct {
	Capture        DesktopSocketCapture `json:"capture"`
	HomeLAN        bool                 `json:"home_lan"`
	TableName      string               `json:"table_name"`
	TableHandle    uint64               `json:"table_handle"`
	ChainHandle    uint64               `json:"chain_handle"`
	BaselineSHA256 string               `json:"baseline_sha256"`
}

func (r DesktopLinuxNodeCreationRecord) Validate() error {
	const maximumExactJSONInteger = uint64(1<<53 - 1)
	if !r.Capture.valid() || r.TableName != desktopLinuxNodeTable(r.Capture) ||
		r.TableHandle == 0 || r.TableHandle > maximumExactJSONInteger || r.ChainHandle == 0 || r.ChainHandle > maximumExactJSONInteger ||
		!desktopSocketHex(r.BaselineSHA256, 64) {
		return errors.New("Linux Node creation record lost its exact captured session baseline")
	}
	return nil
}

// MatchesPrepared checks only the immutable baseline portion. The guardian's
// UID, process birth, permit inventory and selected policy require their actual
// retained native source and authenticated engine channel separately.
func (r DesktopLinuxNodeCreationRecord) MatchesPrepared(p DesktopLinuxProtectionRecord) bool {
	return r.Validate() == nil && p.Validate() == nil && r.Capture == p.Capture && r.TableName == p.TableName &&
		r.TableHandle == p.TableHandle && r.ChainHandle == p.ChainHandle && r.BaselineSHA256 == p.BaselineSHA256
}
