package linuxprotection

import "errors"

// StandardNodeTransfer is immutable durable comparison data. The controller
// and service retain separate live creators; this record reconstructs neither.
type StandardNodeTransfer struct {
	ID                  string        `json:"id"`
	DeadlineNS          int64         `json:"deadline_ns"`
	SourceSession       string        `json:"source_session"`
	SourceConfigSHA256  string        `json:"source_config_sha256"`
	SourceReceiptSHA256 string        `json:"source_receipt_sha256"`
	Destination         NodeSelection `json:"destination"`
	ProfileID           string        `json:"profile_id"`
	ProfileRevision     string        `json:"profile_revision"`
}

func (r StandardNodeTransfer) Validate() error {
	if r.DeadlineNS <= 0 || !lowerHex(r.ID, 32) || !lowerHex(r.SourceSession, 32) || !lowerHex(r.SourceConfigSHA256, 64) || !lowerHex(r.SourceReceiptSHA256, 64) || r.Destination.Validate() != nil || r.SourceSession == r.Destination.SessionID || !profileID(r.ProfileID) || !lowerHex(r.ProfileRevision, 64) {
		return errors.New("cross-adapter intent lost its immutable original owners and selection")
	}
	return nil
}

func validTransferCheckpoint(previous, next JournalRecord) bool {
	same := previous.Transfer == nil && next.Transfer == nil || previous.Transfer != nil && next.Transfer != nil && *previous.Transfer == *next.Transfer
	if same {
		return true
	}
	// A fresh accepted transfer may replace only an idle empty comparison
	// checkpoint. The journal's live owner separately proves the prior abort and
	// the new original service reservation; these bytes grant no capability.
	return previous.Phase == "settled" && next.Phase == "settled" && previous.Committed == (JournalState{}) && next.Committed == (JournalState{}) && next.Transfer != nil && next.Transfer.Validate() == nil && (previous.Transfer == nil || previous.Transfer.ID != next.Transfer.ID)
}
