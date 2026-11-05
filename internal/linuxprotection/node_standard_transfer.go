package linuxprotection

import "errors"

// NodeStandardTransfer records comparison identities only. Both processes keep
// their own creator capabilities; a journal cannot reconstruct either one.
type NodeStandardTransfer struct {
	ID                       string        `json:"id"`
	DeadlineNS               int64         `json:"deadline_ns"`
	Source                   NodeSelection `json:"source"`
	SourceProfileID          string        `json:"source_profile_id"`
	SourceProfileRevision    string        `json:"source_profile_revision"`
	SourceReceiptSHA256      string        `json:"source_receipt_sha256"`
	DestinationSession       string        `json:"destination_session"`
	DestinationConfigSHA256  string        `json:"destination_config_sha256"`
	DestinationProfileID     string        `json:"destination_profile_id"`
	DestinationProfileSHA256 string        `json:"destination_profile_sha256"`
	Endpoint                 string        `json:"endpoint"`
	Policy                   string        `json:"policy"`
	HomeLAN                  bool          `json:"home_lan"`
}

func (r NodeStandardTransfer) Validate() error {
	if !lowerHex(r.ID, 32) || r.DeadlineNS <= 0 || r.Source.Validate() != nil || !profileID(r.SourceProfileID) || !lowerHex(r.SourceProfileRevision, 64) || !lowerHex(r.SourceReceiptSHA256, 64) || !lowerHex(r.DestinationSession, 32) || r.DestinationSession == r.Source.SessionID || !lowerHex(r.DestinationConfigSHA256, 64) || !profileID(r.DestinationProfileID) || !lowerHex(r.DestinationProfileSHA256, 64) || r.Endpoint == "" || (r.Policy != "always" && r.Policy != "on-connect") {
		return errors.New("reverse transfer lost original source or destination identity")
	}
	return nil
}
func validReverseTransferCheckpoint(previous, next JournalRecord) bool {
	if previous.ReverseTransfer == nil && next.ReverseTransfer == nil || previous.ReverseTransfer != nil && next.ReverseTransfer != nil && *previous.ReverseTransfer == *next.ReverseTransfer {
		return true
	}
	return previous.Phase == "settled" && next.Phase == "intent" && next.Intent != nil && next.Intent.Action == "standard-transfer" && next.ReverseTransfer != nil && next.ReverseTransfer.Validate() == nil && (previous.ReverseTransfer == nil || previous.ReverseTransfer.ID != next.ReverseTransfer.ID)
}
