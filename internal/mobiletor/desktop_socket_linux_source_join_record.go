package mobiletor

import "errors"

// DesktopLinuxSourceJoinRecord reports teardown through an original Node
// source which joined its actual Cmd and closed its retained witnesses. A
// failed constructor may never complete its birth observation; such a record
// can report the native join without inventing a complete guardian identity.
// It cannot create a ProtectionTarget, adopt a process or authorize deletion.
// The authenticated parent still owns the original baseline and engine join.
type DesktopLinuxSourceJoinRecord struct {
	Capture   DesktopSocketCapture        `json:"capture"`
	ProcessID uint32                      `json:"process_id"`
	Original  *DesktopLinuxGuardianRecord `json:"original,omitempty"`
}

func (r DesktopLinuxSourceJoinRecord) Validate() error {
	if !r.Capture.valid() || r.ProcessID == 0 || r.ProcessID > 1<<31-1 ||
		r.Original != nil && (r.Original.Validate() != nil || uint32(r.Original.Guardian.ProcessID) != r.ProcessID) {
		return errors.New("Linux joined-source record lost its captured native creation")
	}
	return nil
}

func (r DesktopLinuxSourceJoinRecord) Clone() DesktopLinuxSourceJoinRecord {
	if r.Original != nil {
		copy := *r.Original
		r.Original = &copy
	}
	return r
}
