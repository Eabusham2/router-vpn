package mobiletor

import "testing"

func TestLinuxBaselineSourceJoinRecordPreservesPartialOwnership(t *testing.T) {
	partial := DesktopLinuxSourceJoinRecord{Capture: desktopSocketFixtureCapture(), ProcessID: 123}
	if err := partial.Validate(); err != nil {
		t.Fatal("actual partial source comparison requires no invented native identity", err)
	}
	for _, change := range []func(*DesktopLinuxSourceJoinRecord){
		func(r *DesktopLinuxSourceJoinRecord) { r.Capture.NetworkID = "" },
		func(r *DesktopLinuxSourceJoinRecord) { r.ProcessID = 0 },
		func(r *DesktopLinuxSourceJoinRecord) { r.ProcessID = 1 << 31 },
		func(r *DesktopLinuxSourceJoinRecord) { r.Original = &DesktopLinuxGuardianRecord{} },
	} {
		bad := partial.Clone()
		change(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatal("malformed partial native ownership was accepted")
		}
	}
}
