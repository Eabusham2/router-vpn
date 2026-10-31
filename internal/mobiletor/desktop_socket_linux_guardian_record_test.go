package mobiletor

import (
	"testing"

	"router-vpn/internal/linuxprocess"
)

func TestLinuxBaselineGuardianRecordRequiresNativeRelationship(t *testing.T) {
	engine := linuxprocess.Observation{BootID: "11111111-2222-3333-4444-555555555555", ProcessID: 101, ProcProcessID: 301,
		ProcParentID: 300, StartTicks: 400, Image: linuxprocess.Object{Device: 1, Inode: 2, Mode: 0100755},
		NetworkNamespace: linuxprocess.Object{Device: 3, Inode: 4, Mode: 0100444}, PIDNamespace: linuxprocess.Object{Device: 3, Inode: 5, Mode: 0100444}}
	guardian := engine
	guardian.ProcessID, guardian.ProcProcessID, guardian.ProcParentID, guardian.StartTicks = 102, 302, 301, 401
	original := DesktopLinuxGuardianRecord{Engine: engine, Guardian: guardian}
	if err := original.Validate(); err != nil {
		t.Fatal(err)
	}
	for label, mutate := range map[string]func(*DesktopLinuxGuardianRecord){
		"native-pid-alias": func(r *DesktopLinuxGuardianRecord) { r.Guardian.ProcessID = r.Engine.ProcessID },
		"proc-pid-alias":   func(r *DesktopLinuxGuardianRecord) { r.Guardian.ProcProcessID = r.Engine.ProcProcessID },
		"parent":           func(r *DesktopLinuxGuardianRecord) { r.Guardian.ProcParentID++ },
		"birth":            func(r *DesktopLinuxGuardianRecord) { r.Guardian.StartTicks = r.Engine.StartTicks - 1 },
		"boot":             func(r *DesktopLinuxGuardianRecord) { r.Guardian.BootID = "21111111-2222-3333-4444-555555555555" },
		"image":            func(r *DesktopLinuxGuardianRecord) { r.Guardian.Image.Inode++ },
		"network":          func(r *DesktopLinuxGuardianRecord) { r.Guardian.NetworkNamespace.Inode++ },
		"pid-namespace":    func(r *DesktopLinuxGuardianRecord) { r.Guardian.PIDNamespace.Inode++ },
		"invalid-engine":   func(r *DesktopLinuxGuardianRecord) { r.Engine.Image.Mode |= 0002 },
	} {
		t.Run(label, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("guardian record accepted a different created process relationship")
			}
		})
	}
}
