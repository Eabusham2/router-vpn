package mobiletor

import (
	"strings"
	"testing"
)

func TestDesktopLinuxProtectionRecordBounds(t *testing.T) {
	record := DesktopLinuxProtectionRecord{Capture: desktopSocketFixtureCapture(), Owner: desktopSocketFixturePolicy().owner,
		UID: 10001, PermitPrefix: "rvpn_" + strings.Repeat("a", 20), TableHandle: 1, ChainHandle: 2, BaselineSHA256: strings.Repeat("b", 64)}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DesktopLinuxProtectionRecord){
		"missing-network":    func(r *DesktopLinuxProtectionRecord) { r.Capture.NetworkID = "" },
		"missing-source":     func(r *DesktopLinuxProtectionRecord) { r.Capture.SourceSHA256 = "" },
		"foreign-owner-kind": func(r *DesktopLinuxProtectionRecord) { r.Owner.Kind = "windows-isolated-token" },
		"missing-generation": func(r *DesktopLinuxProtectionRecord) { r.Owner.Generation = 0 },
		"missing-owner":      func(r *DesktopLinuxProtectionRecord) { r.Owner.IdentitySHA256 = "" },
		"root-uid":           func(r *DesktopLinuxProtectionRecord) { r.UID = 0 },
		"missing-prefix":     func(r *DesktopLinuxProtectionRecord) { r.PermitPrefix = "" },
		"uppercase-prefix":   func(r *DesktopLinuxProtectionRecord) { r.PermitPrefix = "rvpn_" + strings.Repeat("A", 20) },
		"malformed-prefix":   func(r *DesktopLinuxProtectionRecord) { r.PermitPrefix = "rvpn_" + strings.Repeat("g", 20) },
		"missing-table":      func(r *DesktopLinuxProtectionRecord) { r.TableHandle = 0 },
		"missing-chain":      func(r *DesktopLinuxProtectionRecord) { r.ChainHandle = 0 },
		"inexact-table":      func(r *DesktopLinuxProtectionRecord) { r.TableHandle = 1 << 53 },
		"inexact-chain":      func(r *DesktopLinuxProtectionRecord) { r.ChainHandle = 1 << 53 },
		"missing-baseline":   func(r *DesktopLinuxProtectionRecord) { r.BaselineSHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := record
			mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("malformed Linux observation became a valid native identity")
			}
		})
	}
}
