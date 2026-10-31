package mobiletor

import (
	"strings"
	"testing"
)

func TestLinuxBaselineNodeCreationRecordBindsPreparedIdentity(t *testing.T) {
	p := DesktopLinuxProtectionRecord{Capture: desktopSocketFixtureCapture(), Owner: desktopSocketFixturePolicy().owner,
		UID: 10001, PermitPrefix: "rvpn_" + strings.Repeat("a", 20), TableHandle: 1, ChainHandle: 2, BaselineSHA256: strings.Repeat("b", 64)}
	p.TableName = desktopLinuxNodeTable(p.Capture)
	r := DesktopLinuxNodeCreationRecord{Capture: p.Capture, HomeLAN: true, TableName: p.TableName,
		TableHandle: p.TableHandle, ChainHandle: p.ChainHandle, BaselineSHA256: p.BaselineSHA256}
	if err := r.Validate(); err != nil || !r.MatchesPrepared(p) {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DesktopLinuxNodeCreationRecord){
		"capture":        func(r *DesktopLinuxNodeCreationRecord) { r.Capture.SourceSHA256 = strings.Repeat("c", 64) },
		"network":        func(r *DesktopLinuxNodeCreationRecord) { r.Capture.NetworkID = strings.Repeat("c", 32) },
		"table":          func(r *DesktopLinuxNodeCreationRecord) { r.TableName = desktopLinuxNFTTable },
		"table-handle":   func(r *DesktopLinuxNodeCreationRecord) { r.TableHandle++ },
		"chain-handle":   func(r *DesktopLinuxNodeCreationRecord) { r.ChainHandle++ },
		"baseline":       func(r *DesktopLinuxNodeCreationRecord) { r.BaselineSHA256 = strings.Repeat("c", 64) },
		"inexact-handle": func(r *DesktopLinuxNodeCreationRecord) { r.TableHandle = 1 << 53 },
		"missing-handle": func(r *DesktopLinuxNodeCreationRecord) { r.ChainHandle = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if changed.MatchesPrepared(p) {
				t.Fatal("creation record matched a different guardian baseline")
			}
		})
	}
}
