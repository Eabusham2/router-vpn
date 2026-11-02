//go:build linux

package main

import (
	"reflect"
	"testing"
)

// Native observations are the existing retained-host fixture boundary. This
// tests the exact batch preflight, not an installed TUN or a successful handoff.
func TestDesktopExternalComparisonLinuxRetainedProtectionRejectsBeforeStop(t *testing.T) {
	f := newLinuxSpeedLabPathFixture(t)
	before, command := f.a.state, f.a.cmd
	profiles := cloneRouterProfileStore(f.a.profiles)
	session, host, predecessor, journal := f.p.session, f.s.active, f.s.predecessor, f.s.journal
	request := speedLabRequest{Scope: "temporary", Topology: "external", NodeID: "external-exit", Execution: "local"}
	if f.a.retainedDesktopNodeProtection() {
		t.Fatal("Linux fixture accidentally borrowed the Windows protection slot")
	}
	if err := f.a.guardDesktopExternalComparisonPath(request, speedLabTemporarySnapshot{}); err == nil {
		t.Fatal("batch admitted an external successor without Linux protection transfer")
	}
	if f.a.state != before || f.a.cmd != command || !reflect.DeepEqual(f.a.profiles, profiles) || f.p.session != session || f.s.active != host || f.s.predecessor != predecessor || f.s.journal != journal {
		t.Fatal("refused comparison changed the original Linux runtime, policy or journal")
	}
	if _, exists := desktopNodeOwners.Load(f.a); exists {
		t.Fatal("refused comparison registered a competing legacy native owner")
	}
}
