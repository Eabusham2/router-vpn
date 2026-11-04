package desktopnetwork

import (
	"strings"
	"testing"
)

func TestDesktopNetworkRetirementCanonicalPartialCreation(t *testing.T) {
	for _, r := range []DesktopNetworkRetirementReceipt{
		{Schema: 1, TargetOS: "linux", Objects: []DesktopNetworkObject{}},
		{Schema: 1, TargetOS: "linux", Created: true, Unindexed: true, Name: "original0", Incarnation: strings.Repeat("a", 32), Objects: []DesktopNetworkObject{}},
		{Schema: 1, TargetOS: "linux", Created: true, Name: "original0", Index: 7, Incarnation: strings.Repeat("a", 32), Objects: []DesktopNetworkObject{}},
	} {
		raw, err := CanonicalDesktopNetworkRetirementReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseDesktopNetworkRetirementReceipt(raw); err != nil {
			t.Fatal(err)
		}
		for _, changed := range []string{raw + " ", strings.Replace(raw, "\"schema\":1", "\"schema\":1,\"schema\":1", 1), raw[:len(raw)-1] + ",\"unknown\":true}"} {
			if _, err := ParseDesktopNetworkRetirementReceipt(changed); err == nil {
				t.Fatal("noncanonical retirement report accepted")
			}
		}
	}
}
func TestDesktopNetworkRetirementRejectsInventedNoCreation(t *testing.T) {
	valid := DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true, Name: "original0", Index: 7, Incarnation: strings.Repeat("a", 32), Objects: []DesktopNetworkObject{}}
	for _, mutate := range []func(*DesktopNetworkRetirementReceipt){
		func(r *DesktopNetworkRetirementReceipt) { r.Created = false },
		func(r *DesktopNetworkRetirementReceipt) { r.Unindexed = true },
		func(r *DesktopNetworkRetirementReceipt) { r.Index = 0 },
		func(r *DesktopNetworkRetirementReceipt) { r.Incarnation = "" },
		func(r *DesktopNetworkRetirementReceipt) { r.TargetOS = "darwin" },
		func(r *DesktopNetworkRetirementReceipt) { r.Objects = nil },
	} {
		copy := valid
		mutate(&copy)
		if _, err := CanonicalDesktopNetworkRetirementReceipt(copy); err == nil {
			t.Fatal("incomplete or contradictory native retirement accepted", copy)
		}
	}
}
