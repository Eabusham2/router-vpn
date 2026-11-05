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

func TestDesktopNetworkRetirementExactPartialAddresses(t *testing.T) {
	base := DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true, Name: "original0", Index: 7, Incarnation: strings.Repeat("a", 32), Objects: []DesktopNetworkObject{}}
	old, err := CanonicalDesktopNetworkRetirementReceipt(base)
	if err != nil || strings.Contains(old, "addresses") {
		t.Fatal("old empty receipt bytes changed", old, err)
	}
	base.Addresses = []string{"192.0.2.7/24", "fd00::7/64"}
	raw, err := CanonicalDesktopNetworkRetirementReceipt(base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDesktopNetworkRetirementReceipt(raw)
	if err != nil || len(got.Addresses) != 2 || got.Addresses[0] != "192.0.2.7/24" {
		t.Fatal("actual host prefix was lost", got, err)
	}
	for _, test := range []struct {
		name      string
		addresses []string
	}{
		{"duplicate", []string{"192.0.2.7/24", "192.0.2.7/24"}},
		{"unordered", []string{"fd00::7/64", "192.0.2.7/24"}},
		{"unbounded", make([]string, 33)},
		{"unspecified", []string{"0.0.0.0/32"}},
		{"multicast", []string{"ff02::1/128"}},
		{"mapped", []string{"::ffff:192.0.2.7/128"}},
		{"noncanonical", []string{"FD00::7/64"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := base
			copy.Addresses = test.addresses
			if _, err := CanonicalDesktopNetworkRetirementReceipt(copy); err == nil {
				t.Fatal("unproved address history accepted")
			}
		})
	}
	for _, unindexed := range []bool{false, true} {
		copy := base
		copy.Index = 0
		copy.Unindexed = unindexed
		copy.Created = unindexed
		if _, err := CanonicalDesktopNetworkRetirementReceipt(copy); err == nil {
			t.Fatal("uncreated or unindexed address accepted")
		}
	}
	if _, err := ParseDesktopNetworkRetirementReceipt(old[:len(old)-1] + ",\"addresses\":[]}"); err == nil {
		t.Fatal("noncanonical empty optional evidence accepted")
	}
}
