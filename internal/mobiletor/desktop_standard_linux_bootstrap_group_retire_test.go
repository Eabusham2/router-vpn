//go:build linux

package mobiletor

import (
	"context"
	"testing"
)

func TestLinuxStandardBootstrapGroupRecyclingRetainsAuthority(t *testing.T) {
	for _, name := range []string{"active", "joined-pinned", "unknown-creation", "poisoned-creation"} {
		t.Run(name, func(t *testing.T) {
			g := &DesktopLinuxBootstrapDNSGroup{owner: &DesktopLinuxStandardProtection{baseline: &DesktopLinuxNodeBaseline{}}, inventoryBytes: 8192}
			member := &desktopLinuxStandardBootstrap{group: g}
			g.members = []*desktopLinuxStandardBootstrap{member}
			switch name {
			case "joined-pinned":
				member.groupJoined, member.groupPinned = true, true
			case "unknown-creation":
				member.groupJoined = true
				member.grant = &desktopLinuxBootstrapGrant{sent: true}
			case "poisoned-creation":
				member.groupJoined = true
				member.grant = &desktopLinuxBootstrapGrant{poison: context.Canceled}
			}
			err := g.retireJoined(context.Background())
			if (name == "unknown-creation" || name == "poisoned-creation") != (err != nil) {
				t.Fatalf("wrong original receipt disposition: %v", err)
			}
			if len(g.members) != 1 || g.members[0] != member || g.inventoryBytes != 8192 {
				t.Fatal("unjoined, pinned or uncertain member released original accounting")
			}
			foreign := &desktopLinuxStandardBootstrap{group: &DesktopLinuxBootstrapDNSGroup{}, groupPinned: true}
			g.unpin(foreign)
			if !foreign.groupPinned {
				t.Fatal("foreign group unpinned original member")
			}
		})
	}
}

func TestLinuxStandardBootstrapGroupRecyclingKeepsAdmissionBound(t *testing.T) {
	g := &DesktopLinuxBootstrapDNSGroup{initialDescriptors: 32, inventoryBytes: 8192}
	// This checks admission arithmetic, not a claim of native full-cohort IO.
	for i := 0; i < desktopLinuxBootstrapGroupAdmissions; i++ {
		if err := g.capacityFor(32, 4096); err != nil {
			t.Fatal(i, err)
		}
		g.admitted++
	}
	if err := g.capacityFor(32, 4096); err == nil {
		t.Fatal("recycled resources erased historical admission bound")
	}
	g.admitted = 0
	if err := g.capacityFor(32, 64); err == nil {
		t.Fatal("recycling manufactured native descriptor capacity")
	}
}
