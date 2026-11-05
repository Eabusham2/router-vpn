//go:build linux

package desktopnetwork

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLinuxRoutingHistoryRetiresAllActualConstructors(t *testing.T) {
	for _, scenario := range []string{"complete", "physical-change", "missing-reader", "missing-address", "missing-object", "missing-partial", "changed-constructor", "old-link-remains", "old-object-remains", "unjoined", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			owner, native := networkTestTracker(t, nil)
			old, current := networkTestReceipt(77), networkTestReceipt(78)
			retire := func(r DesktopNetworkReceipt) DesktopNetworkRetirementReceipt {
				return DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true, Incarnation: r.Incarnation, Name: r.Name, Index: r.Index, Addresses: append([]string(nil), r.Addresses...), Objects: append([]DesktopNetworkObject(nil), r.Objects...)}
			}
			partial := DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true, Unindexed: true, Incarnation: strings.Repeat("f", 32), Name: "partial-tun", Objects: []DesktopNetworkObject{}}
			owner.old = &old
			owner.current = &current
			owner.recorded = []DesktopNetworkReceipt{old, current}
			owner.retired = []DesktopNetworkRetirementReceipt{partial}
			lost := errors.New("actual network failure during retained mutation")
			owner.failLocked(lost)
			if !errors.Is(owner.CurrentContext(context.Background()), lost) {
				t.Fatal("original health failure was not reported")
			}
			history := []DesktopNetworkRetirementReceipt{retire(old), retire(current), partial}
			snapshot := networkTestPhysical()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "physical-change":
				snapshot.Links[0].MTU = 1400
			case "missing-reader":
				history = history[1:]
			case "missing-address":
				history[0].Addresses = nil
			case "missing-object":
				history[0].Objects = history[0].Objects[:1]
			case "missing-partial":
				history = history[:2]
			case "changed-constructor":
				changed := retire(old)
				changed.Name = "another"
				history = append(history, changed)
			case "old-link-remains":
				snapshot.Links = append(snapshot.Links, Link{Index: old.Index, Name: old.Name, MTU: old.MTU})
			case "old-object-remains":
				snapshot.Objects = append(snapshot.Objects, old.Objects[0])
			case "cancelled":
				cancel()
			}
			native.set(snapshot)
			if scenario != "unjoined" {
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err := owner.RoutingHistoryAbsent(ctx, history)
			pass := scenario == "complete" || scenario == "physical-change"
			if (err == nil) != pass {
				t.Fatalf("owned absence verdict: %v", err)
			}
		})
	}
}
