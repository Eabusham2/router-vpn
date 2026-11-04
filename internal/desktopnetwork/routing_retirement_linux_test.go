//go:build linux

package desktopnetwork

import (
	"context"
	"errors"
	"testing"
)

type routingRetirementFixture struct {
	*networkFakeNative
	failure error
	during  func()
}

func (f *routingRetirementFixture) Snapshot(ctx context.Context) (Snapshot, error) {
	if f.during != nil {
		f.during()
	}
	if f.failure != nil {
		return Snapshot{}, f.failure
	}
	return f.networkFakeNative.Snapshot(ctx)
}

func TestLinuxRoutingRetirementRequiresOriginalJoinedInventory(t *testing.T) {
	for _, scenario := range []string{"empty", "route-remains", "rule-remains", "duplicate-owned", "malformed", "unjoined", "failed-join", "owned-baseline", "incomplete-baseline", "read-failure", "cancelled", "late-cancel", "foreign-reader", "missing-ledger", "owned-baseline-alias", "new-foreign-route", "partial-ledger", "foreign-same-key", "incomplete-dump"} {
		t.Run(scenario, func(t *testing.T) {
			var receipt *DesktopNetworkReceipt
			if scenario == "owned-baseline" {
				value := networkTestReceipt(77)
				receipt = &value
			}
			owner, native := networkTestTracker(t, receipt)
			wrapper := &routingRetirementFixture{networkFakeNative: native}
			owner.native = wrapper
			snapshot := networkTestWith(native.snapshot, nil)
			original := networkTestReceipt(77)
			created := DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true, Incarnation: original.Incarnation, Name: original.Name, Index: original.Index, Objects: original.Objects}
			createdPointer := &created
			if scenario == "partial-ledger" {
				owner.current = &original
				created.Objects = created.Objects[:1]
			}
			if scenario == "missing-ledger" {
				createdPointer = nil
			}
			if scenario == "owned-baseline-alias" {
				snapshot.Objects = append(snapshot.Objects, original.Objects[1])
				owner.physical.Objects = append(owner.physical.Objects, original.Objects[1])
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "failed-join" {
				native.closeFailures = 1
			}
			if scenario != "unjoined" {
				err := owner.Close()
				if (err != nil) != (scenario == "failed-join") {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "route-remains":
				snapshot.Objects = append(snapshot.Objects, networkTestObject("route", 77, 2022, "0.0.0.0/0", ""))
			case "rule-remains":
				snapshot.Objects = append(snapshot.Objects, networkTestObject("rule", 0, 2022, "", ""))
			case "duplicate-owned":
				snapshot.Objects = append(snapshot.Objects, created.Objects[0], created.Objects[0])
			case "foreign-same-key":
				snapshot.Objects = append(snapshot.Objects, created.Objects[1])
			case "new-foreign-route":
				snapshot.Objects = append(snapshot.Objects, networkTestObject("route", 2, 254, "203.0.113.0/24", "192.0.2.1"))
			case "incomplete-dump":
				snapshot.Links = nil
			case "malformed":
				snapshot.Objects[0].Native = "incomplete"
			case "incomplete-baseline":
				owner.startedWithoutOwnedReceipt = false
			case "read-failure":
				wrapper.failure = errors.New("original native inventory unavailable")
			case "cancelled":
				cancel()
			case "late-cancel":
				wrapper.during = cancel
			case "foreign-reader":
				wrapper.during = func() { owner.mu.Lock(); owner.native = &networkFakeNative{}; owner.mu.Unlock() }
			}
			native.set(snapshot)
			err := owner.RoutingAbsent(ctx, createdPointer)
			if (err == nil) != (scenario == "empty" || scenario == "new-foreign-route") {
				t.Fatal("retirement inferred absence from incomplete or foreign inventory", err)
			}
			if scenario == "new-foreign-route" && len(native.snapshot.Objects) != 2 {
				t.Fatal("read-only retirement altered a foreign route")
			}
			if owner.CurrentContext(context.Background()) == nil && scenario != "unjoined" {
				t.Fatal("retirement rebased the original closed epoch")
			}
			if scenario == "foreign-reader" {
				owner.mu.Lock()
				foreign := owner.native.(*networkFakeNative)
				owner.native = wrapper
				owner.mu.Unlock()
				if foreign.closes != 0 {
					t.Fatal("retirement closed replacement native reader")
				}
			}
		})
	}
}
