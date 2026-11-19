package mobilemtu

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const fixedRevision = "ffff0000111122223333444455556666"

func TestDeviceFixedRetainsProvedSourceAndPeerEnvelope(t *testing.T) {
	for _, mode := range []string{"auto", "fixed", "default"} {
		t.Run(mode, func(t *testing.T) {
			c, owner := contextController(t)
			c.profile.Automatic = mode == "auto"
			c.external.profile.MTUPolicy = mode
			// No bounded cache is supplied: neither its lookup nor write may run.
			prefs := &testPreferences{data: "preserve opaque measured history", fail: true}
			c.cache = NewCache(prefs)
			old := c.Config()
			if err := c.ApplyDeviceFixedContext(context.Background(), fixedRevision, 1400); err != nil {
				t.Fatal(err)
			}
			if c.Requested() || c.RunContext(context.Background(), strings.Repeat("b", 32), true) == nil {
				t.Fatal("fixed session permitted Retest")
			}
			plan, err := NewPlan(old, 1380)
			if err != nil {
				t.Fatal(err)
			}
			want, err := plan.Config(1400)
			if err != nil {
				t.Fatal(err)
			}
			status := readStatus(t, c)
			if c.Config() != want || c.frozenConfig != old || status.Source != "device-fixed" || status.Request != fixedRevision || status.Measured || !status.Complete || status.Running || status.EffectiveMTU != 1400 || len(status.Candidates) != 0 || len(owner.dials) != 0 || prefs.data != "preserve opaque measured history" {
				t.Fatal(status)
			}
			if !reflect.DeepEqual(owner.applied, []int{1400}) || len(owner.proofs) != 2 || owner.proofs[0].MTU != 1380 || owner.proofs[1].MTU != 1400 {
				t.Fatal(owner.applied, owner.proofs)
			}
			if err := c.CancelContext(context.Background(), fixedRevision); !errors.Is(err, ErrOperationCommitted) {
				t.Fatal("committed fixed size was cancellable", err)
			}
			if c.ApplyDeviceFixedContext(context.Background(), strings.Repeat("b", 32), 1390) == nil {
				t.Fatal("retained owner reused for another revision")
			}
		})
	}
}

func TestDeviceFixedRejectsStaleOrUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name, rev string
		mtu       int
	}{{"invalid-revision", "stale", 1400}, {"outside", "", 9001}, {"peer-ceiling", fixedRevision, 8000}, {"jumbo-conflict", fixedRevision, 1390}, {"tor-entry-conflict", fixedRevision, 1390}} {
		t.Run(tc.name, func(t *testing.T) {
			c, o := contextController(t)
			if tc.name == "jumbo-conflict" {
				c.profile.Jumbo = true
			}
			if tc.name == "tor-entry-conflict" {
				c.external.profile.EntryFixedMTU = 1380
			}
			if err := c.ApplyDeviceFixedContext(context.Background(), tc.rev, tc.mtu); err == nil {
				t.Fatal("unowned size accepted")
			}
			if len(o.applied) != 0 || len(o.proofs) != 0 || c.Config() != c.frozenConfig || readStatus(t, c).Measured {
				t.Fatal("rejected request mutated an owner")
			}
		})
	}
}

func TestDeviceFixedWrongReadbackRollsBackOnlyOriginal(t *testing.T) {
	c, o := contextController(t)
	o.wrongReadback = true
	original := c.Config()
	o.mutate = func(ctx context.Context, state State, mtu int) (State, error) {
		if !DeviceFixedChangeAllowed(ctx, mtu) || DeviceFixedChangeAllowed(ctx, 1499) || DeviceFixedChangeAllowed(context.Background(), mtu) {
			t.Fatal("native lease lost original mutation boundary", mtu)
		}
		return o.testOwner.ChangeMTU(ctx, state, mtu)
	}
	if err := c.ApplyDeviceFixedContext(context.Background(), fixedRevision, 1400); err == nil {
		t.Fatal("wrong native readback accepted")
	}
	status := readStatus(t, c)
	if !reflect.DeepEqual(o.applied, []int{1400, 1380}) || status.Source != "restored-unmeasured" || status.Measured || !status.Restored || c.Config() != original {
		t.Fatal(status, o.applied)
	}
}

func TestDeviceFixedJoinsOriginalTypedRun(t *testing.T) {
	c, o := contextController(t)
	admitted := make(chan context.Context, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	deadline := func(context.Context) (time.Time, error) { return time.Now().Add(time.Second), nil }
	wait, err := c.StartDeviceFixedContextWithCleanupProvider(context.Background(), context.Background(), fixedRevision, 1380, deadline,
		func(ctx context.Context) error { admitted <- ctx; return nil }, func(ctx context.Context) error {
			initial := <-admitted
			if !SameOperationContext(initial, ctx) {
				return errors.New("finalization replaced native run")
			}
			close(entered)
			<-release
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	if !c.Running() || c.Requested() {
		t.Fatal("fixed run released exclusive owner before finalization")
	}
	close(release)
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if c.Running() || readStatus(t, c).Source != "device-fixed" || len(o.proofs) != 1 || len(o.applied) != 0 {
		t.Fatal("same-size adoption did not join, reprove, or preserve original reader")
	}
}
