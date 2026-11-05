//go:build linux

package desktopnetwork

import (
	"context"
	"errors"
	"testing"
	"time"
)

func retainedTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func retainedTestPartial(index uint32) DesktopNetworkRetirementReceipt {
	r := networkTestReceipt(index)
	return DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true,
		Incarnation: r.Incarnation, Name: r.Name, Index: r.Index,
		Addresses: append([]string(nil), r.Addresses...), Objects: []DesktopNetworkObject{}}
}

func retainedTestEvents(t *Tracker, r DesktopNetworkRetirementReceipt, action string) {
	t.observe(Event{Kind: "link", Action: action, Index: r.Index, Name: r.Name}, nil)
	for _, address := range r.Addresses {
		t.observe(Event{Kind: "address", Action: action, Index: r.Index, Address: address}, nil)
	}
	for _, object := range r.Objects {
		t.observe(Event{Kind: object.Kind, Action: action, Index: object.Index, Object: object}, nil)
	}
}

func TestNetworkRetainedTransitionKeepsBothOriginalObservers(t *testing.T) {
	ctx := retainedTestContext(t)
	original, rollback := networkTestReceipt(7), networkTestReceipt(9)
	partial := retainedTestPartial(8)
	var owners [2]*Tracker
	var natives [2]*networkFakeNative
	var operations [2]*Transition
	var identities [2]string
	for i := range owners {
		owners[i], natives[i] = networkTestTracker(t, &original)
		identities[i] = owners[i].Identity()
		var err error
		operations[i], err = owners[i].BeginRetained(ctx, &original)
		if err != nil {
			t.Fatal(err)
		}
		networkTestEvents(owners[i], original, "delete")
		retainedTestEvents(owners[i], partial, "add")
		retainedTestEvents(owners[i], partial, "delete")
		if err := operations[i].RecordRetirement(ctx, partial); err != nil {
			t.Fatal(err)
		}
		if err := operations[i].RecordRetirement(ctx, partial); err != nil {
			t.Fatal(err)
		}
		if len(owners[i].recorded) != 0 {
			t.Fatal("partial reader became a fabricated Ready")
		}
		networkTestEvents(owners[i], rollback, "add")
		if err := operations[i].Record(ctx, rollback); err != nil {
			t.Fatal(err)
		}
		natives[i].set(networkTestWith(networkTestPhysical(), &rollback))
	}
	t.Run("service", func(t *testing.T) {
		if err := operations[0].Complete(ctx, &rollback); err != nil {
			t.Fatal(err)
		}
		if owners[0].CurrentContext(ctx) != nil || owners[1].CurrentContext(ctx) == nil || owners[1].retained != operations[1] {
			t.Fatal("one observer completion pretended to acknowledge the second original stream")
		}
	})
	t.Run("controller", func(t *testing.T) {
		caller, cancel := context.WithCancel(ctx)
		natives[1].mu.Lock()
		natives[1].barrier = cancel
		natives[1].mu.Unlock()
		if err := operations[1].Complete(caller, &rollback); !errors.Is(err, context.Canceled) {
			t.Fatal("late second acknowledgement became success", err)
		}
		if owners[1].retained != operations[1] || owners[1].failureError() != nil || owners[0].CurrentContext(ctx) != nil {
			t.Fatal("second observer expiry changed either original acknowledgement")
		}
		if err := operations[1].Complete(ctx, &rollback); err != nil {
			t.Fatal(err)
		}
		for i := range owners {
			if owners[i].Identity() != identities[i] || owners[i].CurrentContext(ctx) != nil || owners[i].retained != nil || owners[i].transition {
				t.Fatal("completion replaced original observer or lost actual rollback receipt")
			}
		}
	})
}

func TestNetworkRetainedTransitionRejectsUnclaimedPartialEffects(t *testing.T) {
	for _, kind := range []string{"missing-retirement", "wrong-address", "wrong-index", "unindexed-name-only", "foreign-object", "physical-away-and-back"} {
		t.Run(kind, func(t *testing.T) {
			ctx := retainedTestContext(t)
			original := networkTestReceipt(7)
			owner, _ := networkTestTracker(t, &original)
			op, err := owner.BeginRetained(ctx, &original)
			if err != nil {
				t.Fatal(err)
			}
			actual := retainedTestPartial(8)
			retainedTestEvents(owner, actual, "add")
			retainedTestEvents(owner, actual, "delete")
			claimed := actual
			switch kind {
			case "wrong-address":
				claimed.Addresses = []string{"10.0.0.99/24"}
			case "wrong-index":
				claimed.Index++
			case "unindexed-name-only":
				claimed.Index, claimed.Unindexed, claimed.Addresses = 0, true, nil
			case "foreign-object":
				owner.observe(Event{Kind: "route", Action: "add", Index: 8, Object: networkTestObject("route", 8, 2033, "198.51.100.0/24", "")}, nil)
			}
			if kind != "missing-retirement" {
				if err := op.RecordRetirement(ctx, claimed); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "physical-away-and-back" {
				owner.observe(Event{Kind: "link", Action: "change", Index: 2, Name: "physical-test"}, nil)
			}
			if err := op.Complete(ctx, &original); err == nil {
				t.Fatal("unclaimed partial effect became current")
			}
			if owner.failureError() == nil || owner.CurrentContext(ctx) == nil {
				t.Fatal("real event loss was not latched")
			}
		})
	}
}

func TestNetworkRetainedTransitionCancellationKeepsOriginalHistory(t *testing.T) {
	ctx := retainedTestContext(t)
	original := networkTestReceipt(7)
	owner, native := networkTestTracker(t, &original)
	op, err := owner.BeginRetained(ctx, &original)
	if err != nil {
		t.Fatal(err)
	}
	partial := retainedTestPartial(8)
	retainedTestEvents(owner, partial, "add")
	retainedTestEvents(owner, partial, "delete")
	if err := op.RecordRetirement(ctx, partial); err != nil {
		t.Fatal(err)
	}
	observation, cancel := context.WithCancel(ctx)
	native.mu.Lock()
	native.barrier = cancel
	native.mu.Unlock()
	if err := op.Complete(observation, &original); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled completion became current", err)
	}
	if owner.retained != op || !owner.transition || len(owner.retired) != 1 || owner.failureError() != nil {
		t.Fatal("pure completion expiry discarded original history or failed the observer")
	}
	if owner.CurrentContext(ctx) == nil {
		t.Fatal("pending transition became a current observation")
	}
	if err := op.Complete(ctx, &original); err != nil {
		t.Fatal("original cleanup could not complete original history", err)
	}
	next, err := owner.BeginRetained(ctx, &original)
	if err != nil {
		t.Fatal(err)
	}
	if err := op.RecordRetirement(ctx, partial); err == nil {
		t.Fatal("older completion mutated replacement transition")
	}
	if owner.retained != next || owner.failureError() != nil {
		t.Fatal("older token invalidated replacement observer")
	}
	if err := next.Complete(ctx, &original); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkRetainedTransitionAdmissionUsesCaller(t *testing.T) {
	for _, stage := range []string{"begin", "record", "retirement", "complete"} {
		t.Run(stage, func(t *testing.T) {
			ctx := retainedTestContext(t)
			original := networkTestReceipt(7)
			owner, _ := networkTestTracker(t, &original)
			var op *Transition
			var err error
			if stage != "begin" {
				op, err = owner.BeginRetained(ctx, &original)
				if err != nil {
					t.Fatal(err)
				}
			}
			caller, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
			defer cancel()
			owner.mu.Lock()
			done := make(chan error, 1)
			go func() {
				switch stage {
				case "begin":
					_, err := owner.BeginRetained(caller, &original)
					done <- err
				case "record":
					done <- op.Record(caller, original)
				case "retirement":
					done <- op.RecordRetirement(caller, retainedTestPartial(8))
				case "complete":
					done <- op.Complete(caller, &original)
				}
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Error("held-lock caller lost expiry", err)
				}
			case <-time.After(time.Second):
				owner.mu.Unlock()
				<-done
				t.Fatal("caller left a detached or unbounded lock waiter")
			}
			owner.mu.Unlock()
			if owner.failureError() != nil {
				t.Fatal("held observation failed healthy original owner")
			}
			if op != nil {
				if err := op.Complete(ctx, &original); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestNetworkRetainedTransitionRejectsChangedEvidence(t *testing.T) {
	for _, kind := range []string{"duplicate-retirement", "retirement-ready-identity", "duplicate-ready", "mixed-native-loss"} {
		t.Run(kind, func(t *testing.T) {
			ctx := retainedTestContext(t)
			original := networkTestReceipt(7)
			owner, native := networkTestTracker(t, &original)
			op, err := owner.BeginRetained(ctx, &original)
			if err != nil {
				t.Fatal(err)
			}
			partial := retainedTestPartial(8)
			switch kind {
			case "duplicate-retirement":
				if err := op.RecordRetirement(ctx, partial); err != nil {
					t.Fatal(err)
				}
				partial.Addresses = []string{"10.0.0.99/24"}
				err = op.RecordRetirement(ctx, partial)
			case "retirement-ready-identity":
				if err := op.RecordRetirement(ctx, partial); err != nil {
					t.Fatal(err)
				}
				ready := networkTestReceipt(8)
				ready.Name = "foreign"
				err = op.Record(ctx, ready)
			case "duplicate-ready":
				ready := networkTestReceipt(8)
				if err := op.Record(ctx, ready); err != nil {
					t.Fatal(err)
				}
				ready.MTU--
				err = op.Record(ctx, ready)
			case "mixed-native-loss":
				call, cancel := context.WithCancel(ctx)
				defer cancel()
				loss := errors.New("original native stream lost")
				owner.native = &networkOperationNative{nativeObserver: native, snapshot: func(context.Context) (Snapshot, error) { cancel(); return Snapshot{}, errors.Join(loss, call.Err()) }}
				err = op.Complete(call, &original)
				if !errors.Is(err, loss) || !errors.Is(err, context.Canceled) {
					t.Fatal("mixed failure was laundered", err)
				}
			}
			if err == nil || owner.failureError() == nil {
				t.Fatal("changed original evidence did not fail closed", err)
			}
		})
	}
}

func TestNetworkRetainedTransitionRequiresOriginalCapability(t *testing.T) {
	for _, kind := range []string{"unbounded-caller", "foreign-receipt", "foreign-token", "busy-owner", "lifetime-loss"} {
		t.Run(kind, func(t *testing.T) {
			ctx := retainedTestContext(t)
			original := networkTestReceipt(7)
			owner, _ := networkTestTracker(t, &original)
			if kind == "unbounded-caller" {
				if op, err := owner.BeginRetained(context.Background(), &original); err == nil || op != nil {
					t.Fatal("unbounded caller acquired original transition")
				}
				if err := owner.CurrentContext(ctx); err != nil {
					t.Fatal(err)
				}
				return
			}
			if kind == "foreign-receipt" {
				foreign := networkTestReceipt(8)
				if op, err := owner.BeginRetained(ctx, &foreign); err == nil || op != nil {
					t.Fatal("foreign receipt acquired original transition")
				}
				if err := owner.CurrentContext(ctx); err != nil {
					t.Fatal(err)
				}
				return
			}
			op, err := owner.BeginRetained(ctx, &original)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "foreign-token":
				foreign := &Transition{owner: owner}
				if err := foreign.Record(ctx, original); err == nil {
					t.Fatal("copied tracker reference acquired retained capability")
				}
			case "busy-owner":
				if replacement, err := owner.BeginRetained(ctx, &original); err == nil || replacement != nil {
					t.Fatal("second caller acquired occupied original observer")
				}
			case "lifetime-loss":
				lifetime, stop := context.WithCancel(context.Background())
				owner.ctx = lifetime
				stop()
				if err := op.Record(ctx, original); err == nil || owner.failureError() == nil {
					t.Fatal("lost original lifetime regained transition authority")
				}
				return
			}
			if owner.retained != op || owner.failureError() != nil {
				t.Fatal("foreign caller displaced original transition")
			}
			if err := op.Complete(ctx, &original); err != nil {
				t.Fatal(err)
			}
		})
	}
}
