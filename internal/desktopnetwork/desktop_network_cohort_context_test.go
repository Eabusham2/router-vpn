package desktopnetwork

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNetworkCohortCallerHeldAdmission(t *testing.T) {
	for _, stage := range []string{"identity", "begin", "record", "initialize", "end", "end-native-failure"} {
		t.Run(stage, func(t *testing.T) {
			owner, native := networkTestTracker(t, nil)
			identity := owner.Identity()
			if stage == "record" || stage == "end" || stage == "end-native-failure" {
				if err := owner.Begin(context.Background(), nil); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			held := make(chan struct{})
			nativeFailure := errors.New("original native transition inventory lost")
			if stage == "initialize" || stage == "end" {
				native.barrier = func() { owner.mu.Lock(); close(held) }
			} else if stage == "end-native-failure" {
				owner.native = &networkOperationNative{nativeObserver: native, snapshot: func(caller context.Context) (Snapshot, error) {
					owner.mu.Lock()
					close(held)
					<-caller.Done()
					return Snapshot{}, errors.Join(nativeFailure, caller.Err())
				}}
			} else {
				owner.mu.Lock()
				close(held)
			}
			done := make(chan error, 1)
			go func() {
				var err error
				switch stage {
				case "identity":
					var got string
					got, err = owner.IdentityContext(ctx)
					if got != "" {
						err = errors.New("expired identity exposed a selectable frozen key")
					}
				case "begin":
					err = owner.Begin(ctx, nil)
				case "record":
					err = owner.RecordContext(ctx, networkTestReceipt(11))
				case "initialize":
					err = owner.initialize(ctx)
				default:
					err = owner.End(ctx, nil)
				}
				done <- err
			}()
			<-held
			cancel()
			var err error
			select {
			case err = <-done:
				owner.mu.Unlock()
			case <-time.After(time.Second):
				owner.mu.Unlock()
				<-done
				t.Fatal("cohort caller waited for unrelated held tracker lock")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatal("cohort caller lost original cancellation", err)
			}
			if stage == "end-native-failure" && !errors.Is(err, nativeFailure) {
				t.Fatal("cancellation hid the original native failure", err)
			}
			if owner.Identity() != identity || len(owner.recorded) != 0 || owner.current != nil || owner.closed || owner.closing {
				t.Fatal("expired admission changed original identity, receipt history or cleanup ownership")
			}
			if (stage == "record" || stage == "end" || stage == "end-native-failure") && !owner.transition {
				t.Fatal("expired operation completed an undrained native transition")
			}
			if (stage == "identity" || stage == "record" || stage == "initialize") && owner.failureError() != nil {
				t.Fatal("pure read expiry changed the retained observer failure", owner.failureError())
			}
			if stage == "end" || stage == "end-native-failure" {
				if owner.failureError() == nil {
					t.Fatal("startup completion lost its original failure latching")
				}
			}
		})
	}
}

func TestNetworkCohortCallerNativeCallbacks(t *testing.T) {
	for _, stage := range []string{"begin", "end"} {
		t.Run(stage, func(t *testing.T) {
			owner, native := networkTestTracker(t, nil)
			if stage == "end" {
				if err := owner.Begin(context.Background(), nil); err != nil {
					t.Fatal(err)
				}
			}
			type callerKey struct{}
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), callerKey{}, stage), time.Second)
			defer cancel()
			entered := make(chan struct{})
			owner.native = &networkOperationNative{nativeObserver: native, snapshot: func(caller context.Context) (Snapshot, error) {
				if caller.Value(callerKey{}) != stage {
					return Snapshot{}, errors.New("native callback lost the actual comparison caller")
				}
				if deadline, ok := caller.Deadline(); !ok || deadline.After(time.Now().Add(time.Second)) {
					return Snapshot{}, errors.New("native callback lost bounded comparison deadline")
				}
				close(entered)
				<-caller.Done()
				return Snapshot{}, caller.Err()
			}}
			done := make(chan error, 1)
			go func() {
				if stage == "begin" {
					done <- owner.Begin(ctx, nil)
				} else {
					done <- owner.End(ctx, nil)
				}
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatal("native callback did not receive original caller", err)
			case <-time.After(time.Second):
				t.Fatal("native callback was not entered")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("native callback cancellation became a current candidate", err)
				}
			case <-time.After(time.Second):
				t.Fatal("native callback outlived its comparison caller")
			}
			if owner.failureError() == nil || len(owner.recorded) != 0 || owner.current != nil {
				t.Fatal("cancelled startup transition changed original rejection or receipt semantics")
			}
		})
	}
}

func TestNetworkCohortContextRetainsExactReceiptHistory(t *testing.T) {
	owner, native := networkTestTracker(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	identity, err := owner.IdentityContext(ctx)
	if err != nil || identity == "" {
		t.Fatal("original physical identity missing", err)
	}
	if err := owner.Begin(ctx, nil); err != nil {
		t.Fatal(err)
	}
	receipt := networkTestReceipt(11)
	networkTestEvents(owner, receipt, "add")
	if err := owner.RecordContext(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := owner.RecordContext(ctx, receipt); err != nil || len(owner.recorded) != 1 {
		t.Fatal("same exact receipt was duplicated", err)
	}
	native.set(networkTestWith(networkTestPhysical(), &receipt))
	if err := owner.End(ctx, &receipt); err != nil {
		t.Fatal(err)
	}
	if current, err := owner.IdentityContext(ctx); err != nil || current != identity || owner.CurrentContext(ctx) != nil {
		t.Fatal("owned transition replaced original physical cohort", err)
	}
	if err := owner.Begin(ctx, &receipt); err != nil {
		t.Fatal(err)
	}
	if err := owner.RecordContext(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	changed := receipt
	changed.MTU--
	if err := owner.RecordContext(ctx, changed); err == nil || owner.failureError() == nil {
		t.Fatal("same-incarnation replacement borrowed exact captured receipt")
	}
	if owner.CurrentContext(ctx) == nil {
		t.Fatal("replaced receipt recovered into a current physical cohort")
	}
}
