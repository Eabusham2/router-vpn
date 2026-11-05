package desktopnetwork

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNetworkRetainedLifetimeKeepsOriginalOperationBudget(t *testing.T) {
	owner, native := networkTestTracker(t, nil)
	first, finish := context.WithCancel(context.Background())
	if err := owner.CurrentContext(first); err != nil {
		t.Fatal(err)
	}
	finish()
	if err := owner.Current(); err != nil {
		t.Fatal("finished observation cancelled independently retained lifetime", err)
	}
	operation, cancel := context.WithCancel(context.Background())
	native.mu.Lock()
	native.barrier = cancel
	native.mu.Unlock()
	if err := owner.CurrentContext(operation); !errors.Is(err, context.Canceled) {
		t.Fatal("original request cancellation during native barrier became success")
	}
	if err := owner.Current(); err != nil {
		t.Fatal("pure observation expiry poisoned retained healthy owner", err)
	}
}

func TestNetworkInitializationCannotAdoptCancelledCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	native := &networkFakeNative{snapshot: networkTestPhysical(), barrier: cancel}
	owner := &Tracker{ctx: context.Background(), native: native, initializing: true}
	if err := owner.initialize(ctx); err == nil || !owner.initializing {
		t.Fatal("retained lifetime borrowed cancelled startup acceptance", err)
	}
	if err := owner.Current(); err == nil {
		t.Fatal("failed initialization produced a current receipt")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkStartupTransitionKeepsOriginalOperationBudget(t *testing.T) {
	for _, stage := range []string{"begin", "end"} {
		t.Run(stage, func(t *testing.T) {
			owner, native := networkTestTracker(t, nil)
			ctx, cancel := context.WithCancel(context.Background())
			if stage == "end" {
				if err := owner.Begin(ctx, nil); err != nil {
					t.Fatal(err)
				}
			}
			native.mu.Lock()
			native.barrier = cancel
			native.mu.Unlock()
			var err error
			if stage == "begin" {
				err = owner.Begin(ctx, nil)
			} else {
				err = owner.End(ctx, nil)
			}
			if err == nil {
				t.Fatal("native startup transition adopted a cancelled original caller")
			}
			if err := owner.Current(); err == nil {
				t.Fatal("cancelled startup transition recovered into a current epoch")
			}
		})
	}
}

func TestNetworkObservationExpiryPreservesRealFailures(t *testing.T) {
	for _, stage := range []string{"event", "continuity", "identity", "joined-native"} {
		t.Run(stage, func(t *testing.T) {
			owner, native := networkTestTracker(t, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			nativeErr := errors.New("original native inventory lost")
			if stage == "identity" {
				changed := networkTestPhysical()
				changed.Links[0].MTU--
				native.set(changed)
			}
			native.barrier = func() {
				switch stage {
				case "event":
					owner.observe(Event{Kind: "link", Action: "change", Index: 1, Name: "original"}, nil)
				case "continuity":
					owner.observe(Event{}, nativeErr)
				}
				cancel()
			}
			if stage == "joined-native" {
				owner.native = &networkOperationNative{nativeObserver: native, snapshot: func(context.Context) (Snapshot, error) {
					owner.mu.Lock()
					cancel()
					return Snapshot{}, errors.Join(nativeErr, ctx.Err())
				}}
			}
			done := make(chan error, 1)
			go func() { done <- owner.CurrentContext(ctx) }()
			var err error
			select {
			case err = <-done:
			case <-time.After(time.Second):
				if stage == "joined-native" {
					owner.mu.Unlock()
					<-done
				}
				t.Fatal("expired observation waited to record original native failure")
			}
			if stage == "joined-native" {
				owner.mu.Unlock()
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("original cancellation cause lost: %v", err)
			}
			if owner.failureError() == nil {
				t.Fatal("real native failure vanished behind observation cancellation")
			}
			if stage == "joined-native" && !errors.Is(err, nativeErr) {
				t.Fatal("joined native cause lost", err)
			}
			native.set(networkTestPhysical())
			owner.native = native
			if err := owner.Current(); err == nil {
				t.Fatal("later observation accepted an invalidated original owner")
			}
		})
	}
}

type networkOperationNative struct {
	nativeObserver
	snapshot func(context.Context) (Snapshot, error)
}

func (n *networkOperationNative) Snapshot(ctx context.Context) (Snapshot, error) {
	return n.snapshot(ctx)
}

func TestNetworkObservationHeldMutexKeepsCaller(t *testing.T) {
	for _, stage := range []string{"entry", "completion", "failure-report"} {
		t.Run(stage, func(t *testing.T) {
			owner, native := networkTestTracker(t, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			held := make(chan struct{})
			if stage == "entry" {
				owner.mu.Lock()
				close(held)
			} else {
				native.barrier = func() {
					if stage == "failure-report" {
						owner.observe(Event{}, errors.New("original event continuity lost"))
					}
					owner.mu.Lock()
					close(held)
				}
			}
			done := make(chan error, 1)
			go func() { done <- owner.CurrentContext(ctx) }()
			<-held
			select {
			case err := <-done:
				owner.mu.Unlock()
				if stage != "failure-report" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("held mutex lost original deadline", err)
				}
				if stage == "failure-report" && err == nil {
					t.Fatal("lost genuine native failure")
				}
			case <-time.After(time.Second):
				owner.mu.Unlock()
				<-done
				t.Fatal("expired observation waited for tracker mutex or failure report")
			}
			err := owner.Current()
			if stage == "failure-report" && err == nil {
				t.Fatal("original native failure was cleared")
			}
			if stage != "failure-report" && err != nil {
				t.Fatal("mutex timeout poisoned healthy owner", err)
			}
		})
	}
}
