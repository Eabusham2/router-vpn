//go:build linux && go1.25

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProfileProtectionLinuxAdmissionPreservesExpiredCaller(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		want := error(context.Canceled)
		if deadline {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		a := &app{}
		err := a.guardPlatformProtectionOffPendingContext(ctx)
		cancel()
		if !errors.Is(err, want) {
			t.Fatal("protection admission replaced the original expired caller", err, want)
		}
	}
	if err := (&app{}).guardPlatformProtectionOffPendingContext(nil); err == nil {
		t.Fatal("protection admission accepted a missing original caller")
	}
}

func TestProfileProtectionLinuxAdmissionPreservesCancellationDuringCapture(t *testing.T) {
	a := &app{}
	release := measurementHeldLock(&a.mu)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	caller := &measurementAdmissionWaitingContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- a.guardPlatformProtectionOffPendingContext(caller) }()
	select {
	case <-caller.waiting:
	case <-time.After(time.Second):
		cancel()
		release()
		<-done
		t.Fatal("protection capture never waited on its original owner")
	}
	cancel()
	if err := measurementContextResult(t, done, release); !errors.Is(err, context.Canceled) {
		t.Fatal("protection capture discarded cancellation while refusing admission", err)
	}
	if a.mu.TryLock() {
		a.mu.Unlock()
		t.Fatal("cancelled protection capture released another owner's lock")
	}
	release()
	if !a.mu.TryLock() {
		t.Fatal("cancelled protection capture left an unjoined lock owner")
	}
	a.mu.Unlock()
}
