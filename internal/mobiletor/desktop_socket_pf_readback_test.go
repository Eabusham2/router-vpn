package mobiletor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestDesktopPFReadbackCompleteWithinCapturedBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		deadline, _ := ctx.Deadline()
		started := time.Now()
		var active, peak, complete atomic.Int32
		checks := make([]func(context.Context) error, 6)
		for index := range checks {
			checks[index] = func(captured context.Context) error {
				actual, found := captured.Deadline()
				if !found || !actual.Equal(deadline) {
					return errors.New("readback replaced its captured deadline")
				}
				current := active.Add(1)
				defer active.Add(-1)
				for previous := peak.Load(); current > previous; previous = peak.Load() {
					if peak.CompareAndSwap(previous, current) {
						break
					}
				}
				select {
				case <-time.After(30 * time.Millisecond):
					complete.Add(1)
					return nil
				case <-captured.Done():
					return captured.Err()
				}
			}
		}
		if err := desktopPFReadback(ctx, checks...); err != nil || complete.Load() != 6 || active.Load() != 0 || peak.Load() != 4 || time.Since(started) != 60*time.Millisecond {
			t.Fatal("PF readback lost complete bounded parallel proof under its original deadline", complete.Load(), active.Load(), peak.Load(), time.Since(started), err)
		}
	})
}

func TestDesktopPFReadbackFailureAndCancellationJoin(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller-cancel", true: "native-failure"}[failure], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				entered, cleanup := make(chan struct{}), make(chan struct{})
				cleanupClosed := false
				defer func() {
					if !cleanupClosed {
						close(cleanup)
					}
				}()
				cancelled, done := make(chan struct{}), make(chan error, 1)
				want := errors.New("captured native readback failed")
				var retired atomic.Bool
				checks := []func(context.Context) error{func(captured context.Context) error {
					close(entered)
					<-captured.Done()
					close(cancelled)
					<-cleanup
					retired.Store(true)
					return captured.Err()
				}}
				if failure {
					checks = append(checks, func(context.Context) error {
						<-entered
						return want
					})
				}
				go func() { done <- desktopPFReadback(ctx, checks...) }()
				<-entered
				if !failure {
					cancel()
					want = context.Canceled
				}
				<-cancelled
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatal("PF readback returned before its admitted native checks joined", err)
				default:
				}
				close(cleanup)
				cleanupClosed = true
				if err := <-done; !errors.Is(err, want) || !retired.Load() {
					t.Fatal("PF readback discarded its exact failure or cancellation cleanup", err)
				}
			})
		})
	}
}

func TestDesktopPFReadbackDeadlineAndInvalidCapture(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		var complete atomic.Int32
		check := func(captured context.Context) error {
			<-captured.Done()
			complete.Add(1)
			return nil // A stale native success still cannot become proof.
		}
		if err := desktopPFReadback(ctx, check, check, check, check); !errors.Is(err, context.DeadlineExceeded) || complete.Load() != 4 {
			t.Fatal("PF readback accepted a stale deadline or lost admitted cleanup", complete.Load(), err)
		}
		if err := desktopPFReadback(ctx, func(context.Context) error {
			t.Fatal("cancelled PF capture started a native inspection")
			return nil
		}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("PF readback lost its preexisting deadline", err)
		}
	})
	for _, checks := range [][]func(context.Context) error{nil, {nil}, make([]func(context.Context) error, 33)} {
		if err := desktopPFReadback(context.Background(), checks...); err == nil {
			t.Fatal("PF readback accepted an absent or unbounded inspection")
		}
	}
	if err := desktopPFReadback(nil, func(context.Context) error { return nil }); err == nil {
		t.Fatal("PF readback accepted an absent operation context")
	}
}
