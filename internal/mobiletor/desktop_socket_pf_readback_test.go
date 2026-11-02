//go:build go1.25

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
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		deadline, _ := ctx.Deadline()
		started := time.Now()
		var active, peak atomic.Int32
		var completed [10]atomic.Int32
		var checks [10]func(context.Context) error
		for index := range checks {
			checks[index] = func(captured context.Context) error {
				actual, found := captured.Deadline()
				if !found || !actual.Equal(deadline) {
					return errors.New("complete readback replaced its captured deadline")
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
					completed[index].Add(1)
					return nil
				case <-captured.Done():
					return captured.Err()
				}
			}
		}
		var global [6]func(context.Context) error
		copy(global[:], checks[:6])
		err := desktopPFCompleteReadback(ctx, global, checks[6], checks[7], checks[8], checks[9])
		var counts [10]int32
		for index := range counts {
			counts[index] = completed[index].Load()
		}
		// The old global group followed by four serial owner checks needs
		// 180 ms. One shared four-worker group completes all ten in 90 ms.
		if err != nil || counts != [10]int32{1, 1, 1, 1, 1, 1, 1, 1, 1, 1} || active.Load() != 0 || peak.Load() != 4 || time.Since(started) != 90*time.Millisecond {
			t.Fatal("PF complete readback lost its required owner checks or shared bounded budget", counts, active.Load(), peak.Load(), time.Since(started), err)
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
				var checks [10]func(context.Context) error
				for index := range checks {
					checks[index] = func(context.Context) error { return nil }
				}
				checks[6] = func(captured context.Context) error {
					close(entered)
					<-captured.Done()
					close(cancelled)
					<-cleanup
					retired.Store(true)
					return captured.Err()
				}
				if failure {
					checks[7] = func(context.Context) error {
						<-entered
						return want
					}
				}
				var global [6]func(context.Context) error
				copy(global[:], checks[:6])
				go func() { done <- desktopPFCompleteReadback(ctx, global, checks[6], checks[7], checks[8], checks[9]) }()
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
		global := [6]func(context.Context) error{check, check, check, check, check, check}
		if err := desktopPFCompleteReadback(ctx, global, check, check, check, check); !errors.Is(err, context.DeadlineExceeded) || complete.Load() != 4 {
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
	for missing := range 10 {
		var started atomic.Int32
		var checks [10]func(context.Context) error
		for index := range checks {
			checks[index] = func(context.Context) error {
				started.Add(1)
				return nil
			}
		}
		checks[missing] = nil
		var global [6]func(context.Context) error
		copy(global[:], checks[:6])
		if err := desktopPFCompleteReadback(context.Background(), global, checks[6], checks[7], checks[8], checks[9]); err == nil || started.Load() != 0 {
			t.Fatal("PF complete readback started without every required inspection", missing, started.Load(), err)
		}
	}
}
