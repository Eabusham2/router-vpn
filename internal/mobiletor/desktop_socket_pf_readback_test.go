//go:build go1.25

package mobiletor

import (
	"context"
	"errors"
	"strings"
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
	t.Run("probe-firewall-and-account-share-original-budget", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 140*time.Millisecond)
			defer cancel()
			deadline, _ := ctx.Deadline()
			budget := make(chan struct{}, 4)
			ctx = context.WithValue(ctx, desktopPFCommandBudgetKey{}, budget)
			started := time.Now()
			var active, peak atomic.Int32
			var completed [8]atomic.Int32
			command := func(index int) func(context.Context) error {
				return func(captured context.Context) error {
					actual, found := captured.Deadline()
					if !found || !actual.Equal(deadline) || captured.Value(desktopPFCommandBudgetKey{}) != budget {
						return errors.New("probe replaced its original deadline or native command slots")
					}
					release, err := desktopPFEnterCommand(captured)
					if err != nil {
						return err
					}
					defer release()
					current := active.Add(1)
					defer active.Add(-1)
					for previous := peak.Load(); current > previous; previous = peak.Load() {
						if peak.CompareAndSwap(previous, current) {
							break
						}
					}
					select {
					case <-captured.Done():
						return captured.Err()
					case <-time.After(40 * time.Millisecond):
						completed[index].Add(1)
						return nil
					}
				}
			}
			firewall := func(captured context.Context) error {
				return desktopPFReadback(captured, command(0), command(1), command(2), command(3), command(4), command(5))
			}
			account := func(captured context.Context) error {
				if err := command(6)(captured); err != nil {
					return err
				}
				return command(7)(captured)
			}
			err := desktopPFProbeReadback(ctx, firewall, account)
			var counts [8]int32
			for index := range counts {
				counts[index] = completed[index].Load()
			}
			// Serial PF then account reads require 160 ms. The two original
			// proofs must finish within 120 ms using only four shared slots.
			if err != nil || counts != [8]int32{1, 1, 1, 1, 1, 1, 1, 1} || active.Load() != 0 || peak.Load() != 4 || time.Since(started) > 120*time.Millisecond {
				t.Fatal("probe lost complete original firewall/account readback", counts, active.Load(), peak.Load(), time.Since(started), err)
			}
		})
	})
}

func TestDesktopPFReadbackFailureAndCancellationJoin(t *testing.T) {
	t.Run("probe-account-failure-joins-firewall", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			entered, firewallJoined := make(chan struct{}), make(chan struct{})
			// A deliberately broken production join must still leave this test's
			// admitted callbacks retired before the synctest bubble exits. Keep
			// the pre-cleanup observation below: fixture cleanup is not proof that
			// the production call joined its work before returning.
			defer func() {
				cancel()
				synctest.Wait()
				select {
				case <-entered:
					<-firewallJoined
				default:
				}
				synctest.Wait()
			}()
			want := errors.New("captured account was replaced")
			var retired atomic.Bool
			err := desktopPFProbeReadback(ctx, func(captured context.Context) error {
				defer close(firewallJoined)
				close(entered)
				<-captured.Done()
				time.Sleep(5 * time.Millisecond)
				retired.Store(true)
				return nil // Late native success cannot authorize this failed probe.
			}, func(captured context.Context) error {
				select {
				case <-entered:
					return want
				case <-captured.Done():
					return captured.Err()
				}
			})
			if !retired.Load() {
				t.Fatal("PF readback returned before its admitted native checks joined", err)
			}
			if !errors.Is(err, want) {
				t.Fatal("probe discarded failed identity or unjoined firewall readback", err)
			}
		})
	})
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
					checks[7] = func(captured context.Context) error {
						select {
						case <-entered:
							return want
						case <-captured.Done():
							return captured.Err()
						}
					}
				}
				var global [6]func(context.Context) error
				copy(global[:], checks[:6])
				go func() { done <- desktopPFCompleteReadback(ctx, global, checks[6], checks[7], checks[8], checks[9]) }()
				// A broken missing join may return and cancel its workers before
				// this captured owner check starts. Observe that same violation
				// here instead of waiting forever for a skipped callback. The
				// deferred cleanup still retires every admitted fixture worker.
				select {
				case <-entered:
				case err := <-done:
					t.Fatal("PF readback returned before its admitted native checks joined", err)
				}
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
				err := <-done
				if !errors.Is(err, want) || !retired.Load() {
					t.Fatal("PF readback discarded its exact failure or cancellation cleanup", err)
				}
				var observed *desktopPFReadbackFailure
				if !errors.As(err, &observed) || len(observed.checks) != 10 || observed.checks[6].state != 3 {
					t.Fatal("PF failure diagnostics lost the actually joined native check", err)
				}
				for _, check := range observed.checks {
					if check.state == 2 || check.queue < 0 || check.run < 0 {
						t.Fatal("PF failure diagnostics reported unjoined or invalid native timing", check)
					}
				}
			})
		})
	}
	t.Run("queued-failure-timings", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			want := errors.New("fixture native policy failure")
			var checks [10]func(context.Context) error
			for index := range checks {
				checks[index] = func(captured context.Context) error {
					select {
					case <-time.After(30 * time.Millisecond):
						if index == 5 {
							return want
						}
						return nil
					case <-captured.Done():
						return captured.Err()
					}
				}
			}
			var global [6]func(context.Context) error
			copy(global[:], checks[:6])
			err := desktopPFCompleteReadback(ctx, global, checks[6], checks[7], checks[8], checks[9])
			var observed *desktopPFReadbackFailure
			if !errors.Is(err, want) || !errors.As(err, &observed) || len(observed.checks) != 10 {
				t.Fatal("failure diagnostics replaced the original native refusal", err)
			}
			if observed.elapsed != 60*time.Millisecond || observed.checks[5].state != 3 || observed.checks[5].queue != 30*time.Millisecond || observed.checks[5].run != 30*time.Millisecond {
				t.Fatal("failure diagnostics confused queue/native/join durations", observed.elapsed, observed.checks)
			}
			if !strings.Contains(err.Error(), "check=5 state=3 queue_us=30000 run_us=30000") || len(err.Error()) > 4096 {
				t.Fatal("failure timing output lost its bounded numeric shape", err)
			}
		})
	})
	t.Run("grant-phase-and-original-budget", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			originalDeadline, _ := ctx.Deadline()
			time.Sleep(75 * time.Millisecond) // Existing native socket/interface prerequisites.
			progress := desktopPFStartGrant(ctx)
			for index, delay := range []time.Duration{300 * time.Millisecond, 100 * time.Millisecond} {
				if err := progress.run(uint8(index+1), func() error {
					if deadline, _ := ctx.Deadline(); deadline != originalDeadline {
						t.Fatal("diagnostics replaced original native deadline")
					}
					time.Sleep(delay)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			err := progress.run(3, func() error { <-ctx.Done(); return ctx.Err() })
			err = progress.failure(err)
			var observed *desktopPFGrantFailure
			if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &observed) || !observed.progress.deadline || observed.progress.phase != 3 ||
				observed.progress.remaining != 1925*time.Millisecond || observed.elapsed != 1925*time.Millisecond ||
				observed.progress.durations != [3]time.Duration{300 * time.Millisecond, 100 * time.Millisecond, 1525 * time.Millisecond} {
				t.Fatal("grant diagnostic lost its original budget, failed phase or elapsed work", err)
			}
			if progress.failure(nil) != nil || !strings.Contains(err.Error(), "entry_remaining_us=1925000") || len(err.Error()) > 1024 {
				t.Fatal("grant diagnostics fabricated a failure or exceeded numeric output bounds", err)
			}
			withoutDeadline := desktopPFStartGrant(context.Background())
			if withoutDeadline.deadline || withoutDeadline.remaining != 0 || withoutDeadline.failure(nil) != nil {
				t.Fatal("diagnostic created a deadline or success output")
			}
		})
	})
	t.Run("numeric-child-progress-keeps-cause", func(t *testing.T) {
		want := errors.New("fixture native policy failure")
		for command := 0; command <= 5; command++ {
			progress := desktopPFChildrenProgress{listed: true, children: 3, child: 2, verified: 1, command: command, attempted: 7, completed: 6}
			err := progress.failure(want)
			var observed *desktopPFChildrenFailure
			if !errors.Is(err, want) || !errors.As(err, &observed) || observed.progress != progress || len(err.Error()) > 512 {
				t.Fatal("system-child diagnostics changed original failure or numeric progress", err)
			}
			progress.children = 900
			if observed.progress.children != 3 || progress.failure(nil) != nil {
				t.Fatal("failure diagnostic retained mutable progress or emitted success output")
			}
		}
	})

}

func TestDesktopPFReadbackDeadlineAndInvalidCapture(t *testing.T) {
	for missing := range 2 {
		started := 0
		checks := [2]func(context.Context) error{
			func(context.Context) error { started++; return nil },
			func(context.Context) error { started++; return nil },
		}
		checks[missing] = nil
		if err := desktopPFProbeReadback(context.Background(), checks[0], checks[1]); err == nil || started != 0 {
			t.Fatal("probe started without both firewall and identity proof", missing, started, err)
		}
	}
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
