//go:build linux && routervpn_controller_privileged

package standardengine

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Executes the production worker and real captured FD11. Only the native
// backend is modeled so its original call can deliberately remain held.
func TestCleanupOperationWorkerStopRetainsUnjoinedNativeCall(t *testing.T) {
	for _, phase := range []string{"held", "within-budget"} {
		t.Run(phase, func(t *testing.T) {
			ctx, p, c := operationPair(t)
			original, next := &operationNativeReader{1}, &operationNativeReader{2}
			entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			tx := &operationNativeTransaction{next, [3]NativeMTUEvidence{{original, "original-ready", "original-retired", true, false}, {next, "candidate-ready", "", false, false}}}
			retries := 0
			backend := &operationNativeBackend{current: original, change: func(work context.Context, old any, mtu int) (NativeMTUTransaction, error) {
				if old != original || mtu != 1400 {
					t.Error("held native call changed its original capture")
				}
				close(entered)
				<-work.Done()
				close(cancelled)
				<-release
				return tx, errors.New("actual late native failure")
			}, retry: func(call context.Context, retained NativeMTUTransaction) error {
				if retained != tx {
					t.Error("Stop replaced actual late native transaction")
				}
				retries++
				return call.Err()
			}}
			worker, stop, done := operationStartWorker(t, ctx, c, backend, original)
			command := operationCommand(t, ctx, p, 1, InitialReaderBinding(p.capture, "original-ready"))
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			stop()
			select {
			case <-cancelled:
			case <-ctx.Done():
				t.Fatal("Stop did not revoke original work", ctx.Err())
			}
			timer := time.NewTimer(120 * time.Millisecond)
			select {
			case err := <-done:
				timer.Stop()
				if err != nil {
					t.Fatal("original supervisor did not hand off retained call", err)
				}
			case <-timer.C:
				close(release)
				released = true
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("held regression failed to join after release", ctx.Err())
				}
				t.Fatal("original Stop could not reach bounded FD10 join while native call was held")
			}
			if len(worker.units) != 1 || worker.units[0].completion == nil || worker.units[0].before != original || worker.current != original {
				t.Fatal("supervisor lost its exact outstanding native call")
			}
			retained := worker.units[0]
			completion := retained.completion
			if _, err := worker.CurrentReader(); err == nil {
				t.Fatal("unjoined current reader escaped Stop")
			}
			if err := worker.publish(ctx, retained); err == nil {
				t.Fatal("unjoined native result was published")
			}
			if _, err := p.ReadResult(ctx, command.Reservation); !errors.Is(err, ErrOperationPending) {
				t.Fatal("held native work invented a joined result", err)
			}
			if phase == "held" {
				bounded, end := context.WithTimeout(ctx, 25*time.Millisecond)
				err := worker.Retire(bounded)
				end()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("FD10 join ignored original caller deadline", err)
				}
				if retained.completion != completion || retained.transaction != nil || worker.current != original || retries != 0 {
					t.Fatal("expired Stop lost or retired original pending resources")
				}
				close(release)
				released = true
			} else {
				go func() { time.Sleep(10 * time.Millisecond); close(release) }()
				released = true
			}
			bounded, end := context.WithTimeout(ctx, time.Second)
			defer end()
			if err := worker.Retire(bounded); err != nil {
				t.Fatal("original Stop retry did not join exact late completion", err)
			}
			if retries != 1 || retained.transaction != tx || retained.completion != nil {
				t.Fatal("Stop lost actual late transaction or replayed native work")
			}
			current, err := worker.CurrentReader()
			if err != nil || current != next {
				t.Fatal("Stop adopted a replacement instead of actual returned reader", err)
			}
			result, err := p.ReadResult(ctx, command.Reservation)
			if err != nil || !result.WorkerJoined || !result.Failed || result.Pending || result.CurrentRole != CandidateReader {
				t.Fatal("Stop omitted actual joined native history", result, err)
			}
		})
	}
}
