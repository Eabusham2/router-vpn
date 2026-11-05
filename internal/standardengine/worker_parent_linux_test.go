//go:build linux && routervpn_controller_privileged

package standardengine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// The real FD11 remains idle. Losing its original parent must not require a
// new command, while a bounded observation timeout supplies no death evidence.
func TestCleanupOperationIdleOriginalParent(t *testing.T) {
	for _, name := range []string{"live", "lost", "expired", "mixed", "held-command-lock"} {
		t.Run(name, func(t *testing.T) {
			ctx, parent, child := operationPair(t)
			original := &operationNativeReader{1}
			lost := errors.New("actual original parent lost")
			var observations atomic.Int32
			entered := make(chan struct{}, 1)
			guard := func(observe context.Context) error {
				call := observations.Add(1)
				select {
				case entered <- struct{}{}:
				default:
				}
				if name == "expired" || name == "mixed" {
					if call == 1 {
						<-observe.Done()
						if name == "mixed" {
							return errors.Join(observe.Err(), lost)
						}
						return observe.Err()
					}
				}
				if name == "lost" || name == "held-command-lock" || name == "expired" && call > 1 {
					return lost
				}
				return observe.Err()
			}
			backend := &operationNativeBackend{current: original, change: func(context.Context, any, int) (NativeMTUTransaction, error) {
				t.Error("idle parent observation admitted native work")
				return nil, lost
			}}
			worker, err := NewNativeMTUWorker(child, backend, original, "original-ready", guard,
				func(ctx context.Context, _ time.Duration) (context.Context, context.CancelFunc, error) {
					work, cancel := context.WithCancel(ctx)
					return work, cancel, nil
				})
			if err != nil {
				t.Fatal(err)
			}
			if name == "held-command-lock" {
				unlock, err := parent.lock(ctx, false)
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
			}
			lifetime, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- worker.Run(lifetime) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("idle supervisor never observed original parent", ctx.Err())
			}
			if name == "live" {
				select {
				case err := <-done:
					t.Fatal("live original parent retired", err)
				case <-time.After(60 * time.Millisecond):
				}
				cancel()
			}
			select {
			case err := <-done:
				if name == "live" && err != nil || name != "live" && !errors.Is(err, lost) {
					t.Fatal("idle parent outcome lost original evidence", err)
				}
			case <-ctx.Done():
				t.Fatal("idle original parent loss did not reach retirement", ctx.Err())
			}
			if name == "expired" && observations.Load() < 2 {
				t.Fatal("pure observation expiry became parent death")
			}
			if len(worker.units) != 0 || worker.current != original || worker.lastSequence != 0 {
				t.Fatal("idle observation changed original reader or admission")
			}
			if err := worker.Retire(ctx); err != nil {
				t.Fatal("joined idle worker did not retain original retirement", err)
			}
		})
	}
}
