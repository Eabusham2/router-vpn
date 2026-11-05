//go:build linux || windows || darwin

package desktopnetwork

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Native locks are exercised without replacing their shipping methods or
// opening another subscription. Cancellation must happen before descriptor use.
func TestNetworkNativeObservationHeldMutex(t *testing.T) {
	native, mu, lockedSnapshot := networkContextNativeObserver()
	checks := map[string]func(context.Context) error{"barrier": native.Barrier}
	if lockedSnapshot {
		delete(checks, "barrier")
		checks["snapshot"] = func(ctx context.Context) error { _, err := native.Snapshot(ctx); return err }
	}
	for name, read := range checks {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			mu.Lock()
			done := make(chan error, 1)
			go func() { done <- read(ctx) }()
			select {
			case err := <-done:
				mu.Unlock()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("native observation lost original deadline", err)
				}
			case <-time.After(time.Second):
				mu.Unlock()
				<-done
				t.Fatal("native observation waited for retained observer mutex")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := native.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("snapshot replaced original cancellation", err)
	}
	if err := native.Barrier(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("barrier replaced original cancellation", err)
	}
}
