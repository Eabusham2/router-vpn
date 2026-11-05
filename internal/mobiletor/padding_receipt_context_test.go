package mobiletor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPaddingNativeReceiptContextPreservesOwnerOnObserverExpiry(t *testing.T) {
	for _, boundary := range []string{"lease-lock", "owner-observation", "proof-observation", "success"} {
		t.Run(boundary, func(t *testing.T) {
			peer := newPaddingLeasePeer(t)
			until := time.Now().Add(PaddingProofMaxAge)
			var retired atomic.Bool
			options := paddingLeaseOptions(until, func(error) { retired.Store(true) })
			options.Observe = func(ctx context.Context) error {
				if boundary == "owner-observation" {
					<-ctx.Done()
				}
				return ctx.Err()
			}
			options.ObserveProofUntil = func(ctx context.Context) (time.Time, error) {
				if boundary == "proof-observation" {
					<-ctx.Done()
				}
				return until, ctx.Err()
			}
			lease, err := NewPaddingLease(t.Context(), peer.control, options)
			if err != nil {
				t.Fatal(err)
			}
			defer joinPaddingLeaseTest(lease)
			if err := lease.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			if boundary == "lease-lock" {
				lease.mu.Lock()
			}
			done := make(chan error, 1)
			go func() {
				receipt, err := lease.NativeReceiptContext(ctx)
				if err == nil && (receipt == nil || receipt.ChannelCells == 0) {
					err = errors.New("lost actual native receipt")
				}
				done <- err
			}()
			select {
			case err = <-done:
			case <-time.After(time.Second):
				if boundary == "lease-lock" {
					lease.mu.Unlock()
				}
				t.Fatal("receipt observation escaped its caller's deadline")
			}
			if boundary == "lease-lock" {
				lease.mu.Unlock()
			}
			if boundary == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("lost caller expiry: %v", err)
			}
			if retired.Load() || !lease.Healthy() {
				t.Fatal("mere receipt observer expiry retired healthy native lease")
			}
		})
	}
}
