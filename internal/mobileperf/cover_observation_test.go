package mobileperf

import (
	"context"
	"errors"
	"testing"
	"time"
)

type observedCoverEngine struct {
	*fakeCoverEngine
	observe func(context.Context) (string, error)
}

func (e *observedCoverEngine) IdentityContext(ctx context.Context) (string, error) {
	return e.observe(ctx)
}
func TestCoverObservationCancellationPreservesWorker(t *testing.T) {
	for _, held := range []string{"worker", "engine"} {
		t.Run(held, func(t *testing.T) {
			engine := &observedCoverEngine{fakeCoverEngine: &fakeCoverEngine{}}
			engine.identity.Store(1)
			engine.observe = func(ctx context.Context) (string, error) { return engine.Identity(), ctx.Err() }
			worker := &Cover{engine: engine, activeCtx: context.Background(), identity: engine.Identity(), lastReply: time.Now(), running: true, status: CoverStatus{Active: true}, generation: 7}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if held == "worker" {
				worker.mu.Lock()
			} else {
				engine.observe = func(ctx context.Context) (string, error) { cancel(); return "", ctx.Err() }
			}
			done := make(chan error, 1)
			go func() { done <- worker.HealthyContext(ctx) }()
			if held == "worker" {
				cancel()
			}
			select {
			case err := <-done:
				if held == "worker" {
					worker.mu.Unlock()
				}
				if !errors.Is(err, context.Canceled) {
					t.Fatal("caller cancellation lost", err)
				}
			case <-time.After(time.Second):
				if held == "worker" {
					worker.mu.Unlock()
				}
				<-done
				t.Fatal("cover observation waited after cancellation")
			}
			engine.observe = func(ctx context.Context) (string, error) { return engine.Identity(), ctx.Err() }
			if err := worker.HealthyContext(context.Background()); err != nil || worker.closed || worker.generation != 7 {
				t.Fatal("cancelled observer damaged healthy cover", err)
			}
			engine.identity.Store(2)
			if err := worker.HealthyContext(context.Background()); err == nil {
				t.Fatal("changed real cover identity accepted")
			}
		})
	}
}
