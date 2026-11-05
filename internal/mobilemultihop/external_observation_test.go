package mobilemultihop

import (
	"context"
	"errors"
	"testing"
	"time"
)

type observedExternalProof struct {
	*externalProofFixture
	observe func(context.Context) (string, error)
}

func (e *observedExternalProof) IdentityContext(ctx context.Context) (string, error) {
	return e.observe(ctx)
}
func TestExternalObservationExpiryRetainsOriginalProof(t *testing.T) {
	for _, stage := range []string{"before", "entered", "changed", "changed-with-cancel"} {
		t.Run(stage, func(t *testing.T) {
			request, engine, _ := externalRequestFixture(t, "")
			if _, err := request.Run(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observed := &observedExternalProof{externalProofFixture: engine, observe: func(ctx context.Context) (string, error) {
				if err := ctx.Err(); err != nil {
					return "", err
				}
				return engine.Identity(), nil
			}}
			request.engine = observed
			if stage == "before" {
				cancel()
			}
			if stage == "entered" {
				observed.observe = func(ctx context.Context) (string, error) { cancel(); return "", ctx.Err() }
			}
			if stage == "changed" {
				engine.current.Store(false)
			}
			if stage == "changed-with-cancel" {
				observed.observe = func(ctx context.Context) (string, error) {
					cancel()
					return "", errors.Join(ctx.Err(), errors.New("observed another native owner"))
				}
			}
			err := request.VerifyCurrentPathContext(ctx)
			if stage == "changed" || stage == "changed-with-cancel" {
				if err == nil || request.succeeded.Load() || request.ctx.Err() == nil {
					t.Fatal("actual graph loss retained proof authority", err)
				}
				return
			}
			if !errors.Is(err, context.Canceled) || !request.succeeded.Load() || request.ctx.Err() != nil {
				t.Fatal("expired observation retired healthy original proof", err)
			}
			observed.observe = func(ctx context.Context) (string, error) { return engine.Identity(), ctx.Err() }
			if err := request.HealthyContext(context.Background()); err != nil {
				t.Fatal("healthy proof could not be observed after cancelled read", err)
			}
		})
	}
}

type observedExecution struct{ *externalExecutionEngine }

func (e *observedExecution) IdentityContext(ctx context.Context) (string, error) {
	if err := externalObservationLock(ctx, &e.mu); err != nil {
		return "", err
	}
	defer e.mu.Unlock()
	return e.identity, ctx.Err()
}
func (e *observedExecution) SelectedContext(ctx context.Context) (string, error) {
	if err := externalObservationLock(ctx, &e.mu); err != nil {
		return "", err
	}
	defer e.mu.Unlock()
	return e.selected, ctx.Err()
}
func TestExternalExecutionObservationKeepsOriginalLockBudget(t *testing.T) {
	for _, held := range []string{"controller", "engine"} {
		t.Run(held, func(t *testing.T) {
			engine := &observedExecution{&externalExecutionEngine{identity: "original", selected: LocalTag}}
			c := &Controller{engine: engine, engineID: "original", progress: Progress{Complete: true, Stage: "selected", Execution: "local"}}
			c.generation.Store(1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mu := &c.mu
			if held == "engine" {
				mu = &engine.mu
			}
			mu.Lock()
			done := make(chan error, 1)
			go func() { done <- c.HealthyContext(ctx) }()
			cancel()
			select {
			case err := <-done:
				mu.Unlock()
				if !errors.Is(err, context.Canceled) {
					t.Fatal("original lock cancellation lost", err)
				}
			case <-time.After(time.Second):
				mu.Unlock()
				<-done
				t.Fatal("cancelled execution observation waited on owned lock")
			}
			if c.generation.Load() != 1 {
				t.Fatal("expired read revoked healthy execution")
			}
			if err := c.HealthyContext(context.Background()); err != nil {
				t.Fatal("healthy execution damaged", err)
			}
		})
	}
}
