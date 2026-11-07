package main

import (
	"context"
	"errors"
	"time"
)

const speedLabPathCheckInterval = 50 * time.Millisecond

// speedLabPathContext rejects stale paths before any request starts and cancels
// in-flight HTTP work when the observed session/graph changes. This context owns
// only measurement requests: stopping a test must never disconnect the VPN.
func speedLabPathContext(parent context.Context, validate func() error) (context.Context, func(), error) {
	// Compatibility only: an already-entered legacy callback is joined even
	// after cancellation. Shipping contextual observers use WithCaller below.
	if validate == nil {
		return nil, nil, errors.New("Speed Lab path validation is required")
	}
	return speedLabPathContextWithCaller(parent, func(context.Context) error { return validate() })
}

func speedLabPathContextWithCaller(parent context.Context, validate func(context.Context) error) (context.Context, func(), error) {
	if parent == nil {
		return nil, nil, errors.New("Speed Lab path observation has no original caller")
	}
	if err := context.Cause(parent); err != nil {
		return nil, nil, err
	}
	if validate == nil {
		return nil, nil, errors.New("Speed Lab path validation is required")
	}
	ctx, cancel := context.WithCancelCause(parent)
	if err := validate(ctx); err != nil {
		cancel(err)
		return nil, nil, err
	}
	if err := context.Cause(parent); err != nil {
		cancel(err)
		return nil, nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(speedLabPathCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() != nil {
					return
				}
				if err := validate(ctx); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()

	// Join the observer before the caller restores a temporary path or releases
	// its transaction. No old validation callback may outlive that ownership.
	stop := func() {
		cancel(context.Canceled)
		<-done
	}
	return ctx, stop, nil
}

func speedLabPathResultError(ctx context.Context, err error) error {
	return errors.Join(err, context.Cause(ctx))
}
