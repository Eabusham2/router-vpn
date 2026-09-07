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
	if err := context.Cause(parent); err != nil {
		return nil, nil, err
	}
	if validate == nil {
		return nil, nil, errors.New("Speed Lab path validation is required")
	}
	if err := validate(); err != nil {
		return nil, nil, err
	}
	if err := context.Cause(parent); err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithCancelCause(parent)
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
				if err := validate(); err != nil {
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
