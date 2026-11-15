package main

import (
	"context"
	"errors"

	"router-vpn/internal/mobilemtu"
)

// Terminal controller retirement only: ordinary measurement holds and
// Disconnect/restoration retain their existing ability to resume Auto. The
// receipt includes workers still capturing source, before an MTU view exists.
// Keep the retired owner registered so a delayed hold-release cannot recreate
// work after this join, including when there was no worker at retirement.
func retireRouterNodeAutomaticMTUContext(ctx context.Context, a *app) error {
	if ctx == nil || a == nil {
		return errors.New("automatic MTU retirement has no original owner")
	}
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	closing := a.controllerClosingLocked()
	a.mu.Unlock()
	if !closing {
		return errors.New("automatic MTU retirement requires terminal controller shutdown")
	}
	raw, _ := routerNodeAutomaticMTUs.LoadOrStore(a, &routerNodeAutomaticMTU{})
	owner := raw.(*routerNodeAutomaticMTU)
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return err
	}
	if !owner.retired {
		owner.retired, owner.resume = true, false
		if owner.cancel != nil {
			owner.cancel()
		}
		owner.joined = make(chan struct{})
		if owner.workers == 0 {
			close(owner.joined)
		}
	}
	joined := owner.joined
	owner.mu.Unlock()
	cancelCapturedMTU(a)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-joined:
		return ctx.Err()
	}
}

func (owner *routerNodeAutomaticMTU) workerJoined() {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.workers--
	if owner.retired && owner.workers == 0 {
		close(owner.joined)
	}
}

// Caller holds owner.mu and has checked the terminal latch. All command
// generations share this controller lifetime, while each keeps its own join.
func (owner *routerNodeAutomaticMTU) workerStartedLocked() context.Context {
	if owner.context == nil {
		owner.context, owner.cancel = context.WithCancel(context.Background())
	}
	owner.workers++
	return owner.context
}
