package main

import (
	"context"
	"errors"

	"router-vpn/internal/desktopnetwork"
)

// The HTTP intent may be shorter than the original connection transaction.
// Keep both original identities; a later registry read cannot replace either.
type desktopTorCaller struct {
	operation context.Context
	intent    context.Context
	work      context.Context
	selected  string
	finish    context.CancelFunc
}

func captureDesktopTorCaller(a *app, operation, intent context.Context) (*desktopTorCaller, error) {
	if a == nil {
		return nil, errors.New("Tor caller has no original application")
	}
	admission := intent
	var finish context.CancelFunc
	if operation != nil {
		var err error
		admission, finish, err = desktopTorChoiceCaller(operation, intent)
		if err != nil {
			return nil, err
		}
	}
	if admission == nil {
		admission = context.Background() // compatibility for an already-owned legacy caller
	}
	if err := desktopnetwork.LockContext(admission, &a.mu); err != nil {
		if finish != nil {
			finish()
		}
		return nil, err
	}
	if operation == nil {
		operation = a.connectionContext
	}
	selected := a.profiles.SelectedID
	err := errors.Join(desktopTorOperationCurrentLocked(a, operation, selected), admission.Err())
	a.mu.Unlock()
	if err != nil {
		if finish != nil {
			finish()
		}
		return nil, err
	}
	if finish == nil {
		admission, finish, err = desktopTorChoiceCaller(operation, intent)
		if err != nil {
			return nil, err
		}
	}
	return &desktopTorCaller{operation: operation, intent: intent, work: admission, selected: selected, finish: finish}, nil
}

func (caller *desktopTorCaller) currentContext(ctx context.Context, a *app) error {
	if caller == nil || caller.operation == nil || caller.work == nil || ctx == nil {
		return errors.New("Tor admission lost its original caller")
	}
	if err := errors.Join(ctx.Err(), caller.work.Err(), caller.operation.Err()); err != nil {
		return err
	}
	ctx, finish, err := desktopTorChoiceCaller(caller.work, ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	return errors.Join(desktopTorOperationCurrentLocked(a, caller.operation, caller.selected), ctx.Err(), caller.work.Err())
}

func desktopTorPreparationCallerCurrent(ctx context.Context, a *app, driver desktopTorConnectRuntime) error {
	if ctx == nil || a == nil {
		return errors.New("Tor preparation lost its original caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if driver.requestContext != nil && driver.requestContext.Err() != nil {
		return driver.requestContext.Err()
	}
	if driver.operation != nil {
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return err
		}
		err := a.checkCapturedConnectionOperationLocked(driver.operation)
		if a.connectionCancelIntent == driver.operation {
			err = errConnectionOperationCancelled
		}
		a.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}
