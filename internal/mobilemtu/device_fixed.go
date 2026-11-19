package mobilemtu

import (
	"context"
	"errors"
)

// ApplyDeviceFixedContext applies a single device preference revision to this
// fresh native session. It changes only the original owned system TUN. Unlike
// Auto and Retest, it never compares candidates or writes measured history.
func (c *Controller) ApplyDeviceFixedContext(ctx context.Context, revision string, mtu int) error {
	if mtu < MinMTU || mtu > MaxMTU {
		return errors.New("fixed device MTU is outside the supported range")
	}
	op, err := c.beginOperation(ctx, ctx, revision, true, nil, nil, mtu)
	if err != nil {
		return err
	}
	return c.execute(op, false)
}

// StartDeviceFixedContext reserves the operation before the native activity
// gate is released. Work uses the original session's bounded lifetime.
func (c *Controller) StartDeviceFixedContext(admission, parent context.Context, revision string, mtu int) (func() error, error) {
	if mtu < MinMTU || mtu > MaxMTU {
		return nil, errors.New("fixed device MTU is outside the supported range")
	}
	op, err := c.beginOperation(admission, parent, revision, true, nil, nil, mtu)
	if err != nil {
		return nil, err
	}
	return c.executeDeviceFixed(op), nil
}

// StartDeviceFixedContextWithCleanupProvider preserves the retained native
// run's work/cleanup clocks and finalizer. Release the admission lock before
// waiting for the result. The returned function joins this exact generation.
func (c *Controller) StartDeviceFixedContextWithCleanupProvider(admission, operationParent context.Context, revision string, mtu int, provider CleanupDeadlineProvider, admit func(context.Context) error, finalize ...func(context.Context) error) (func() error, error) {
	if mtu < MinMTU || mtu > MaxMTU || provider == nil || admit == nil || len(finalize) > 1 || len(finalize) == 1 && finalize[0] == nil {
		return nil, errors.New("fixed device MTU requires its original bounded admission and cleanup")
	}
	op, err := c.beginOperation(admission, operationParent, revision, true, provider, admit, mtu)
	if err != nil {
		return nil, err
	}
	if len(finalize) == 1 {
		op.finalize = finalize[0]
	}
	return c.executeDeviceFixed(op), nil
}

func (c *Controller) executeDeviceFixed(op *operation) func() error {
	done := make(chan struct{})
	var result error
	go func() { result = c.execute(op, false); close(done) }()
	return func() error { <-done; return result }
}

type deviceFixedChangeKey struct{}
type deviceFixedChange struct{ requested, original int }

// DeviceFixedChangeAllowed grants the retained native lease only the admitted
// work size, or the exact pre-change size on its separate rollback allowance.
func DeviceFixedChangeAllowed(ctx context.Context, mtu int) bool {
	if ctx == nil || ctx.Err() != nil || !SameOperationContext(ctx, ctx) {
		return false
	}
	change, ok := ctx.Value(deviceFixedChangeKey{}).(deviceFixedChange)
	if !ok {
		return false
	}
	if ctx.Value(operationCleanupOnlyKey{}) != nil {
		return mtu == change.original
	}
	return mtu == change.requested
}
