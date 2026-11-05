package mobilemtu

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// CleanupDeadlineProvider publishes or captures one external absolute cleanup
// deadline. Its argument is the original authority's single cleanup-admission
// budget, not a renewed work context. It must honor cancellation synchronously.
type CleanupDeadlineProvider func(context.Context) (time.Time, error)

func WithOperationContextProvider(parent context.Context, budget, cleanupBudget time.Duration, provider CleanupDeadlineProvider) (context.Context, context.CancelFunc, error) {
	if provider == nil {
		return nil, nil, errors.New("MTU shared cleanup omitted original deadline provider")
	}
	return withOperationContextProvider(parent, budget, cleanupBudget, provider)
}

type providedOperationCleanup struct {
	admission context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	state     atomic.Pointer[providedCleanupState]
}
type providedCleanupState struct {
	ctx    context.Context
	cancel context.CancelFunc
	err    error
}

func (a *operationAuthority) finishCleanup() {
	if cleanup := a.cleanup.Load(); cleanup != nil {
		cleanup.cancel()
	}
	if cleanup := a.provided.Load(); cleanup != nil {
		cleanup.cancel()
		if state := cleanup.state.Load(); state != nil && state.cancel != nil {
			state.cancel()
		}
	}
}
func (a *operationAuthority) providedCleanup(original context.Context) (context.Context, error) {
	retained := a.provided.Load()
	if retained == nil {
		admission, cancel := context.WithTimeout(context.WithoutCancel(original), a.cleanupBudget)
		candidate := &providedOperationCleanup{admission: admission, cancel: cancel, ready: make(chan struct{})}
		if a.provided.CompareAndSwap(nil, candidate) {
			retained = candidate
			state := &providedCleanupState{}
			if a.closed.Load() {
				cancel()
			}
			deadline, err := a.provider(admission)
			bound, _ := admission.Deadline()
			if err == nil && (deadline.IsZero() || deadline.After(bound)) {
				err = errors.New("MTU shared cleanup provider renewed original allowance")
			}
			if err == nil && !time.Now().Before(deadline) {
				err = context.DeadlineExceeded
			}
			if err == nil {
				err = admission.Err()
			}
			if err == nil {
				state.ctx, state.cancel = context.WithDeadline(context.WithoutCancel(original), deadline)
				state.ctx = context.WithValue(state.ctx, operationCleanupOnlyKey{}, a)
			}
			state.err = err
			retained.state.Store(state)
			if a.closed.Load() && state.cancel != nil {
				state.cancel()
			}
			close(retained.ready)
		} else {
			cancel()
			retained = a.provided.Load()
		}
	}
	select {
	case <-retained.ready:
	case <-retained.admission.Done():
		return nil, retained.admission.Err()
	}
	state := retained.state.Load()
	if state == nil {
		return nil, errors.New("MTU shared cleanup initialization lost original result")
	}
	if state.err != nil {
		return nil, state.err
	}
	if a.closed.Load() {
		state.cancel()
		return nil, errors.New("MTU cleanup authority is complete")
	}
	if err := state.ctx.Err(); err != nil {
		return nil, err
	}
	return state.ctx, nil
}

// StartContextWithCleanupProvider admits a captured service run with one shared
// cleanup clock. The callback is supplied by the retained owner, never decoded
// from a public request. Existing admission and late-cancellation rules apply.
func (c *Controller) StartContextWithCleanupProvider(admission, operationParent context.Context, request string, force bool, provider CleanupDeadlineProvider, admit func(context.Context) error, finalize ...func(context.Context) error) error {
	if provider == nil || admit == nil || len(finalize) > 1 || len(finalize) == 1 && finalize[0] == nil {
		return errors.New("MTU shared cleanup requires captured provider and admission")
	}
	op, err := c.beginContextAdmissionProvider(admission, operationParent, request, true, provider, admit)
	if err != nil {
		return err
	}
	if len(finalize) == 1 {
		op.finalize = finalize[0]
	}
	go func() { _ = c.execute(op, force) }()
	return nil
}

// RunContextWithCleanupProvider uses the same bounded synchronous execution as
// RunContext, with an owner-supplied shared clock and exact admission callback.
func (c *Controller) RunContextWithCleanupProvider(admission, operationParent context.Context, request string, force bool, provider CleanupDeadlineProvider, admit func(context.Context) error, finalize ...func(context.Context) error) error {
	if provider == nil || admit == nil || len(finalize) > 1 || len(finalize) == 1 && finalize[0] == nil {
		return errors.New("MTU shared cleanup requires captured provider and admission")
	}
	op, err := c.beginContextAdmissionProvider(admission, operationParent, request, true, provider, admit)
	if err != nil {
		return err
	}
	if len(finalize) == 1 {
		op.finalize = finalize[0]
	}
	return c.execute(op, force)
}

// WithCapturedOperationContextProvider retains a previously admitted absolute
// work deadline. A late child receives an already-expired work context, while
// the captured provider can still supply that same run's cleanup remainder.
// It must only be called after validating the original retained run capability.
func WithCapturedOperationContextProvider(parent context.Context, workDeadline time.Time, cleanupBudget time.Duration, provider CleanupDeadlineProvider) (context.Context, context.CancelFunc, error) {
	if parent == nil || workDeadline.IsZero() || cleanupBudget <= 0 || provider == nil {
		return nil, nil, errors.New("captured MTU run omitted original deadline or cleanup provider")
	}
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	work, stop := context.WithDeadline(parent, workDeadline)
	deadline, _ := work.Deadline()
	authority := &operationAuthority{cleanupBudget: cleanupBudget, workDeadline: deadline, provider: provider}
	work = context.WithValue(work, operationAuthorityKey{}, authority)
	work = context.WithValue(work, boundedOperationKey{}, true)
	finish := func() { authority.closed.Store(true); stop(); authority.finishCleanup() }
	return work, finish, nil
}

// OperationWorkDeadline observes the originally accepted work bound, even when
// a short admission wrapper has an earlier deadline. It never grants new work.
func OperationWorkDeadline(ctx context.Context) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, errors.New("MTU work has no original authority")
	}
	authority, ok := ctx.Value(operationAuthorityKey{}).(*operationAuthority)
	if !ok || authority == nil || authority.closed.Load() || authority.workDeadline.IsZero() {
		return time.Time{}, errors.New("MTU work authority is absent or complete")
	}
	return authority.workDeadline, nil
}

// OperationCleanupOnly reports a marker carried only by the original token's
// cleanup context. A deadline or an MTU target cannot imply cleanup authority.
func OperationCleanupOnly(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, errors.New("MTU context has no original authority")
	}
	authority, ok := ctx.Value(operationAuthorityKey{}).(*operationAuthority)
	if !ok || authority == nil || authority.closed.Load() {
		return false, errors.New("MTU authority is absent or complete")
	}
	cleanup, marked := ctx.Value(operationCleanupOnlyKey{}).(*operationAuthority)
	if marked && cleanup != authority {
		return false, errors.New("MTU cleanup marker changed original authority")
	}
	return marked, nil
}
