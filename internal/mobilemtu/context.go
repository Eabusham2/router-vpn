package mobilemtu

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ContextOwner observes the retained reader with the original caller budget.
// Explicit Context operations require this capability; they never call Capture.
type ContextOwner interface {
	CaptureContext(context.Context) (State, error)
}

// ContextCaptureAvailability distinguishes construction-time capability on
// types that support both legacy and context-aware owners. Availability must
// stay fixed for the captured owner; it is not a transient health result.
// ContextOwner implementations without this optional method are available.
type ContextCaptureAvailability interface {
	ContextCaptureAvailable() bool
}

func capturedContextOwner(owner Owner) (ContextOwner, bool) {
	bounded, ok := owner.(ContextOwner)
	if !ok {
		return nil, false
	}
	if availability, ok := owner.(ContextCaptureAvailability); ok && !availability.ContextCaptureAvailable() {
		return nil, false
	}
	return bounded, true
}
type boundedOperationKey struct{}
type operationAuthorityKey struct{}
type operationCleanupOnlyKey struct{}

// ErrOperationCommitted means the original winner was already adopted under
// the controller mutex. A later Cancel cannot promise to restore that winner.
var ErrOperationCommitted = errors.New("MTU operation already committed its measured winner")

// ErrOperationNotCurrent does not grant cancellation of another generation.
var ErrOperationNotCurrent = errors.New("MTU cancellation lost its original operation")

type operationAuthority struct {
	cleanupBudget time.Duration
	workDeadline  time.Time
	provider      CleanupDeadlineProvider
	provided      atomic.Pointer[providedOperationCleanup]
	cleanup       atomic.Pointer[operationCleanup]
	closed        atomic.Bool
}
type operationCleanup struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// WithOperationContext admits one operation and its original cleanup allowance.
// Cleanup starts at most once, after a mutation needs finalization or rollback.
// Its deadline is shared by every layer and never renewed by another read.
func WithOperationContext(parent context.Context, budget, cleanupBudget time.Duration) (context.Context, context.CancelFunc, error) {
	return withOperationContextProvider(parent, budget, cleanupBudget, nil)
}
func withOperationContextProvider(parent context.Context, budget, cleanupBudget time.Duration, provider CleanupDeadlineProvider) (context.Context, context.CancelFunc, error) {
	if parent == nil || budget <= 0 || cleanupBudget <= 0 {
		return nil, nil, errors.New("MTU operation requires bounded work and cleanup")
	}
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	work, stop := context.WithTimeout(parent, budget)
	deadline, _ := work.Deadline()
	authority := &operationAuthority{cleanupBudget: cleanupBudget, workDeadline: deadline, provider: provider}
	work = context.WithValue(work, operationAuthorityKey{}, authority)
	work = context.WithValue(work, boundedOperationKey{}, true)
	finish := func() {
		authority.closed.Store(true)
		stop()
		authority.finishCleanup()
	}
	return work, finish, nil
}

// OperationCleanupContext grants only the original operation its remaining
// cleanup allowance. The returned context cannot admit measurements or a winner.
func OperationCleanupContext(original context.Context) (context.Context, error) {
	if original == nil {
		return nil, errors.New("MTU cleanup has no accepted operation")
	}
	authority, ok := original.Value(operationAuthorityKey{}).(*operationAuthority)
	if !ok || authority == nil || authority.closed.Load() {
		return nil, errors.New("MTU cleanup authority is absent or complete")
	}
	if authority.provider != nil {
		return authority.providedCleanup(original)
	}
	retained := authority.cleanup.Load()
	if retained == nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(original), authority.cleanupBudget)
		ctx = context.WithValue(ctx, operationCleanupOnlyKey{}, authority)
		candidate := &operationCleanup{ctx: ctx, cancel: cancel}
		if authority.cleanup.CompareAndSwap(nil, candidate) {
			retained = candidate
		} else {
			cancel()
			retained = authority.cleanup.Load()
		}
	}
	if authority.closed.Load() {
		retained.cancel()
	}
	if err := retained.ctx.Err(); err != nil {
		return nil, err
	}
	return retained.ctx, nil
}

// SameOperationContext cannot give a new caller the accepted operation's token.
func SameOperationContext(a, b context.Context) bool {
	if a == nil || b == nil {
		return false
	}
	token, ok := a.Value(operationAuthorityKey{}).(*operationAuthority)
	return ok && token != nil && !token.closed.Load() && token == b.Value(operationAuthorityKey{})
}

// LockContext shares an existing owner lock without leaving a detached waiter.
func LockContext(ctx context.Context, mu *sync.Mutex) error {
	if ctx == nil || mu == nil {
		return errors.New("MTU operation has no caller or owner lock")
	}
	var ticker *time.Ticker
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if mu.TryLock() {
			if err := ctx.Err(); err != nil {
				mu.Unlock()
				return err
			}
			return nil
		}
		if ticker == nil {
			ticker = time.NewTicker(time.Millisecond)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func captureContext(ctx context.Context, owner Owner) (State, error) {
	if ctx == nil {
		return State{}, errors.New("MTU capture has no caller")
	}
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	bounded, ok := capturedContextOwner(owner)
	if !ok {
		return State{}, errors.New("MTU owner has no bounded capture")
	}
	state, err := bounded.CaptureContext(ctx)
	if err != nil || ctx.Err() != nil {
		return State{}, errors.Join(err, ctx.Err())
	}
	return state, nil
}
func (c *Controller) capture(ctx context.Context) (State, error) {
	strict, _ := ctx.Value(boundedOperationKey{}).(bool)
	_, contextOwner := capturedContextOwner(c.owner)
	// Native callers can adopt bounded observation without changing their
	// existing cache contract or public Start/Cancel API. An available context
	// capability must retain this operation's caller even for legacy New.
	if c.bounded || strict || contextOwner {
		return captureContext(ctx, c.owner)
	}
	return c.owner.Capture()
}

func (c *Controller) RunContext(ctx context.Context, request string, force bool) error {
	op, err := c.beginContext(ctx, request, true)
	if err != nil {
		return err
	}
	return c.execute(op, force)
}
func (c *Controller) StartContext(ctx context.Context, request string, force bool) error {
	op, err := c.beginContext(ctx, request, true)
	if err != nil {
		return err
	}
	go func() { _ = c.execute(op, force) }()
	return nil
}
func (c *Controller) StatusJSONContext(ctx context.Context) (string, error) {
	if err := LockContext(ctx, &c.mu); err != nil {
		return "", err
	}
	data, err := json.Marshal(c.status)
	c.mu.Unlock()
	if err != nil || ctx.Err() != nil {
		return "", errors.Join(err, ctx.Err())
	}
	return string(data), nil
}
func (c *Controller) RunningContext(ctx context.Context) (bool, error) {
	if err := LockContext(ctx, &c.mu); err != nil {
		return false, err
	}
	defer c.mu.Unlock()
	return c.status.Running, ctx.Err()
}
func (c *Controller) ConfigContext(ctx context.Context) (string, error) {
	if err := LockContext(ctx, &c.mu); err != nil {
		return "", err
	}
	defer c.mu.Unlock()
	return c.currentConfig, ctx.Err()
}
func (c *Controller) CancelContext(ctx context.Context, request string) error {
	if err := LockContext(ctx, &c.mu); err != nil {
		return err
	}
	defer c.mu.Unlock()
	if c.status.Request != request || c.cancel == nil {
		return ErrOperationNotCurrent
	}
	if c.status.Measured {
		return ErrOperationCommitted
	}
	c.cancel()
	return nil
}
func NewContext(ctx context.Context, owner Owner, config, profile string, cache Cache) (*Controller, error) {
	policy, err := ReadProfile(profile)
	if err != nil {
		return nil, err
	}
	return newControllerContext(ctx, owner, config, policy, cache)
}
func newControllerContext(ctx context.Context, owner Owner, config string, policy Profile, cache Cache) (*Controller, error) {
	state, err := captureContext(ctx, owner)
	if err != nil {
		return nil, err
	}
	result, err := newControllerState(owner, config, policy, cache, state)
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	result.bounded = true
	return result, nil
}

// RollbackOwner can recover only the exact accepted transaction when expiry
// prevented its ordinary post-change observation. It grants no measurement or
// winner admission and is invoked only by the original run's rollback defer.
type RollbackOwner interface {
	RollbackStateContext(context.Context, State) (State, error)
}

// ContextCache keeps native mailbox/cache admission in the same work budget.
type ContextCache interface {
	LookupContext(context.Context, string) (int, bool, error)
	SaveContext(context.Context, string, int, func(context.Context) error) error
}

func (c *Controller) CloseContext(ctx context.Context) error {
	if err := LockContext(ctx, &c.mu); err != nil {
		return err
	}
	c.closed = true
	c.revokeLocked("stopped")
	if c.cancel != nil {
		c.cancel()
	}
	done := c.done
	c.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

// StartContextWithAdmission couples a retained native generation to the same
// controller publication. After successful admission, this original worker is
// published even if cancellation races the callback's return.
func (c *Controller) StartContextWithAdmission(ctx context.Context, request string, force bool, admit func(context.Context) error) error {
	if admit == nil {
		return errors.New("MTU admission callback is absent")
	}
	op, err := c.beginContextAdmission(ctx, request, true, admit)
	if err != nil {
		return err
	}
	go func() { _ = c.execute(op, force) }()
	return nil
}

// StartContextWithAdmissionOn observes mailbox admission using its polling
// caller while the accepted worker retains the command lifetime and transported
// absolute deadline. A later poll cannot extend or cancel this operation.
func (c *Controller) StartContextWithAdmissionOn(admission, operationParent context.Context, request string, force bool, admit func(context.Context) error) error {
	if admit == nil {
		return errors.New("MTU admission callback is absent")
	}
	op, err := c.beginContextAdmissionOn(admission, operationParent, request, true, admit)
	if err != nil {
		return err
	}
	go func() { _ = c.execute(op, force) }()
	return nil
}

// WithCleanupContext preserves a legacy caller's existing work lifetime while
// reserving its single cleanup allowance before any mutation. New bounded
// operations use WithOperationContext and never need this compatibility seam.
func WithCleanupContext(parent context.Context, budget time.Duration) (context.Context, context.CancelFunc, error) {
	if parent == nil || budget <= 0 {
		return nil, nil, errors.New("MTU cleanup requires its original caller and allowance")
	}
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	authority := &operationAuthority{cleanupBudget: budget}
	ctx := context.WithValue(parent, operationAuthorityKey{}, authority)
	finish := func() {
		authority.closed.Store(true)
		authority.finishCleanup()
	}
	return ctx, finish, nil
}
func StrictOperationContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	strict, _ := ctx.Value(boundedOperationKey{}).(bool)
	return strict
}
