package desktopnetwork

import (
	"context"
	"errors"
	"runtime"
)

// Transition is the original observer's in-memory capability for one admitted
// native mutation. Serialized history cannot create it. It observes actual
// retained readers; it grants no authority to construct, adopt or delete them.
// A caller may finish observation using its separately captured cleanup budget
// after work cancellation, without renewing that work or admitting a winner.
type Transition struct{ owner *Tracker }

func transitionContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("retained network transition has no caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("retained network transition requires the original bounded observation")
	}
	return nil
}

// BeginRetained observes the already-proved original receipt before accepting
// any mutation. Expired admission leaves that original observer unchanged.
// Startup still uses Begin/End, whose failed-admission semantics are stricter.
func (t *Tracker) BeginRetained(ctx context.Context, original *DesktopNetworkReceipt) (operation *Transition, result error) {
	defer t.reportFailure(&result)
	if t == nil || original == nil || original.Validate() != nil || original.TargetOS != runtime.GOOS {
		return nil, errors.New("retained transition requires its proved original native receipt")
	}
	if err := transitionContext(ctx); err != nil {
		return nil, err
	}
	if err := LockContext(ctx, &t.mu); err != nil {
		return nil, errors.Join(err, t.failureError())
	}
	busy := t.transition || t.retained != nil
	t.mu.Unlock()
	if busy {
		return nil, errors.New("original observer already owns a native transition")
	}
	if err := t.CurrentContext(ctx); err != nil {
		return nil, err
	}
	if err := LockContext(ctx, &t.mu); err != nil {
		return nil, errors.Join(err, t.failureError())
	}
	defer t.mu.Unlock()
	if t.failureError() != nil {
		return nil, t.failureError()
	}
	if t.closed || t.closing || t.ctx == nil || t.ctx.Err() != nil {
		return nil, t.failLocked(errors.New("retained transition lost its original observer lifetime"))
	}
	if t.transition || t.retained != nil || receiptKey(original) != receiptKey(t.current) {
		return nil, errors.New("retained transition does not own the current original receipt")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	operation = &Transition{owner: t}
	t.old, t.recorded, t.retired, t.events = cloneReceipt(original), nil, nil, nil
	t.transition, t.retained = true, operation
	return operation, nil
}

// lock retains the exact original token, without a detached waiter. A completed
// or copied/foreign token cannot affect a later transition on the same tracker.
func (o *Transition) lock(ctx context.Context) (*Tracker, error) {
	if o == nil || o.owner == nil {
		return nil, errors.New("retained transition capability is absent")
	}
	t := o.owner
	if err := transitionContext(ctx); err != nil {
		return nil, errors.Join(err, t.failureError())
	}
	if err := LockContext(ctx, &t.mu); err != nil {
		return nil, errors.Join(err, t.failureError())
	}
	if t.retained != o || !t.transition {
		t.mu.Unlock()
		return nil, errors.New("retained transition no longer owns this observer")
	}
	if t.failureError() != nil {
		err := t.failureError()
		t.mu.Unlock()
		return nil, err
	}
	if t.closed || t.closing || t.ctx == nil || t.ctx.Err() != nil {
		err := t.failLocked(errors.New("retained transition lost its original observer lifetime"))
		t.mu.Unlock()
		return nil, err
	}
	return t, nil
}

func retainedIdentityMatches(ready *DesktopNetworkReceipt, retired *DesktopNetworkRetirementReceipt) bool {
	return ready == nil || retired == nil || ready.Incarnation != retired.Incarnation ||
		retired.Created && !retired.Unindexed && ready.TargetOS == retired.TargetOS && ready.Name == retired.Name && ready.Index == retired.Index && ready.LUID == 0
}

// Record retains an actual reader's complete Ready receipt. It never turns
// partial retirement evidence into a successful Ready or current interface.
func (o *Transition) Record(ctx context.Context, receipt DesktopNetworkReceipt) (result error) {
	if o != nil {
		defer o.owner.reportFailure(&result)
	}
	t, err := o.lock(ctx)
	if err != nil {
		return err
	}
	defer t.mu.Unlock()
	if receipt.Validate() != nil || receipt.TargetOS != runtime.GOOS {
		return t.failLocked(errors.New("retained transition received a malformed native Ready"))
	}
	if t.old != nil && t.old.Incarnation == receipt.Incarnation && receiptKey(t.old) != receiptKey(&receipt) {
		return t.failLocked(errors.New("retained Ready changed its original incarnation"))
	}
	for i := range t.retired {
		if !retainedIdentityMatches(&receipt, &t.retired[i]) {
			return t.failLocked(errors.New("native Ready disagrees with original retirement identity"))
		}
	}
	for _, prior := range t.recorded {
		if prior.Incarnation == receipt.Incarnation {
			if receiptKey(&prior) != receiptKey(&receipt) {
				return t.failLocked(errors.New("native Ready changed within its retained incarnation"))
			}
			return ctx.Err()
		}
	}
	if len(t.recorded) >= 64 {
		return t.failLocked(errors.New("retained native Ready history exceeds its original bound"))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.recorded = append(t.recorded, *cloneReceipt(&receipt))
	return nil
}

// RecordRetirement records a completed original retirement, including a reader
// that failed before Ready. Unindexed receipts cannot classify events by name.
func (o *Transition) RecordRetirement(ctx context.Context, receipt DesktopNetworkRetirementReceipt) (result error) {
	if o != nil {
		defer o.owner.reportFailure(&result)
	}
	t, err := o.lock(ctx)
	if err != nil {
		return err
	}
	defer t.mu.Unlock()
	key, err := CanonicalDesktopNetworkRetirementReceipt(receipt)
	if err != nil || receipt.TargetOS != runtime.GOOS {
		return t.failLocked(errors.New("retained transition received malformed original retirement"))
	}
	if !receipt.Created {
		return ctx.Err()
	}
	if !retainedIdentityMatches(t.old, &receipt) {
		return t.failLocked(errors.New("retirement changed the original native reader identity"))
	}
	for i := range t.recorded {
		if !retainedIdentityMatches(&t.recorded[i], &receipt) {
			return t.failLocked(errors.New("retirement disagrees with its retained Ready identity"))
		}
	}
	for _, prior := range t.retired {
		if prior.Incarnation == receipt.Incarnation {
			previous, _ := CanonicalDesktopNetworkRetirementReceipt(prior)
			if previous != key {
				return t.failLocked(errors.New("completed retirement changed within its original incarnation"))
			}
			return ctx.Err()
		}
	}
	if len(t.retired) >= 64 {
		return t.failLocked(errors.New("retained retirement history exceeds its original bound"))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	receipt.Addresses = append([]string(nil), receipt.Addresses...)
	receipt.Objects = append([]DesktopNetworkObject{}, receipt.Objects...)
	t.retired = append(t.retired, receipt)
	return nil
}

// Complete drains the same native event stream and verifies the unchanged
// physical cohort against the actual current reader. Pure observation expiry
// leaves this token and its full history pending for original cleanup; genuine
// failures remain permanently latched. Completion alone is not winner adoption.
func (o *Transition) Complete(ctx context.Context, current *DesktopNetworkReceipt) (result error) {
	if o != nil {
		defer o.owner.reportFailure(&result)
	}
	t, err := o.lock(ctx)
	if err != nil {
		return err
	}
	if current != nil && (current.Validate() != nil || current.TargetOS != runtime.GOOS) {
		t.mu.Unlock()
		return t.failLocked(errors.New("retained completion has no exact current native receipt"))
	}
	native, baseline := t.native, t.baseline
	t.mu.Unlock()
	snapshot, observed := native.Snapshot(ctx)
	key := ""
	if observed == nil {
		var projection error
		_, key, projection = project(snapshot, current)
		if projection != nil {
			t.failLocked(projection)
		} else if key != baseline {
			t.failLocked(errors.New("retained native mutation changed its frozen physical cohort"))
		}
		if ctx.Err() == nil {
			observed = native.Barrier(ctx)
		} else {
			observed = ctx.Err()
		}
	}
	if observed != nil && !observationExpired(observed) {
		t.failLocked(observed)
	}
	if failure := t.failureError(); failure != nil {
		return errors.Join(failure, observed, ctx.Err())
	}
	if observed != nil || ctx.Err() != nil {
		return errors.Join(observed, ctx.Err())
	}
	t, err = o.lock(ctx)
	if err != nil {
		return err
	}
	defer t.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return t.finishTransitionLocked(current, key)
}
