package startwhitening

import (
	"context"
	"errors"
	"net"
	"reflect"
	"time"
)

var errOriginalOwner = errors.New("authenticated whitening lost its original owner")

func lockOriginalOwner(ctx context.Context, o *Owner) error {
	if ctx == nil || o == nil {
		return errOriginalOwner
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.mu.TryLock() {
		return nil
	}
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if o.mu.TryLock() {
				return nil
			}
		}
	}
}

// CaptureOriginalContext binds an existing outbound's exact live generation.
// It reveals no key, connection or dialing capability. Reset and Close revoke
// the observation even if the same Outbound remains in its manager slot.
func (o *Owner) CaptureOriginalContext() (func(context.Context) error, error) {
	if o == nil || o.self != o {
		return nil, errOriginalOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ctx == nil || o.ctx.Err() != nil || o.closed || o.generation == nil || o.generation.Err() != nil {
		return nil, errOriginalOwner
	}
	ctx, generation, done := o.ctx, o.generation, o.closeDone
	return func(call context.Context) error {
		if call == nil || call.Err() != nil {
			return errOriginalOwner
		}
		if err := lockOriginalOwner(call, o); err != nil {
			return err
		}
		defer o.mu.Unlock()
		if o.self != o || o.ctx != ctx || o.generation != generation || o.closeDone != done || o.closed || ctx.Err() != nil || generation.Err() != nil {
			return errOriginalOwner
		}
		return call.Err()
	}, nil
}

// CaptureJoinedRetirement is cleanup-only authority over a connection already
// held by the caller. It does not expose the whitening transport or cipher.
// The exact original authenticated owner must be live at capture; the returned
// receipt becomes usable only after its raw, both I/O directions and cipher
// have joined Close. Close retains its original error for every retry.
func (c *AuthenticatedStream) CaptureJoinedRetirement(knownRaw net.Conn) func(context.Context) error {
	if c == nil || c.self != c || knownRaw == nil || reflect.ValueOf(knownRaw).Kind() != reflect.Pointer || reflect.ValueOf(knownRaw).IsNil() ||
		c.Conn == nil || reflect.ValueOf(c.Conn).Kind() != reflect.Pointer || reflect.ValueOf(c.Conn).IsNil() ||
		c.guard.raw == nil || c.guard.raw.Conn != knownRaw || c.guard.raw.owner == nil || c.guard.closeDone == nil || c.guard.closed.Load() {
		return nil
	}
	raw, cipher, owner, generation, done := c.guard.raw, c.Conn, c.guard.raw.owner, c.guard.raw.generation, c.guard.closeDone
	owner.mu.Lock()
	live := owner.self == owner && !owner.closed && owner.ctx != nil && owner.ctx.Err() == nil && owner.generation == generation && generation != nil && generation.Err() == nil && owner.conns[raw] == c
	owner.mu.Unlock()
	if !live {
		return nil
	}
	return func(ctx context.Context) error {
		if ctx == nil || ctx.Err() != nil || c.self != c || c.Conn != cipher || c.guard.raw != raw || raw.Conn != knownRaw || raw.owner != owner || owner.self != owner || raw.generation != generation || c.guard.closeDone != done {
			return errOriginalOwner
		}
		select {
		case <-done:
		default:
			return errors.New("original authenticated whitening stream has not joined")
		}
		if err := lockOriginalOwner(ctx, owner); err != nil {
			return err
		}
		_, retained := owner.conns[raw]
		owner.mu.Unlock()
		if retained || !c.guard.closed.Load() {
			return errOriginalOwner
		}
		return ctx.Err()
	}
}
