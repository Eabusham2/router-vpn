package mobiletor

import (
	"context"
	"errors"
	"sync"
)

// One reader belongs to one complete global inspection. Its immutable callback
// captures the native command, argv construction and original namespace. It is
// never retained by a policy or reused for a later pre/post/probe inspection.
// Sharing a joined inventory does not share the independent validators which
// consume it, and never authorizes a mutation or substitutes empty output on error.
type desktopPFInventoryReadback struct {
	owner   context.Context
	native  func(context.Context, string) ([]byte, error)
	mu      sync.Mutex
	entries map[string]*desktopPFInventoryResult
	bytes   int
}
type desktopPFInventoryResult struct {
	done chan struct{}
	raw  []byte
	err  error
}

func newDesktopPFInventoryReadback(owner context.Context, native func(context.Context, string) ([]byte, error)) *desktopPFInventoryReadback {
	return &desktopPFInventoryReadback{owner: owner, native: native, entries: make(map[string]*desktopPFInventoryResult)}
}
func (r *desktopPFInventoryReadback) read(ctx context.Context, path string) ([]byte, error) {
	if r == nil || r.owner == nil || ctx == nil || r.native == nil || (path != "" && !desktopPFInventoryPath(path)) {
		return nil, errors.New("Darwin PF inventory has no captured invocation")
	}
	if err := errors.Join(r.owner.Err(), ctx.Err()); err != nil {
		return nil, err
	}
	r.mu.Lock()
	existing := r.entries[path]
	if existing != nil {
		r.mu.Unlock()
		select {
		case <-existing.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-r.owner.Done():
			return nil, r.owner.Err()
		}
	} else {
		if len(r.entries) >= 512 {
			r.mu.Unlock()
			return nil, errors.New("Darwin PF inventory exceeds its invocation bound")
		}
		existing = &desktopPFInventoryResult{done: make(chan struct{})}
		r.entries[path] = existing
		r.mu.Unlock()
		// The caller executes and joins the native command itself: no detached
		// worker or cancellation acknowledgement can outlive the enclosing group.
		raw, err := r.native(ctx, path)
		r.mu.Lock()
		if len(raw) > 64<<10 || r.bytes+len(raw) > 2<<20 {
			err = errors.Join(err, errors.New("Darwin PF inventory exceeds its captured output bound"))
		}
		if err == nil {
			existing.raw = append([]byte(nil), raw...)
			r.bytes += len(raw)
		}
		existing.err = err
		close(existing.done)
		r.mu.Unlock()
	}
	if err := errors.Join(r.owner.Err(), ctx.Err(), existing.err); err != nil {
		return nil, err
	}
	return append([]byte(nil), existing.raw...), nil
}
