package hopmeasure

import (
	"context"
	"errors"
)

// NewOrderedExternalFinalContext admits an authenticated private entry followed
// by separately captured public HTTPS observations at every stream, including the exit.
func NewOrderedExternalFinalContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	return newOrderedExternalFinal(ctx, engine, hops, false)
}

// NewOrderedExternalFinalServerContext binds every public suffix position,
// including the exit, to the same selected Server branch digest.
func NewOrderedExternalFinalServerContext(ctx context.Context, engine Engine, hops []Hop) (*Service, error) {
	return newOrderedExternalFinal(ctx, engine, hops, true)
}

func newOrderedExternalFinal(ctx context.Context, engine Engine, hops []Hop, server bool) (*Service, error) {
	if len(hops) < 3 || len(hops) > PhysicalTraversalDepth || hops[0].Kind != "private-node" {
		return nil, errors.New("ordered external exit requires the captured private entry and original public streams")
	}
	public := make(map[int]bool, len(hops)-1)
	for i := 1; i < len(hops); i++ {
		if hops[i].Kind != "public-path" {
			return nil, errors.New("ordered external stream has no public response authority")
		}
		public[i] = true
	}
	s, err := newOrderedInventoryContext(ctx, engine, hops, true, public, server, len(hops) > 8)
	if err != nil {
		return nil, err
	}
	s.orderedExternalFinal = true
	return s, nil
}
