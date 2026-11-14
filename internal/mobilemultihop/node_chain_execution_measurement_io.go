package mobilemultihop

import (
	"context"
	"errors"
	"sync"

	"router-vpn/internal/hopmeasure"
)

type nodeChainExecutionMeasurementScope struct {
	id      string
	io      *leaseStopIO
	release func()
	done    chan struct{}
	work    sync.Once
	gate    chan struct{}
	once    sync.Once
	joined  chan struct{}
}

func (e *nodeChainExecutionMeasurementEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if err := e.current(ctx); err != nil {
		return nil, err
	}
	e.mu.Lock()
	id, busy := e.nextID, e.scope != nil
	e.mu.Unlock()
	if id == "" || busy {
		return nil, errors.New("original ordered measurement cleanup remains owned")
	}
	finishHold, err := e.retainRuntimeActivity(ctx)
	if err != nil {
		return nil, err
	}
	release, err := e.owner.BeginMeasurementContext(ctx)
	if release == nil {
		finishHold()
		return nil, errors.Join(err, nodeChainExecutionError)
	}
	nativeRelease := release
	release = func() { nativeRelease(); finishHold() }
	if err != nil {
		return release, err
	}
	scope := &nodeChainExecutionMeasurementScope{id: id, io: newLeaseStopIO(ctx), release: release,
		done: make(chan struct{}), gate: make(chan struct{}, 1), joined: make(chan struct{})}
	e.mu.Lock()
	if e.scope != nil || e.nextID != id {
		e.mu.Unlock()
		return release, nodeChainExecutionError
	}
	e.scope = scope
	e.mu.Unlock()
	finish := func() {
		scope.work.Do(func() { close(scope.done) })
		cleanup, cancel := context.WithTimeout(context.Background(), hopmeasure.DrainTimeout)
		defer cancel()
		_ = e.drainCapturedScope(cleanup, scope)
	}
	if err := e.current(ctx); err != nil {
		return finish, err
	}
	return finish, nil
}

// A partially acquired host activity remains part of this exact runtime's
// cleanup until its release actually returns. Closing shared/remote proof alone
// cannot authorize a new native MTU generation while that work still exists.
func (e *nodeChainExecutionMeasurementEngine) retainRuntimeActivity(ctx context.Context) (func(), error) {
	r := e.runtime
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return nil, err
	}
	if r.retired.Load() || r.closed || r.active != e.trial || r.identity != e.identity || ctx.Err() != nil {
		r.mu.Unlock()
		return nil, hopmeasure.ErrStale
	}
	r.measurementHolds++
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() { r.mu.Lock(); r.measurementHolds--; r.mu.Unlock() })
	}, nil
}

func (e *nodeChainExecutionMeasurementEngine) retireScope() {
	e.mu.Lock()
	scope := e.scope
	e.mu.Unlock()
	if scope != nil {
		scope.io.retire()
	}
}

func (e *nodeChainExecutionMeasurementEngine) drainScope(ctx context.Context, id string) error {
	if ctx == nil {
		return nodeChainExecutionError
	}
	e.mu.Lock()
	scope := e.scope
	e.mu.Unlock()
	if scope == nil || id != "" && scope.id != id {
		return ctx.Err()
	}
	return e.drainCapturedScope(ctx, scope)
}

// A borrowed operation keeps its actual scope, not only a caller-chosen ID.
// A delayed completion must never close a later operation reusing that ID.
func (e *nodeChainExecutionMeasurementEngine) drainCapturedScope(ctx context.Context, scope *nodeChainExecutionMeasurementScope) error {
	if ctx == nil {
		return nodeChainExecutionError
	}
	if scope == nil {
		return ctx.Err()
	}
	select {
	case scope.gate <- struct{}{}:
		defer func() { <-scope.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	scope.io.retire()
	if err := scope.io.wait(ctx); err != nil {
		return err
	}
	select {
	case <-scope.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	// The activity callback itself can wait on its original native owner.
	// Retain and join it exactly once; a short caller cannot drop that hold.
	scope.once.Do(func() { go func() { scope.release(); close(scope.joined) }() })
	select {
	case <-scope.joined:
	case <-ctx.Done():
		return ctx.Err()
	}
	e.mu.Lock()
	if e.scope == scope {
		e.scope = nil
	}
	e.mu.Unlock()
	return ctx.Err()
}
