package mobiletor

import (
	"context"
	"errors"
	"sync/atomic"
)

// DesktopWindowsProtectionObservation owns a read-only native observation and
// one captured durable acknowledgement. Run calls the acknowledgement
// synchronously while the BFE read transaction still covers the exact retained
// target (or explicit absence) and absence of a dynamic session owner. It does
// not confer permission to remove policy or adopt a different baseline.
//
// A failed Run can retain a native handle/transaction. The same owner must be
// retried or closed; cancellation never leaves an unowned background writer.
// The callback must honour its context and must not query BFE or call this
// owner's Run/Close, because it executes inside the native snapshot and gate.
type DesktopWindowsProtectionObservation struct {
	expected []*desktopWindowsProtectionExpected
	callback func(context.Context, int) error
	open     func() (desktopWindowsProtectionObservationNative, error)
	native   desktopWindowsProtectionObservationNative
	gate     chan struct{}
	lifetime context.Context
	cancel   context.CancelFunc
	closing  atomic.Bool
	acked    bool  // protected by gate; successful durable acknowledgement is not replayed
	proofErr error // protected by gate; lost snapshot cannot become success after cleanup
}

type desktopWindowsProtectionObservationNative interface {
	observe(context.Context, []*desktopWindowsProtectionExpected) (int, error)
	finishSnapshot() error
	close() error
}

func newDesktopWindowsProtectionObservation(candidates []*DesktopWindowsProtectionTarget, callback func(context.Context, int) error, open func() (desktopWindowsProtectionObservationNative, error)) (*DesktopWindowsProtectionObservation, error) {
	if len(candidates) < 1 || len(candidates) > 2 || callback == nil || open == nil {
		return nil, errors.New("Windows protection observation requires one or two captured outcomes and its durable callback")
	}
	expected := make([]*desktopWindowsProtectionExpected, len(candidates))
	for index, target := range candidates {
		value, err := newDesktopWindowsProtectionExpected(target)
		if err != nil {
			return nil, err
		}
		for _, previous := range expected[:index] {
			if previous.target == nil && value.target == nil || previous.target != nil && value.target != nil && *previous.target == *value.target {
				return nil, errors.New("Windows protection observation requires distinct captured outcomes")
			}
		}
		expected[index] = value
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &DesktopWindowsProtectionObservation{expected: expected, callback: callback, open: open,
		gate: make(chan struct{}, 1), lifetime: lifetime, cancel: cancel}, nil
}

func (o *DesktopWindowsProtectionObservation) closeNative() error {
	if o.native == nil {
		return nil
	}
	if err := o.native.close(); err != nil {
		return err // retain this exact partial owner for a joined retry
	}
	o.native = nil
	return nil
}

// Run holds the verified native snapshot until the callback has returned. A
// retry first joins prior native cleanup, then obtains a fresh snapshot before
// retrying a failed callback. The caller must make an uncertain durable write
// idempotent against its locked journal head. A callback that returned success
// is never replayed, even if native cleanup subsequently failed.
// Loss of the snapshot through the callback is a retained proof failure;
// cleanup cannot repair it or authorize adoption on a later Run.
func (o *DesktopWindowsProtectionObservation) Run(ctx context.Context) (result error) {
	if o == nil || ctx == nil || o.gate == nil || o.lifetime == nil || o.cancel == nil {
		return errors.New("Windows protection observation requires its owned request and context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.closing.Load() {
		return errors.New("Windows protection observation is retiring")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-o.lifetime.Done():
		return errors.New("Windows protection observation is retiring")
	case o.gate <- struct{}{}:
	}
	defer func() { <-o.gate }()
	if o.closing.Load() {
		return errors.New("Windows protection observation is retiring")
	}
	request, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(o.lifetime, cancel)
	defer func() { stop(); cancel() }()
	if err := o.closeNative(); err != nil {
		return errors.Join(err, request.Err())
	}
	if err := request.Err(); err != nil {
		return err
	}
	if o.proofErr != nil {
		return o.proofErr
	}
	if o.acked {
		return nil
	}
	var err error
	o.native, err = o.open()
	// Open may fail after acquiring a native handle. Preserve and join that
	// partial operation exactly as for a later read/callback failure.
	defer func() { result = errors.Join(result, o.closeNative(), request.Err()) }()
	if err != nil {
		return err
	}
	if o.native == nil {
		return errors.New("Windows protection observation opened no native owner")
	}
	matched, err := o.native.observe(request, o.expected)
	if err != nil {
		return err
	}
	if matched < 0 || matched >= len(o.expected) {
		return errors.New("Windows protection observation returned an uncaptured outcome")
	}
	if err := request.Err(); err != nil {
		return err
	}
	if o.closing.Load() {
		return errors.New("Windows protection observation retired before durable acknowledgement")
	}
	callbackErr := o.callback(request, matched)
	if callbackErr == nil {
		o.acked = true
	}
	// A callback can perform a durable write even when it reports failure or
	// cancellation. Require the actual read transaction to have survived until
	// it returned. Cleanup's benign "already aborted" result is insufficient
	// here: no later retry may convert lost snapshot proof into adoption.
	if err := o.native.finishSnapshot(); err != nil {
		o.proofErr = errors.Join(errors.New("Windows protection observation lost its snapshot through durable acknowledgement"), err)
	}
	return errors.Join(callbackErr, o.proofErr)
}

// Close revokes a pending callback context before joining the Run gate and the
// exact remaining native resources. An expired Close is not a joined receipt:
// the same owner remains available for another Close. No saved PID or ambient
// selected profile participates in cleanup.
func (o *DesktopWindowsProtectionObservation) Close(ctx context.Context) error {
	if o == nil || ctx == nil || o.gate == nil || o.lifetime == nil || o.cancel == nil {
		return errors.New("Windows protection observation cleanup requires its owner and context")
	}
	o.closing.Store(true)
	o.cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case o.gate <- struct{}{}:
	}
	defer func() { <-o.gate }()
	return errors.Join(o.closeNative(), ctx.Err())
}
