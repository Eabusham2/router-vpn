//go:build windows

package mobiletor

import (
	"context"
	"errors"
	"unsafe"
)

// ProbeDesktopWindowsProtectionAbsent performs only read-only lookups of the
// two fixed managed sublayers. It is available to an ordinary local process:
// BFE normally grants Everyone OPEN, but an existing protected object requires
// administrator READ. Access denied, a partial lookup, cancellation and every
// other unknown result are errors, never absence.
//
// This is deliberately NOT an authoritative protection snapshot. The lookups
// are sequential because ordinary callers cannot begin a BFE read transaction.
// A true result permits only a no-op return by a caller owning no native
// session. It authorizes no mutation, replacement, release or Connected claim;
// concurrent preparation must still use the elevated captured-owner protocol.
// https://learn.microsoft.com/en-us/windows/win32/fwp/access-control
func ProbeDesktopWindowsProtectionAbsent(ctx context.Context) (bool, error) {
	return probeDesktopWindowsProtectionAbsent(ctx, nil)
}

func probeDesktopWindowsProtectionAbsent(ctx context.Context, fixtureScope []byte) (bool, error) {
	if ctx == nil || ctx.Err() != nil || len(fixtureScope) > 65536 || len(fixtureScope)%2 != 0 {
		return false, errors.New("Windows protection absence probe requires a live bounded caller")
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case desktopWindowsProtectionReadGate <- struct{}{}:
	}
	type result struct {
		absent bool
		err    error
	}
	finished := make(chan result, 1)
	scope := append([]byte(nil), fixtureScope...)
	go func() {
		defer func() { <-desktopWindowsProtectionReadGate }()
		absent, err := desktopWindowsProtectionProbe(ctx, scope)
		finished <- result{absent, err}
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case completed := <-finished:
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return completed.absent, completed.err
	}
}

func desktopWindowsProtectionProbe(ctx context.Context, scope []byte) (absent bool, result error) {
	engine, err := desktopWFPOpen(false)
	if engine != nil {
		defer func() {
			result = errors.Join(result, engine.Close())
			if result != nil {
				absent = false
			}
		}()
	}
	if err != nil {
		return false, err
	}
	// The lock precedes baseline preparation. Rechecking it also catches a
	// preparation that became visible between these exact lookups; even three
	// absent observations are not claimed to be an atomic snapshot.
	for _, kind := range []string{"session-lock", "baseline", "session-lock"} {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		key := desktopWindowsManagedKey(kind, scope)
		var pointer *desktopWFPSubLayer
		status, _, _ := engine.api.getLayer.Call(uintptr(engine.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pointer)))
		if pointer != nil {
			engine.free(unsafe.Pointer(pointer))
		}
		if uint32(status) == 0x80320007 && pointer == nil { // FWP_E_SUBLAYER_NOT_FOUND
			continue
		}
		if err := desktopWFPError("probe managed protection absence", status); err != nil {
			return false, err
		}
		if pointer == nil {
			return false, errors.New("Windows protection absence probe received no object or not-found result")
		}
		return false, nil
	}
	return true, ctx.Err()
}
