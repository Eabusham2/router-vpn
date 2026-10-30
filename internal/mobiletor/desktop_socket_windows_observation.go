//go:build windows

package mobiletor

import (
	"context"
	"errors"
)

// NewDesktopWindowsProtectionObservation captures one or two recorded recovery
// outcomes. A nil candidate means proved absence, never an arbitrary current
// baseline. Creation opens no engine; Run obtains and retains its native read
// transaction through the synchronous acknowledgement. This is an elevated
// Windows API, not a portable substitute for physical firewall evidence.
func NewDesktopWindowsProtectionObservation(candidates []*DesktopWindowsProtectionTarget, callback func(context.Context, int) error) (*DesktopWindowsProtectionObservation, error) {
	return newDesktopWindowsProtectionObservationScoped(candidates, callback, nil)
}

func newDesktopWindowsProtectionObservationScoped(candidates []*DesktopWindowsProtectionTarget, callback func(context.Context, int) error, scope []byte) (*DesktopWindowsProtectionObservation, error) {
	if len(scope) > 65536 || len(scope)%2 != 0 {
		return nil, errors.New("Windows protection observation has an invalid native scope")
	}
	if err := desktopWindowsRequireElevation(); err != nil {
		return nil, err
	}
	capturedScope := append([]byte(nil), scope...)
	return newDesktopWindowsProtectionObservation(candidates, callback, func() (desktopWindowsProtectionObservationNative, error) {
		engine, err := desktopWFPOpen(false)
		if engine == nil {
			return nil, err
		}
		return &desktopWindowsProtectionNativeObservation{engine: engine, scope: capturedScope}, err
	})
}

type desktopWindowsProtectionNativeObservation struct {
	engine *desktopWFPEngine
	scope  []byte
}

func (n *desktopWindowsProtectionNativeObservation) observe(ctx context.Context, expected []*desktopWindowsProtectionExpected) (int, error) {
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	if n.engine == nil || n.engine.handle == 0 || n.engine.transaction {
		return -1, errors.New("Windows protection observation lost its fresh engine")
	}
	// FWPM_TXN_READ_ONLY holds one consistent kernel snapshot without adding
	// a dynamic owner or changing persistent policy. The configured native
	// engine transaction wait is bounded; Close retains failed aborts/handles.
	// https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
	status, _, _ := n.engine.api.begin.Call(uintptr(n.engine.handle), 1)
	if err := desktopWFPError("begin recovery observation read transaction", status); err != nil {
		return -1, err
	}
	n.engine.transaction = true
	lock, err := n.engine.readSublayer(desktopWindowsManagedKey("session-lock", n.scope), false)
	if err != nil || lock != nil {
		return -1, errors.Join(err, errors.New("Windows protection observation still has a live native session owner"))
	}
	actual, err := desktopWindowsReadBaseline(n.engine, desktopWindowsManagedKey("baseline", n.scope), n.scope)
	if err != nil {
		return -1, err
	}
	if actual != nil {
		if err := n.engine.AssertComplete(actual.sublayer, actual.baseline); err != nil {
			return -1, err
		}
	}
	for index, candidate := range expected {
		if candidate.verify(actual) == nil {
			return index, ctx.Err()
		}
	}
	return -1, errors.New("Windows protection observation found no exact recorded outcome")
}

func (n *desktopWindowsProtectionNativeObservation) close() error {
	if n.engine == nil {
		return nil
	}
	if err := n.engine.Close(); err != nil {
		return err
	}
	n.engine = nil
	return nil
}

func (n *desktopWindowsProtectionNativeObservation) finishSnapshot() error {
	if n.engine == nil || n.engine.handle == 0 || !n.engine.transaction {
		return errors.New("Windows recovery snapshot ended before its durable callback joined")
	}
	// Unlike cleanup, only an actual successful abort proves this transaction
	// was still ours through the callback. NO_TXN/ABORTED can clean resources,
	// but cannot acknowledge a write made after the snapshot was lost.
	status, _, _ := n.engine.api.abort.Call(uintptr(n.engine.handle))
	if status == 0 {
		n.engine.transaction = false
	}
	return desktopWFPError("finish acknowledged recovery snapshot", status)
}
