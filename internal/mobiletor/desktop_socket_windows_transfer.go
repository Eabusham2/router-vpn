//go:build windows

package mobiletor

import (
	"context"
	"errors"
)

// NewDesktopWindowsSocketPolicySuccessor creates a native source only after
// replacing the exact captured predecessor in one BFE transaction. A nil
// predecessor explicitly requires no prior baseline. A still-live old source
// keeps the exclusive native lock, so its sockets must be joined first while
// its deny baseline is retained. This API never adopts unknown stale state.
//
// A nonnil result on failure retains every partial native operation and must
// be closed. A committed replacement remains fail-closed under the selected
// retention policy; a timeout is not proof that replacement did not occur.
func NewDesktopWindowsSocketPolicySuccessor(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions, predecessor *DesktopWindowsProtectionTarget) (*DesktopWindowsSocketPolicy, error) {
	return newDesktopWindowsSocketPolicySuccessor(ctx, capture, options, predecessor, nil)
}

func newDesktopWindowsSocketPolicySuccessor(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions, predecessor *DesktopWindowsProtectionTarget, scope []byte) (*DesktopWindowsSocketPolicy, error) {
	expected, err := newDesktopWindowsProtectionExpected(predecessor)
	if err != nil {
		return nil, err
	}
	if !options.RetainBaselineForHandoff {
		return nil, errors.New("Windows native succession requires retained deny until exact completion")
	}
	if expected.target != nil && expected.target.Capture == capture {
		return nil, errors.New("Windows native successor cannot reuse its predecessor capture")
	}
	p, err := newDesktopWindowsPolicyOwner(ctx, capture, options, scope)
	if err != nil {
		return nil, err
	}
	p.predecessor = expected
	return startDesktopWindowsSocketPolicy(ctx, p)
}

func (expected *desktopWindowsProtectionExpected) verify(actual *DesktopWindowsSocketPolicy) error {
	if expected == nil {
		return errors.New("Windows native succession has no captured expectation")
	}
	if expected.target == nil {
		if actual != nil {
			return errors.New("Windows initial protection cannot adopt a retained predecessor")
		}
		return nil
	}
	if actual == nil || !expected.target.matches(actual.capture, actual.options.KillSwitchPolicy, actual.metadata) {
		return errors.New("Windows protection operation found another captured predecessor")
	}
	return nil
}

// ReadDesktopWindowsRetainedProtection verifies the exact complete baseline
// only after the former native session lock and all dynamic permits are gone.
// It is a read-only observation, not a lease or permission to delete policy.
func ReadDesktopWindowsRetainedProtection(ctx context.Context, target DesktopWindowsProtectionTarget) error {
	return readDesktopWindowsRetainedProtection(ctx, target, nil)
}

func readDesktopWindowsRetainedProtection(ctx context.Context, target DesktopWindowsProtectionTarget, scope []byte) error {
	if ctx == nil || ctx.Err() != nil || target.Validate() != nil || len(scope) > 65536 || len(scope)%2 != 0 {
		return errors.New("Windows retained protection requires its exact live read request")
	}
	if err := desktopWindowsRequireElevation(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case desktopWindowsProtectionReadGate <- struct{}{}:
	}
	capturedScope := append([]byte(nil), scope...)
	done := make(chan error, 1)
	go func() {
		defer func() { <-desktopWindowsProtectionReadGate }()
		done <- desktopWindowsReadRetainedTarget(ctx, target, capturedScope)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return errors.Join(err, ctx.Err())
	}
}

func desktopWindowsReadRetainedTarget(ctx context.Context, target DesktopWindowsProtectionTarget, scope []byte) (result error) {
	engine, err := desktopWFPOpen(false)
	if engine != nil {
		defer func() { result = errors.Join(result, engine.Close()) }()
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The read lock covers absence of the prior dynamic session, the exact
	// persistent record and its complete rules in the same kernel snapshot.
	status, _, _ := engine.api.begin.Call(uintptr(engine.handle), 1)
	if err := desktopWFPError("begin retained protection read transaction", status); err != nil {
		return err
	}
	engine.transaction = true
	lock, err := engine.readSublayer(desktopWindowsManagedKey("session-lock", scope), false)
	if err != nil || lock != nil {
		return errors.Join(err, errors.New("Windows retained protection still has a native session owner"))
	}
	actual, err := desktopWindowsReadBaseline(engine, desktopWindowsManagedKey("baseline", scope), scope)
	if err != nil {
		return err
	}
	expected := &desktopWindowsProtectionExpected{target: &target}
	if err := expected.verify(actual); err != nil {
		return err
	}
	if err := engine.AssertComplete(actual.sublayer, actual.baseline); err != nil {
		return err
	}
	return ctx.Err()
}

// RetainedProtectionTarget acknowledges this exact source's completed native
// drain. It does not return a guessed target for an unjoined/failed close or a
// replacement baseline. A caller that already captured the prepared target may
// independently use ReadDesktopWindowsRetainedProtection after process exit.
func (p *DesktopWindowsSocketPolicy) RetainedProtectionTarget(ctx context.Context) (DesktopWindowsProtectionTarget, error) {
	return desktopWindowsPolicyCall(p, ctx, true, func() (DesktopWindowsProtectionTarget, error) {
		if !p.closed || !p.baselineDone || !p.installed || p.locked || len(p.permits) != 0 || len(p.bindings) != 0 || len(p.tunnel) != 0 {
			return DesktopWindowsProtectionTarget{}, errors.New("Windows source has not joined with its exact deny baseline retained")
		}
		target := desktopWindowsProtectionTarget(p.capture, p.options.KillSwitchPolicy, p.metadata)
		if err := readDesktopWindowsRetainedProtection(ctx, target, p.fixtureScope); err != nil {
			return DesktopWindowsProtectionTarget{}, err
		}
		return target, nil
	})
}

// NewDesktopWindowsProtectionReleaseTarget is normal disconnected cleanup of
// one exact retained baseline. It preserves Always and refuses missing,
// replaced, malformed or live state instead of adopting the current record.
func NewDesktopWindowsProtectionReleaseTarget(ctx context.Context, target DesktopWindowsProtectionTarget) (*DesktopWindowsProtectionRecovery, error) {
	return newDesktopWindowsProtectionTransactionTarget(ctx, nil, false, &target)
}

// NewDesktopWindowsProtectionRecoveryTarget is the explicit recovery/Off
// variant. It can retire Always, but still only the exact captured baseline.
// Ordinary session transitions must use succession or normal target release.
func NewDesktopWindowsProtectionRecoveryTarget(ctx context.Context, target DesktopWindowsProtectionTarget) (*DesktopWindowsProtectionRecovery, error) {
	return newDesktopWindowsProtectionTransactionTarget(ctx, nil, true, &target)
}
