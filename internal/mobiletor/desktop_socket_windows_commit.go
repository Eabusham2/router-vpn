//go:build windows

package mobiletor

import (
	"context"
	"errors"
)

// NewDesktopWindowsSocketPolicySuccessorWithBarrier adds a mandatory durable
// intent acknowledgment to exact succession. The callback receives the actual
// normalized candidate and old target while their BFE write transaction is
// still uncommitted. Its failure/cancellation aborts that transaction. A nonnil
// partial result must still be joined; neither a callback nor a commit error
// establishes which outcome survived without independent native readback.
func NewDesktopWindowsSocketPolicySuccessorWithBarrier(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions, predecessor *DesktopWindowsProtectionTarget, barrier DesktopWindowsProtectionCommitBarrier) (*DesktopWindowsSocketPolicy, error) {
	if barrier == nil {
		return nil, errors.New("Windows durable successor has no commit barrier")
	}
	return newDesktopWindowsSocketPolicySuccessorWithBarrier(ctx, capture, options, predecessor, nil, barrier)
}

// NewDesktopWindowsProtectionReleaseTargetWithBarrier records a normal exact
// removal before BFE commit. Always remains retained without any removal or
// callback; the caller must checkpoint its separately proved joined state.
func NewDesktopWindowsProtectionReleaseTargetWithBarrier(ctx context.Context, target DesktopWindowsProtectionTarget, barrier DesktopWindowsProtectionCommitBarrier) (*DesktopWindowsProtectionRecovery, error) {
	if barrier == nil {
		return nil, errors.New("Windows durable target release has no commit barrier")
	}
	return newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx, nil, false, &target, barrier)
}

// NewDesktopWindowsProtectionRecoveryTargetWithBarrier is the explicit Off
// form. It can remove the captured Always target only after its durable intent
// callback succeeds. This does not itself acknowledge profile persistence.
func NewDesktopWindowsProtectionRecoveryTargetWithBarrier(ctx context.Context, target DesktopWindowsProtectionTarget, barrier DesktopWindowsProtectionCommitBarrier) (*DesktopWindowsProtectionRecovery, error) {
	if barrier == nil {
		return nil, errors.New("Windows durable target recovery has no commit barrier")
	}
	return newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx, nil, true, &target, barrier)
}

func (p *DesktopWindowsSocketPolicy) completeSuccessorCommitBarrier(previous *DesktopWindowsSocketPolicy) error {
	if p.commitBarrier == nil {
		return nil // Existing bounded constructors do not claim durable adoption.
	}
	if p.commitAction != "successor" || p.predecessor == nil || p.baselineEngine == nil || !p.baselineEngine.transaction {
		return errors.New("Windows successor barrier lost its captured native transaction")
	}
	if err := p.predecessor.verify(previous); err != nil {
		return err
	}
	actual, err := desktopWindowsReadBaseline(p.baselineEngine, p.sublayer, p.fixtureScope)
	if err != nil || actual == nil {
		return errors.Join(err, errors.New("Windows successor barrier has no actual uncommitted candidate"))
	}
	candidate := desktopWindowsProtectionTarget(p.capture, p.options.KillSwitchPolicy, p.metadata)
	if !candidate.matches(actual.capture, actual.options.KillSwitchPolicy, actual.metadata) {
		return errors.New("Windows successor barrier changed its normalized native candidate")
	}
	if err := p.baselineEngine.AssertComplete(actual.sublayer, actual.baseline); err != nil {
		return err
	}
	change := DesktopWindowsProtectionCommit{Action: "successor", Candidate: &candidate}
	if previous != nil {
		old := desktopWindowsProtectionTarget(previous.capture, previous.options.KillSwitchPolicy, previous.metadata)
		change.Previous = &old
	}
	return desktopWindowsCompleteProtectionCommit(p.ctx, p.commitBarrier, change)
}

func (p *DesktopWindowsSocketPolicy) completeRemovalCommitBarrier(ctx context.Context) error {
	if p.commitBarrier == nil {
		return nil
	}
	if !p.recoveryMode || !p.recoveryArmed.Load() || p.predecessor == nil || p.predecessor.target == nil ||
		p.commitAction != "release" && p.commitAction != "off" || p.baselineEngine == nil || !p.baselineEngine.transaction {
		return errors.New("Windows retirement barrier lost its exact armed native transaction")
	}
	actual, err := desktopWindowsReadBaseline(p.baselineEngine, p.sublayer, p.fixtureScope)
	if err != nil {
		return err
	}
	if err := p.predecessor.verify(actual); err != nil {
		return err
	}
	if actual == nil {
		return errors.New("Windows retirement barrier cannot adopt missing protection")
	}
	if err := p.baselineEngine.AssertComplete(actual.sublayer, actual.baseline); err != nil {
		return err
	}
	// Explicit Off changes only the in-memory removal choice. Preserve the
	// original kernel policy (including Always) in its durable intent target.
	previous := desktopWindowsProtectionTarget(actual.capture, actual.options.KillSwitchPolicy, actual.metadata)
	return desktopWindowsCompleteProtectionCommit(ctx, p.commitBarrier,
		DesktopWindowsProtectionCommit{Action: p.commitAction, Previous: &previous})
}
