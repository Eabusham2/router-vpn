//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/standardengine"
)

func (m *linuxStandardServiceMTU) readOperationReport(ctx context.Context, op *linuxStandardServiceMTUOperation) (standardengine.OperationReport, error) {
	result, err := m.native.operations.ReadResult(ctx, op.command.Reservation)
	if err != nil {
		return standardengine.OperationReport{}, err
	}
	report := standardengine.OperationReport{Command: op.command, Result: result}
	for role := standardengine.OperationRole(0); role < standardengine.OperationReaders; role++ {
		binding, bindErr := m.native.operations.ReadBinding(ctx, op.command.Reservation, role)
		if bindErr != nil {
			return standardengine.OperationReport{}, bindErr
		}
		if binding == (standardengine.ReaderBinding{}) {
			continue
		}
		entry := &standardengine.OperationReaderEvidence{Binding: binding}
		if result.ReadyMask&(1<<role) != 0 {
			entry.Ready, err = m.native.operations.ReadEvidence(ctx, op.command.Reservation, role, standardengine.ReadyEvidence)
			if err != nil {
				return standardengine.OperationReport{}, err
			}
		}
		if result.RetirementMask&(1<<role) != 0 {
			entry.Retirement, err = m.native.operations.ReadEvidence(ctx, op.command.Reservation, role, standardengine.RetirementEvidence)
			if err != nil {
				return standardengine.OperationReport{}, err
			}
		}
		report.Readers[role] = entry
	}
	digest, err := standardengine.OperationResultDigest(report)
	if err != nil || digest != result.Digest {
		return standardengine.OperationReport{}, errors.Join(err, errors.New("standard MTU native evidence changed while being observed"))
	}

	return report, ctx.Err()
}

// Called only after the creating goroutine joined a successful original child
// and FD10 proved complete cleanup. The original observer is already closed;
// retaining cleanup evidence does not call Complete or adopt a healthy path.
func (m *linuxStandardServiceMTU) retainStoppedHistory(ctx context.Context) error {
	if m == nil || m.native == nil || m.session == nil || m.session.mtu != m || m.session.owner == nil || m.session.owner != m.native.owner || m.session.owner.native != m.native || m.native.mtuStopOwner != m {
		return errors.New("standard MTU Stop history lost its original session or native owner")
	}
	op := m.active
	if op == nil || op.noSubmission {
		return ctx.Err()
	}
	report, err := m.readOperationReport(ctx, op)
	if err != nil {
		return err
	}
	if !report.Result.WorkerJoined || report.Result.Pending || op.report != nil && op.report.Result.Revision > report.Result.Revision {
		return errors.New("standard MTU Stop has no complete joined original history")
	}
	current, err := validateLinuxStandardServiceMTUReport(report, op.original)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = m.native.retainMTURetirements(report); err != nil {
		return err
	}
	if current != nil {
		m.native.retainRoutingReceipt(*current)
	} else {
		m.native.routingReceipt = nil
	}
	op.report = &report
	op.historyValid = true
	return ctx.Err()
}

// Caller retains launch.mu; the original connection intent is checked around
// the service Stop. A received Stop acknowledgement is never itself native
// evidence: the exact cached FD11 history must still retire this controller's
// original token before its epoch/copies can be released.
func (s *linuxStandardServiceStop) stopPendingMTULocked(ctx context.Context, release bool) (bool, error) {
	o := s.owner
	owner := o.mtuOwner
	if owner == nil || owner.pending == nil {
		return false, nil
	}
	if !o.attempted || owner.launch != o {
		return false, errors.New("standard MTU Stop lost its original admitted owner")
	}
	pending := owner.pending
	if err := o.currentIntentContext(ctx, s.operation, s.command); err != nil {
		return false, err
	}
	request := linuxStandardServiceRequest{Schema: 1, Action: "stop", Session: o.request.Session, Release: release}
	if err := o.call(ctx, request, nil); err != nil {
		return false, err
	}
	if err := o.currentIntentContext(ctx, s.operation, s.command); err != nil {
		return true, err
	}
	if o.mtuOwner != owner || owner.pending != pending {
		return true, errors.New("standard MTU Stop replaced its captured pending reservation")
	}
	_, err := owner.finishStopLocked(ctx)
	if owner.pending != nil {
		return true, errors.Join(err, errors.New("standard MTU Stop has not consumed its original joined history"))
	}
	return true, err
}

// Only the network epoch read changes during an admitted transition. Callers
// retain their original process, policy, source and DNS receipt checks.
func (s *linuxStandardService) observationNetworkCurrent(ctx context.Context, session *linuxStandardServiceSession, required bool) error {
	if session != nil && session.mtu != nil && session.mtu.active != nil && !session.mtu.active.ended {
		return s.watchNetworkCurrent(ctx, session)
	}
	return s.networkCurrent(ctx, session, required)
}
