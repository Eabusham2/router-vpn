//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
	"time"
)

// The service keeps this run beside its original FD11 and observer. A wire
// descriptor can name that authority; it cannot replace either native owner.
func (m *linuxStandardServiceMTU) runResponse(ctx context.Context, run standardengine.OperationRun) (*linuxStandardServiceMTUResponse, error) {
	response := m.response()
	response.Run = &run
	if rejected, ok := m.rejectedRuns[run.ID]; ok {
		if rejected != run {
			return nil, errors.New("standard MTU rejected run identity changed")
		}
		response.RunState = standardengine.OperationRunClosed
		return response, ctx.Err()
	}
	retained, err := m.native.operations.OperationRunRetained(ctx, run)
	if err != nil {
		return nil, err
	}
	response.RunRetained = retained
	if !retained {
		return response, ctx.Err()
	}
	actual, state, err := m.native.operations.ReadOperationRun(ctx)
	if err != nil || actual != run {
		return nil, errors.Join(err, errors.New("standard MTU run publication remains unresolved"))
	}
	response.RunState = state
	if m.run != nil && *m.run == run {
		response.CleanupDeadlineNS = m.runCleanupDeadlineNS
	}
	if state != standardengine.OperationRunClosed {
		deadline, present, err := m.native.operations.OperationRunCleanupDeadline(ctx, run)
		if err != nil {
			return nil, err
		}
		if present {
			response.CleanupDeadlineNS = deadline.UnixNano()
			if m.run != nil && *m.run == run {
				m.runCleanupDeadlineNS = response.CleanupDeadlineNS
			}
		}
	}
	return response, ctx.Err()
}

func (m *linuxStandardServiceMTU) runRequest(ctx context.Context, action string, q *linuxStandardServiceMTURequest) (*linuxStandardServiceMTUResponse, error) {
	if q == nil || q.Run == nil {
		return nil, errors.New("standard MTU run omitted captured authority")
	}
	run := *q.Run
	empty := *q
	empty.Run = nil
	if empty != (linuxStandardServiceMTURequest{}) {
		return nil, errors.New("standard MTU run supplied transaction fields")
	}
	if _, err := run.SHA256(); err != nil {
		return nil, err
	}
	if run.CaptureSHA256 != m.native.captureSHA || run.CleanupBudgetNS != int64(standardengine.OperationRunCleanupLimit) {
		return nil, errors.New("standard MTU run changed original capture or cleanup bound")
	}
	if rejected, ok := m.rejectedRuns[run.ID]; ok {
		if rejected != run || action == "mtu-run-begin" {
			return nil, errors.New("standard MTU run was permanently rejected before admission")
		}
		return m.runResponse(ctx, run)
	}
	switch action {
	case "mtu-run-begin":
		if m.run != nil && *m.run == run {
			return m.runResponse(ctx, run)
		}
		if m.run != nil {
			prior, state, e := m.native.operations.ReadOperationRun(ctx)
			if e != nil || prior != *m.run || state != standardengine.OperationRunClosed {
				return nil, errors.Join(e, errors.New("standard MTU prior run has not joined original closure"))
			}
		}
		if m.active != nil && !m.active.settled {
			return nil, errors.New("standard MTU run preceded original transaction settlement")
		}
		ready, err := desktopnetwork.ParseDesktopNetworkReceipt(m.ready)
		if err != nil || run.Original != m.current || run.OriginalMTU != ready.MTU || run.Original.InitialReceiptSHA256 != standardengine.SHA256([]byte(m.ready)) {
			return nil, errors.Join(err, errors.New("standard MTU run changed original current reader"))
		}
		if err = m.native.tracker.CurrentContext(ctx); err != nil {
			return nil, err
		}
		// Keep a possible published admission even when its acknowledgement expires.
		captured := run
		m.run = &captured
		m.runCleanupDeadlineNS = 0
		if err = m.native.operations.BeginOperationRun(ctx, run); err != nil {
			return nil, err
		}
		return m.runResponse(ctx, run)
	case "mtu-run-cleanup":
		retained, e := m.native.operations.OperationRunRetained(ctx, run)
		if e != nil {
			return nil, e
		}
		if !retained {
			return m.runRequest(ctx, "mtu-run-close", q)
		}
		if m.run == nil || *m.run != run {
			return nil, errors.New("standard MTU cleanup lost original run")
		}
		current, state, e := m.native.operations.ReadOperationRun(ctx)
		if e != nil || current != run {
			return nil, errors.Join(e, errors.New("standard MTU cleanup changed original run"))
		}
		if state == standardengine.OperationRunClosed {
			return m.runResponse(ctx, run)
		}

		if _, err := m.native.operations.ActivateOperationRunCleanup(ctx, run); err != nil {
			return nil, err
		}
	case "mtu-run-close":
		retained, err := m.native.operations.OperationRunRetained(ctx, run)
		if err != nil {
			return nil, err
		}
		if !retained {
			// Close can overtake a lost Begin. Its exact tombstone prevents a delayed
			// packet from creating a new run after the controller drops its authority.
			if len(m.rejectedRuns) >= standardengine.OperationTransactions {
				return nil, errors.New("standard MTU run rejection capacity exhausted")
			}
			if m.rejectedRuns == nil {
				m.rejectedRuns = make(map[string]standardengine.OperationRun)
			}
			m.rejectedRuns[run.ID] = run
			if m.run != nil && *m.run == run {
				m.run = nil
				m.runCleanupDeadlineNS = 0
			}
			return m.runResponse(ctx, run)
		}
		if m.run == nil || *m.run != run || m.active != nil && !m.active.settled {
			return nil, errors.New("standard MTU run closure preceded both original observers")
		}
		_, state, e := m.native.operations.ReadOperationRun(ctx)
		if e != nil {
			return nil, e
		}
		if state != standardengine.OperationRunClosed {
			deadline, present, e := m.native.operations.OperationRunCleanupDeadline(ctx, run)
			if e != nil {
				return nil, e
			}
			if present {
				m.runCleanupDeadlineNS = deadline.UnixNano()
				if !time.Now().Before(deadline) {
					return nil, context.DeadlineExceeded
				}
				bound, cancel := context.WithDeadline(ctx, deadline)
				defer cancel()
				ctx = bound
			}
		}
		if err = m.native.operations.RequestOperationRunClosure(ctx, run); err != nil {
			return nil, err
		}
	case "mtu-run-status":
		if m.run != nil && *m.run != run {
			return nil, errors.New("standard MTU status changed original run")
		}
	default:
		return nil, errors.New("standard MTU run action is unavailable")
	}
	return m.runResponse(ctx, run)
}

func (m *linuxStandardServiceMTU) bindRunCommand(ctx context.Context, q *linuxStandardServiceMTURequest) error {
	if q == nil || q.Run == nil || m.run == nil || *q.Run != *m.run {
		return errors.New("standard MTU command has no original shared run")
	}
	run, state, err := m.native.operations.ReadOperationRun(ctx)
	if err != nil || run != *m.run || state != standardengine.OperationRunOpen {
		return errors.Join(err, errors.New("standard MTU command replaced or closed its run"))
	}
	if q.CleanupOnly {
		deadline, present, err := m.native.operations.OperationRunCleanupDeadline(ctx, run)
		if err != nil || !present || q.MTU != run.OriginalMTU || q.DeadlineNS > deadline.UnixNano() {
			return errors.Join(err, errors.New("standard MTU cleanup changed original restore target or clock"))
		}
	} else {
		_, active, err := m.native.operations.OperationRunCleanupDeadline(ctx, run)
		if err != nil || active || q.DeadlineNS > run.WorkDeadlineNS {
			return errors.Join(err, errors.New("standard MTU candidate exceeded original work authority"))
		}
	}
	return ctx.Err()
}

func (m *linuxStandardServiceMTU) runObservationCurrent(ctx context.Context) error {
	if m.run == nil {
		return errors.New("standard MTU active transaction has no original run")
	}
	run, state, err := m.native.operations.ReadOperationRun(ctx)
	if err != nil || run != *m.run || state == standardengine.OperationRunClosed {
		return errors.Join(err, errors.New("standard MTU active transaction lost its original run"))
	}
	deadline, present, err := m.native.operations.OperationRunCleanupDeadline(ctx, run)
	if err != nil {
		return err
	}
	if !present && time.Now().UnixNano() > run.WorkDeadlineNS+run.CleanupBudgetNS {
		return errors.New("standard MTU original work and cleanup age expired")
	}

	if present && !time.Now().Before(deadline) {
		return errors.New("standard MTU original shared cleanup deadline expired")
	}
	return ctx.Err()
}

func (m *linuxStandardServiceMTU) acknowledgeRejection(ctx context.Context, q *linuxStandardServiceMTURequest) error {
	if err := m.matches(q); err != nil {
		return err
	}
	op := m.active
	if !op.noSubmission || !op.ended || op.run == nil {
		return errors.New("standard MTU rejection acknowledgement preceded original completion")
	}
	if op.runBound {
		if err := m.native.operations.AcknowledgeUnsubmitted(ctx, op.command.Reservation, standardengine.ControllerObserver); err != nil {
			return err
		}
	}
	op.settled = true
	return ctx.Err()
}
