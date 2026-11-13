package main

import (
	"context"
	"errors"
	"os"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
)

func prepareDesktopCandidatePrefixHost(ctx context.Context, p *orderedCandidatePreparation) (*desktopNodeLaunch, error) {
	if p == nil || p.prefixPreparation == nil || p.request.Scope != orderedCandidateSavedPrefixScope {
		return nil, errors.New("prefix host requires its captured closed preparation")
	}
	capture, err := captureDesktopNodeChainHostContext(ctx, p.app, p.selection)
	if err != nil {
		return nil, err
	}
	var launch *desktopNodeLaunch
	var binary string
	if capture.windows != nil {
		binary, err = verifiedDesktopImportedPackage(ctx, capture.windows)
		if err == nil {
			launch, err = prepareDesktopOwnedCandidatePrefixLaunch(ctx, capture, p.selection, p)
		}
	} else if capture.platform != nil {
		launch, binary, err = capture.platform.prepareCandidatePrefixForPurpose(ctx, capture, p.selection, p)
	} else {
		err = errors.New("prefix host has no accepted concrete native controller")
	}
	if err != nil {
		return launch, err
	}
	// The exact preparation retains every partial native owner for cancellation.
	// Preflight only validates the closed projected config and real dispatcher.
	if err := preflightRetainedNativeMultihop(ctx, binary, launch, runDesktopExternalPreflightCommand); err != nil {
		return launch, err
	}
	return launch, nil
}

func desktopCandidatePrefixCurrent(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if launch == nil || launch.candidatePrefix == nil || launch.chain != nil {
		return errors.New("prefix observation lost its distinct original launch")
	}
	if platform := launch.candidatePrefix.platform; platform != nil {
		return platform.current(ctx)
	}
	return desktopOwnedCandidatePrefixCurrent(ctx, a, launch)
}

func desktopCandidatePrefixReadyBudget(launch *desktopNodeLaunch) (time.Duration, error) {
	if launch == nil || launch.candidatePrefix == nil || launch.candidatePrefix.policy == nil ||
		launch.candidatePrefix.policy.Validate() != nil {
		return 0, errors.New("prefix startup lost its finite sealed proof inventory")
	}
	count := launch.candidatePrefix.policy.Metadata().PrefixPosition + 1
	if count < 1 || count > 7 {
		return 0, errors.New("prefix startup changed its bounded proof count")
	}
	// The shared prefix proof has 15+5*N seconds. Ten seconds belong to the
	// original native startup/reader handoff; the enclosing preparation is finite.
	return time.Duration(25+5*count) * time.Second, nil
}

func awaitDesktopCandidatePrefixReady(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if launch.candidatePrefix.platform != nil {
		return launch.candidatePrefix.platform.activate(ctx)
	}
	budget, err := desktopCandidatePrefixReadyBudget(launch)
	if err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		// Only absent first receipts may wait. Changed/malformed proof or a lost
		// original native process is a terminal failure, never a readiness retry.
		if err := a.desktopOwnedNodeCurrentContext(call, launch, true); err != nil {
			return err
		}
		if _, err := readDesktopRuntimeFileContext(call, launch, "node-mtu-status.json", 16384); err == nil {
			_, err = a.readDesktopOwnedCandidatePrefixReadyContext(call, launch, true)
			if err == nil {
				return call.Err()
			}
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-call.Done():
			return call.Err()
		case <-desktopNodeProcessDone(launch):
			return errors.New("original prefix child exited before its private proof")
		case <-ticker.C:
		}
	}
}

func (p *orderedCandidatePreparation) startPrefixRuntime(ctx context.Context, r *orderedCandidatePreparedRuntime) (*orderedCandidatePreparedRuntime, error) {
	launch, err := prepareDesktopCandidatePrefixHost(ctx, p)
	if err != nil {
		return r, err
	}
	if launch != p.launch || !orderedCandidateLaunchBound(p, launch) {
		return r, errors.New("prefix runtime changed its original native purpose")
	}
	if err := p.app.guardDesktopOwnedNodeTransitionContext(ctx, launch); err != nil {
		return r, err
	}
	if err := p.sourceCurrent(ctx); err != nil {
		return r, err
	}
	if err := r.cohort.Begin(ctx, nil); err != nil {
		return r, err
	}
	r.transition = true
	if platform := launch.candidatePrefix.platform; platform != nil {
		if err = platform.stage(ctx); err == nil {
			err = platform.start(ctx)
		}
	} else {
		err = stageDesktopNodeLaunchContext(ctx, p.app, launch)
		if err == nil {
			err = desktopnetwork.LockContext(ctx, &p.app.mu)
			if err == nil {
				err = p.app.publishDesktopCandidatePrefixStartLocked(p.operation, launch, p.selection)
				p.app.mu.Unlock()
			}
		}
		if err == nil {
			err = startDesktopOwnedCandidatePrefixLaunch(ctx, p.operation, p.app, launch)
		}
	}
	if err != nil {
		return r, err
	}
	if err := awaitDesktopCandidatePrefixReady(ctx, p.app, launch); err != nil {
		return r, err
	}
	if err := desktopCandidatePrefixCurrent(ctx, p.app, launch); err != nil {
		return r, err
	}
	r.live, err = readDesktopNodeMTUContext(ctx, launch)
	if err != nil || r.live.Active || r.live.Failure != "" {
		return r, errors.Join(err, errors.New("prefix preparation lost its original closed native reader"))
	}
	r.receipt, err = parseDesktopCohortReceipt(r.live.NetworkReceipt, r.live.Interface, r.live.Index, r.live.MTU)
	if err != nil {
		return r, err
	}
	if err := r.cohort.RecordContext(ctx, *r.receipt); err != nil {
		return r, err
	}
	if err := r.cohort.End(ctx, r.receipt); err != nil {
		return r, err
	}
	r.transition = false
	// This remains the original source-only full graph, never a native graph.
	r.catalog, err = captureDesktopNodeChainCandidateSources(ctx, p.app, p.inventory.launch, p.request.Position, p.request.CandidateIDs)
	if err != nil || !orderedCandidateSameInventory(p.inventory, r.catalog) {
		return r, errors.Join(err, errors.New("prefix preparation changed its captured saved inventory"))
	}
	if err := p.sourceCurrent(ctx); err != nil {
		return r, err
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return r, err
	}
	_, err = orderedCandidateLaunchPurposeLocked(p.app, launch)
	if err == nil && (p.app.cmd != launch.command || p.app.state.Connected) {
		err = errors.New("prefix preparation lost its original private testing owner")
	}
	if err == nil {
		p.app.state.Phase, p.app.state.LastError = "candidate:testing", ""
	}
	p.app.mu.Unlock()
	if err != nil {
		return r, err
	}
	return r, r.current(ctx)
}

func validateOrderedCandidatePreparedStatus(p *orderedCandidatePreparation, id string, status hopmeasure.CandidateStatus, now time.Time) error {
	if p == nil {
		return errors.New("candidate receipt has no captured preparation")
	}
	if p.prefixPreparation != nil {
		return validateDesktopNodeCandidatePrefixStatus(p.prefixPreparation, id, status, now)
	}
	if p.runtime == nil || p.runtime.catalog == nil {
		return errors.New("candidate receipt has no original complete saved inventory")
	}
	return validateDesktopNodeChainCandidateStatus(p.runtime.catalog.plan, id, status, now)
}
