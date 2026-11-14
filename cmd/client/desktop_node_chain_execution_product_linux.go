//go:build linux

package main

import (
	"context"
	"errors"
)

// Capture the stop transaction from this concrete original platform owner,
// never from whichever host happens to be current in the application.
func (platform *desktopNodeChainPlatformRuntime) captureExecutionProductStop(ctx context.Context, s *desktopNodeChainExecutionSession) (desktopRetainedStopCapture, error) {
	if ctx == nil || s == nil || s.launch == nil || s.launch.chain == nil ||
		s.launch.chain.platform != platform || platform == nil || platform.capture == nil ||
		platform.capture.app != s.app {
		return nil, errors.New("ordered Linux Stop lost its original platform session")
	}
	// A preparation that never entered native staging owns no transaction.
	// Session.Close already joined its exact no-process outcome before this
	// branch can release only the product registry.
	if s.closed && !platform.registered && (platform.host == nil ||
		platform.host.process == nil && platform.host.transaction == nil && !platform.host.stageEntered && !platform.host.startEntered) {
		return nil, nil
	}
	if s.closed && platform.registered && platform.session == nil && platform.host != nil {
		h := platform.host
		if err := h.enter(ctx); err != nil {
			return nil, err
		}
		unentered := h.closed && h.released && !h.stageEntered && !h.startEntered && h.process == nil && h.transaction == nil &&
			platform.capture.platform != nil && h.parent == platform.capture.platform.parent
		h.gate <- struct{}{}
		if unentered {
			if err := h.parent.retirementCurrent(ctx); err != nil {
				return nil, err
			}
			p := h.parent.parent
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-p.gate:
			}
			_, retained := p.dependents[h]
			p.gate <- struct{}{}
			if !retained {
				return nil, nil
			}
		}
	}
	if platform.session == nil || platform.host == nil {
		return nil, errors.New("ordered Linux Stop lost its entered native session")
	}
	captured, err := s.app.captureDesktopNodeStopContext(ctx)
	if err != nil {
		return nil, err
	}
	if captured == nil && s.closed {
		if err := platform.host.enter(ctx); err != nil {
			return nil, err
		}
		joined := platform.host.closed && platform.host.released
		platform.host.gate <- struct{}{}
		if joined {
			if err := platform.session.enter(ctx); err != nil {
				return nil, err
			}
			empty := platform.session.active == nil && platform.session.predecessor == nil && platform.session.off == nil && platform.session.journalErr == nil
			var proofErr error
			if empty {
				proofErr = platform.session.unclaimedStopLocked(ctx)
			}
			platform.session.gate <- struct{}{}
			if empty && proofErr == nil {
				return nil, nil
			}
			if proofErr != nil {
				return nil, proofErr
			}
		}
	}
	// A failed Connect may already have positively joined this exact host.
	// Its original session can still retain that transaction's deny baseline;
	// permit only that predecessor (or proved absence), never a successor.
	sameHost := captured != nil && captured.host == platform.host && captured.command == s.launch.command
	if captured != nil && s.closed && captured.host == nil && captured.command == nil &&
		(captured.predecessor == nil || captured.predecessor == platform.host.transaction) {
		sameHost = true
	}
	if captured == nil || captured.session != platform.session || !sameHost || captured.app != s.app {
		return nil, errors.New("ordered Linux Stop captured a replacement native transaction")
	}
	return captured, nil
}
