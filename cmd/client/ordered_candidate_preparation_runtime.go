package main

import (
	"context"
	"errors"

	"router-vpn/internal/desktopnetwork"
)

// Host constructors call this before registering any native partial process or
// protection owner. A failed later preflight therefore remains reachable from
// the exact preparation, even when its first retirement attempt also fails.
func newDesktopNodeChainLaunchForPurpose(ctx context.Context, selection multihopSelection, session, target string,
	purpose *orderedCandidatePreparation) (*desktopNodeLaunch, error) {
	if selection.Native != nil && selection.Native.chain != nil && selection.Native.chain.host != nil {
		a := selection.Native.chain.host.app
		if a == nil {
			return nil, errors.New("ordered constructor lost its captured controller")
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return nil, err
		}
		matched := a.candidatePreparation == purpose
		a.mu.Unlock()
		if !matched {
			return nil, errors.New("ordered constructor changed its captured temporary purpose before native registration")
		}
	}
	launch, err := newDesktopNodeChainLaunch(selection, session, target)
	if err != nil {
		return nil, err
	}
	if purpose != nil {
		if err := purpose.bindLaunch(ctx, launch); err != nil {
			clear(launch.config)
			clear(launch.metadata)
			return nil, errors.Join(err, errors.New("ordered native constructor refused the original candidate purpose"))
		}
	}
	return launch, nil
}
