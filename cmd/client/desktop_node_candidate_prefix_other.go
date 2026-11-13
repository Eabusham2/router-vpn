//go:build !linux && !darwin

package main

import (
	"context"
	"errors"
)

// Windows uses its captured owned-node host. Other targets have no concrete
// platform adapter; public admission remains a separate accepted-capability gate.
func (*desktopNodeChainPlatformCapture) prepareCandidatePrefixForPurpose(context.Context, *desktopNodeChainHostCapture, multihopSelection, *orderedCandidatePreparation) (*desktopNodeLaunch, string, error) {
	return nil, "", errors.New("candidate prefix native platform admission is unavailable")
}
