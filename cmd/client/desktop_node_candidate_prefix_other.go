//go:build !linux

package main

import (
	"context"
	"errors"
)

// Windows uses its captured owned-node host. Darwin remains unavailable until
// its actual prefix PF/utun lifecycle has earned native acceptance.
func (*desktopNodeChainPlatformCapture) prepareCandidatePrefixForPurpose(context.Context, *desktopNodeChainHostCapture, multihopSelection, *orderedCandidatePreparation) (*desktopNodeLaunch, string, error) {
	return nil, "", errors.New("candidate prefix native platform admission is unavailable")
}
