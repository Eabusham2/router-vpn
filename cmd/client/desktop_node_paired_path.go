package main

import (
	"context"
	"errors"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Restoration holds only original source and parent authority. A fresh runtime
// must prove its own new native child/DNS/utun and paired private response.
type desktopMacOSPairedNodeRestore interface {
	clear()
	restart(context.Context, *app, common.RouterProfile) error
}

func (a *app) readDesktopRouterReadyContext(ctx context.Context, launch *desktopNodeLaunch, fresh bool) (mobilemultihop.DesktopNodeReadyRecord, error) {
	if launch == nil || launch.ownedNode != nil && launch.pairedNode != nil {
		return mobilemultihop.DesktopNodeReadyRecord{}, errors.New("Router readiness has conflicting original native hosts")
	}
	if launch.pairedNode != nil {
		if fresh {
			return mobilemultihop.DesktopNodeReadyRecord{}, errors.New("paired Router fresh readiness belongs only to its startup host")
		}
		return launch.pairedNode.Ready(ctx)
	}
	return a.readDesktopOwnedNodeReadyContext(ctx, launch, fresh)
}
