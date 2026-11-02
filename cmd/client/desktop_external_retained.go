package main

import (
	"context"
	"sync"
)

// A retained adapter belongs to the original native host/session. It is never
// an alternative process waiter, Stop authority or source of serialized proof.
type desktopExternalRetainedRuntime interface {
	Stage(context.Context) error
	Start(context.Context) error
	Activate(context.Context) error
	Monitor(context.Context) error
	Close(context.Context) error
	ProcessDone() <-chan struct{}
	CurrentProof(context.Context, desktopExternalProof) error
}

// This index exposes the existing retained external launch to measurements.
// Every observation still checks its original session, process and proof. The
// legacy process-owner registry stays empty, and retirement uses only the
// original native session/journal chain.
var desktopExternalRetainedLaunches sync.Map // *app -> *desktopNodeLaunch

func lookupDesktopNativeLaunch(a *app) (any, bool) {
	if value, found := desktopNodeOwners.Load(a); found {
		return value, true
	}
	return desktopExternalRetainedLaunches.Load(a)
}
