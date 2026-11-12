//go:build darwin

package main

import (
	"context"
	"errors"
	"os/exec"
	"sync/atomic"
	"time"
)

// Only the original host's bounded cleanup can defer a failed health
// observation. Retest as a whole never suspends monitoring. Keep the last
// receipt after completion so a timeout racing that completion is retried.
type desktopMacOSMTUObservationSlot struct {
	value atomic.Pointer[desktopMacOSMTUCleanupObservation]
}

type desktopMacOSMTUCleanupObservation struct {
	host    *desktopMacOSNodeChainHost
	launch  *desktopNodeLaunch
	command *exec.Cmd
	caller  context.Context
	done    atomic.Bool
}

// The caller holds host.gate and has retained the original cleanup owner.
// This does not take operationMu: explicit Stop may already own that lock.
func (owner *desktopMacOSNodeMTUOwner) beginCleanupObservationLocked(ctx context.Context) (func(), error) {
	if err := owner.originalLocked(); err != nil {
		return nil, err
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("macOS MTU cleanup lost its original bounded caller")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 14*time.Second {
		return nil, errors.New("macOS MTU cleanup observation requires its unchanged cleanup budget")
	}
	h := owner.host
	if previous := h.mtuObservation.value.Load(); previous != nil && !previous.done.Load() {
		return nil, errors.New("macOS MTU cleanup observation still belongs to its original caller")
	}
	receipt := &desktopMacOSMTUCleanupObservation{host: h, launch: owner.launch,
		command: owner.launch.command, caller: ctx}
	h.mtuObservation.value.Store(receipt)
	return func() { receipt.done.Store(true) }, nil
}

func (slot *desktopMacOSMTUObservationSlot) deferFailure(h *desktopMacOSNodeChainHost, launch *desktopNodeLaunch,
	before *desktopMacOSMTUCleanupObservation) bool {
	if slot == nil || h == nil || launch == nil || launch.command == nil {
		return false
	}
	current := slot.value.Load()
	if current == nil || current.host != h || current.launch != launch || current.command != launch.command || current.caller == nil {
		return false
	}
	// A cleanup that started during this observation can finish just as the
	// two-second observer expires. Recheck once even if its caller is already
	// canceled; an older completed receipt cannot defer the next observation.
	if current != before {
		return true
	}
	return !current.done.Load() && current.caller.Err() == nil
}
