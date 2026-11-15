//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"time"
)

// Supported single Router graphs always select their captured installed parent.
// A missing package/controller cannot silently fall through to a legacy helper.
func (a *app) startDesktopMacOSPairedNodeConnection(operation context.Context, profile common.RouterProfile, mode common.Mode, options [3]bool, holdOnFailure bool, transition ...*modeAttemptTransition) (handled bool, failure error) {
	if !mobilemultihop.DesktopLinuxNodePhysicalGraphSupported(mode.ID, profile.StartLayer) {
		return false, nil
	}
	if len(transition) > 1 {
		return true, errors.New("macOS Router connection has multiple transition owners")
	}
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return true, err
	}
	profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled = options[0], options[1], options[2]
	h, err := prepareDesktopMacOSPairedNodeHost(operation, a, profile, mode.ID, 0)
	if h != nil {
		defer func() {
			if failure != nil {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(operation), 20*time.Second)
				defer cancel()
				failure = errors.Join(failure, h.closeWithIntent(cleanup, holdOnFailure))
			}
		}()
	}
	if err != nil {
		return true, err
	}
	ctx, cancel := context.WithTimeout(operation, 7*time.Minute)
	defer cancel()
	if err := h.Stage(ctx); err != nil {
		return true, err
	}
	if len(transition) == 1 && transition[0] != nil {
		transition[0].StopBegun = true
	}
	if err := a.stopModeWithIntent(true); err != nil {
		return true, err
	}
	if err := h.Start(ctx); err != nil {
		return true, err
	}
	if err := a.speedLabOwnRuntime(h.launch.command); err != nil {
		return true, err
	}
	ready, stopReady := context.WithTimeout(ctx, 25*time.Second)
	err = h.WaitReady(ready)
	stopReady()
	if err != nil {
		return true, err
	}
	elapsed, err := h.Prove(ctx)
	if err != nil {
		return true, fmt.Errorf("%s started but selected-router path proof failed: %w", mode.Name, err)
	}
	if err := h.Activate(ctx); err != nil {
		return true, err
	}
	if err := h.Monitor(ctx); err != nil {
		return true, err
	}
	a.mu.Lock()
	if usageErr := a.recordProfileUsageLocked(profile.ID, time.Now().UTC()); usageErr != nil {
		log.Printf("profile usage metadata was not persisted: %v", usageErr)
	}
	a.mu.Unlock()
	log.Printf("mode %s selected-router path proof OK in %.2f ms", mode.ID, float64(elapsed.Microseconds())/1000)
	a.startRouterNodeAutomaticMTU()
	return true, nil
}
