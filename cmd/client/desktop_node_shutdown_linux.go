//go:build linux

package main

import (
	"context"
	"errors"
	"time"
)

// Called only by the actual terminal controller drain, under operationMu,
// before legacy process teardown. Normal Stop and temporary restoration retain
// their own captured transaction; this hook cannot create or adopt a session.
func (a *app) retireNativeNodeForShutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return a.retireNativeNodeForShutdownContext(ctx)
}

func (a *app) retireNativeNodeForShutdownContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Linux terminal retirement requires its bounded caller")
	}
	a.mu.Lock()
	controller, closing, command, operation := a.localController, a.closing, a.cmd, a.connectionContext
	a.mu.Unlock()
	var capturedMTU *mtuLiveOwner
	if raw, found := mtuLiveOwners.Load(a); found {
		capturedMTU, _ = raw.(*mtuLiveOwner)
	}
	if controller == nil || controller.nodeParent == nil {
		return nil
	}
	parent, ok := controller.nodeParent.(*desktopLinuxNodeParent)
	if !ok || parent == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-parent.gate:
	}
	transactions := append([]*desktopLinuxNodeTransaction(nil), parent.shutdownTransactions...)
	if !parent.stopping {
		for dependent := range parent.dependents {
			if transaction, ok := dependent.(*desktopLinuxNodeTransaction); ok {
				transactions = append(transactions, transaction)
			}
		}
	}
	parent.gate <- struct{}{}
	if len(transactions) == 0 && !closing {
		return nil
	}
	if !closing {
		return errors.New("Linux terminal retirement requires the application's permanent shutdown latch")
	}
	// Join the outstanding original MTU lease before retiring its child or
	// clearing cmd. Ordinary Stop cannot take over a closed admission lifetime,
	// and a failed drain must retain both the native engine and lease for retry.
	releaseMTU, err := a.holdCapturedMTU(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		handled, retireErr := prepareDesktopPlatformMTUStop(ctx, a, command, operation, capturedMTU, true, err)
		if !handled || retireErr != nil {
			return errors.Join(err, retireErr)
		}
		releaseMTU, err = a.holdCapturedMTU(ctx)
		if err != nil {
			return err
		}
	}
	defer releaseMTU()
	if len(transactions) == 0 {
		return nil
	}
	// Capture the selected actual command before touching any engine. A late
	// old shutdown must neither stop nor clear a replacement command/owner.
	a.mu.Lock()
	if a.cmd != command || a.connectionContext != operation {
		a.mu.Unlock()
		return errors.New("Linux terminal MTU drain changed its original command or operation")
	}
	var selected *desktopLinuxNodeTransaction
	for _, transaction := range transactions {
		if transaction.parent == nil || transaction.parent.app != a || transaction.parent.controller != controller ||
			transaction.parent.parent != parent || transaction.process == nil || transaction.parent.currentAppLocked(true) != nil {
			a.mu.Unlock()
			return errors.New("Linux shutdown transaction belongs to a replacement application or controller")
		}
		if command != nil && transaction.process.command == command {
			selected = transaction
		}
	}
	if command != nil && selected == nil {
		a.mu.Unlock()
		return errors.New("Linux shutdown cannot retire an unowned replacement app command")
	}
	a.mu.Unlock()
	if err := parent.prepareTransactionShutdown(ctx); err != nil {
		return err
	}
	if selected == nil {
		return nil
	}
	if err := selected.enter(ctx); err != nil {
		return err
	}
	defer func() { selected.gate <- struct{}{} }()
	if !selected.closed || !selected.released || selected.complete && (!selected.retired || !selected.engineJoined) {
		return errors.New("Linux shutdown cannot clear an unjoined original transaction")
	}
	process := selected.process
	if err := process.enter(ctx); err != nil {
		return err
	}
	defer func() { process.gate <- struct{}{} }()
	select {
	case <-process.joined:
	default:
		return errors.New("Linux shutdown app state preceded its original Cmd.Wait")
	}
	if process.command != command || process.command.ProcessState == nil || !process.closed || !process.released {
		return errors.New("Linux shutdown lost its exact joined original command receipt")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closing || a.cmd != command || selected.parent.currentAppLocked(true) != nil {
		return errors.New("Linux shutdown cannot clear a replacement app command or lifetime")
	}
	a.cmd = nil
	a.state.Connected = false
	a.state.Mode, a.state.RuntimeMode, a.state.Phase = "off", "", "off"
	return nil
}
