//go:build go1.25

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Exercise the real retirement path with only its native child boundary
// modeled. After that child joins, receipt admission must still belong to the
// original cleanup caller; a held workspace cannot strand cancelled cleanup.
func TestDesktopOwnedNodeRetirementReceiptReadKeepsCaller(t *testing.T) {
	launch := &desktopNodeLaunch{ownedNode: &desktopOwnedNodeRuntime{}}
	attempt := &desktopNodeProtectionAttempt{launch: launch}
	slot := &desktopNodeProtectionSlot{active: attempt}
	launch.ownedNode.attempt, launch.ownedNode.slot = attempt, slot
	a := &app{nodeProtection: slot}
	locked := make(chan struct{})
	process := &desktopOwnedNodeTestProcess{started: true, join: func() {
		launch.workspaceMu.Lock()
		close(locked)
	}}
	launch.ownedNode.process = process
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &desktopNodeMTUWaitingContext{Context: parent, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- a.retireDesktopOwnedNode(ctx, launch) }()
	<-locked
	var released sync.Once
	unlock := func() { released.Do(launch.workspaceMu.Unlock) }
	defer unlock()
	select {
	case <-ctx.waiting:
	case <-time.After(time.Second):
		cancel()
		unlock()
		<-done
		t.Fatal("retirement receipt admission discarded its cleanup caller")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("held receipt read lost original cancellation", err)
		}
	case <-time.After(time.Second):
		unlock()
		<-done
		t.Fatal("cancelled receipt read waited for an unrelated workspace release")
	}
	if !process.closed || launch.ownedNode.retired || slot.active != attempt {
		t.Fatal("cancelled receipt admission lost its joined child or released unproved protection")
	}
}
