package main

import (
	"os/exec"
	"testing"
	"time"
)

func TestDesktopTorMonitorClaimsOnlyItsCurrentTransaction(t *testing.T) {
	command, replacement := &exec.Cmd{}, &exec.Cmd{}
	a := &app{cmd: command}
	release, current := a.claimRuntimeMonitorOperation(command)
	if !current || release == nil {
		t.Fatal("current Tor monitor could not own its idle transaction")
	}
	if a.operationMu.TryLock() {
		a.operationMu.Unlock()
		t.Fatal("claimed monitor did not exclude competing operations")
	}
	release()
	a.operationMu.Lock()
	release, current = a.claimRuntimeMonitorOperation(command)
	if !current || release != nil {
		t.Fatal("monitor blocked or overlapped an active transaction")
	}
	a.operationMu.Unlock()
	for _, retired := range []*exec.Cmd{nil, replacement} {
		a.mu.Lock()
		a.cmd = retired
		a.mu.Unlock()
		for _, candidate := range []*exec.Cmd{nil, {}, command} {
			if release, current := a.claimRuntimeMonitorOperation(candidate); release != nil || current {
				if release != nil {
					release()
				}
				t.Fatal("retired monitor claimed another session's transaction")
			}
			if !a.operationMu.TryLock() {
				t.Fatal("retired monitor left a spurious busy transaction")
			}
			a.operationMu.Unlock()
		}
	}
}

func TestDesktopTorMonitorOwnerCaptureJoinsTheAppStateLock(t *testing.T) {
	command, replacement := &exec.Cmd{}, &exec.Cmd{}
	a := &app{cmd: command}
	started, done := make(chan struct{}), make(chan struct{})
	var release func()
	var current bool
	a.mu.Lock()
	go func() {
		close(started)
		release, current = a.claimRuntimeMonitorOperation(command)
		close(done)
	}()
	<-started
	select {
	case <-done:
		a.mu.Unlock()
		if release != nil {
			release()
		}
		t.Fatal("monitor captured the child outside the app-state transaction")
	case <-time.After(20 * time.Millisecond):
	}
	// Publish the replacement while still owning the state lock. The pending
	// monitor must observe it before touching the separate operation mutex.
	a.cmd = replacement
	a.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("monitor did not release a stale captured operation")
	}
	if current || release != nil {
		if release != nil {
			release()
		}
		t.Fatal("old monitor acquired the replacement transaction")
	}
	if !a.operationMu.TryLock() {
		t.Fatal("replacement was spuriously busy after retired monitor capture")
	}
	a.operationMu.Unlock()
}
