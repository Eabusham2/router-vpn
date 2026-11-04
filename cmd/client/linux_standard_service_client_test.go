//go:build linux

package main

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestLinuxStandardServiceStaleStopCannotCancelCurrentMonitor(t *testing.T) {
	f := newStandardMonitorFixture(t)
	f.start(t, func(context.Context) error { return nil }, nil)
	stop := &linuxStandardServiceStop{owner: f.o, command: f.o.Command(), operation: f.op}
	f.a.mu.Lock()
	f.a.connectionContext = context.Background()
	f.a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := stop.Retire(ctx, f.o.Command(), true); err == nil {
		t.Fatal("obsolete Stop acquired current runtime")
	}
	if f.m.ctx.Err() != nil {
		t.Fatal("rejected old Stop cancelled the current observer")
	}
	if actual, ok := linuxStandardServiceMonitors.Load(f.o); !ok || actual != f.m {
		t.Fatal("rejected old Stop discarded current monitor")
	}
}

func TestLinuxStandardServiceShippingOwnershipGuardKeepsCallerLock(t *testing.T) {
	a := &app{}
	command := exec.Command("unstarted-original-service-request")
	o := &linuxStandardServiceLaunch{app: a, prepared: &linuxLegacyStandardExitOwner{command: command}}
	a.cmd = command
	linuxStandardServiceOwners.Store(a, o)
	defer linuxStandardServiceOwners.Delete(a)
	joined := make(chan bool, 1)
	go func() {
		// platformStandardExitConnectOwned holds this same state lock across
		// the production ownership guard and its final state transition.
		a.mu.Lock()
		defer a.mu.Unlock()
		joined <- legacyStandardExitFailureOwned(a, o, false)
	}()
	select {
	case owned := <-joined:
		if !owned {
			t.Fatal("shipping guard rejected original remote runtime")
		}
	case <-time.After(time.Second):
		t.Fatal("shipping remote ownership guard recursively locked app state")
	}
	a.mu.Lock()
	a.cmd = nil
	o.joined = true
	if !legacyStandardExitFailureOwned(a, o, true) {
		t.Fatal("joined original cleanup lost ownership")
	}
	linuxStandardServiceOwners.Store(a, &linuxStandardServiceLaunch{})
	if legacyStandardExitFailureOwned(a, o, true) {
		t.Fatal("retired original adopted a replacement")
	}
	a.mu.Unlock()
}
