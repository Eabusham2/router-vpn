//go:build darwin

package main

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestDesktopMacOSMTUCleanupMonitorRetriesOnlyItsOriginalObservation(t *testing.T) {
	owner, _ := desktopMacOSMTUComparisonFixture(t)
	h, launch := owner.host, owner.launch
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	if err := h.enter(ctx); err != nil {
		t.Fatal(err)
	}
	before := h.mtuObservation.value.Load()
	finish, err := owner.beginCleanupObservationLocked(ctx)
	if err != nil {
		h.gate <- struct{}{}
		t.Fatal(err)
	}
	active := h.mtuObservation.value.Load()
	// Exercise the production host wait that a health observation uses while
	// the same native rollback retains the host gate. No scheduling sleep.
	observation, endObservation := context.WithCancel(context.Background())
	endObservation()
	if err := h.enter(observation); err == nil {
		finish()
		h.gate <- struct{}{}
		t.Fatal("observer entered a host still owned by rollback")
	}
	if !h.mtuObservation.deferFailure(h, launch, before) || !h.mtuObservation.deferFailure(h, launch, active) {
		finish()
		h.gate <- struct{}{}
		t.Fatal("bounded original cleanup did not defer its blocked observer")
	}
	finish()
	h.gate <- struct{}{}
	if !h.mtuObservation.deferFailure(h, launch, before) {
		t.Fatal("cleanup completing during a failed observation lost its one fresh recheck")
	}
	if h.mtuObservation.deferFailure(h, launch, active) {
		t.Fatal("an old completed cleanup concealed a later path failure")
	}
	cancel()
	if !h.mtuObservation.deferFailure(h, launch, before) {
		t.Fatal("completed caller cancellation erased its concurrent observation receipt")
	}
	if err := h.enter(context.Background()); err != nil {
		t.Fatal("completed cleanup retained the native observation gate", err)
	}
	h.gate <- struct{}{}
}

func TestDesktopMacOSMTUCleanupMonitorRejectsUnboundedForeignOrExpiredClaims(t *testing.T) {
	for _, fault := range []string{"nil-caller", "unbounded", "extended", "cancelled", "foreign-owner", "nested"} {
		t.Run(fault, func(t *testing.T) {
			owner, _ := desktopMacOSMTUComparisonFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
			defer cancel()
			var caller context.Context = ctx
			switch fault {
			case "nil-caller":
				caller = nil
			case "unbounded":
				caller = context.Background()
			case "extended":
				long, stop := context.WithTimeout(context.Background(), time.Minute)
				defer stop()
				caller = long
			case "cancelled":
				cancel()
			case "foreign-owner":
				owner.host.mtu = &desktopMacOSNodeMTUOwner{}
			case "nested":
				finish, err := owner.beginCleanupObservationLocked(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer finish()
			}
			before := owner.host.mtuObservation.value.Load()
			finish, err := owner.beginCleanupObservationLocked(caller)
			if err == nil || finish != nil || owner.host.mtuObservation.value.Load() != before {
				if finish != nil {
					finish()
				}
				t.Fatal("invalid cleanup replaced or acquired the original observation", fault)
			}
		})
	}
	owner, _ := desktopMacOSMTUComparisonFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	finish, err := owner.beginCleanupObservationLocked(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer finish()
	h, launch := owner.host, owner.launch
	current := h.mtuObservation.value.Load()
	if h.mtuObservation.deferFailure(&desktopMacOSNodeChainHost{}, launch, nil) ||
		h.mtuObservation.deferFailure(h, &desktopNodeLaunch{command: &exec.Cmd{}}, nil) ||
		h.mtuObservation.deferFailure(h, nil, nil) {
		cancel()
		t.Fatal("original cleanup deferred a foreign host, launch or command")
	}
	originalCommand := launch.command
	launch.command = &exec.Cmd{}
	if h.mtuObservation.deferFailure(h, launch, nil) {
		cancel()
		t.Fatal("original cleanup adopted a replacement command on the same launch")
	}
	launch.command = originalCommand
	cancel()
	if h.mtuObservation.deferFailure(h, launch, current) {
		t.Fatal("expired cleanup suppressed ongoing failure observation")
	}
}
