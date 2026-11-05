//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/mobilemtu"
)

func TestLinuxStandardMTUOwnerDoesNotWaitPastCallerForLaunchLock(t *testing.T) {
	launch := &linuxStandardServiceLaunch{}
	owner := &linuxStandardServiceMTUOwner{launch: launch}
	launch.mu.Lock()
	defer launch.mu.Unlock()
	for _, test := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"capture", func(ctx context.Context) error { _, err := owner.CaptureContext(ctx); return err }},
		{"change", func(ctx context.Context) error { _, err := owner.ChangeMTU(ctx, mobilemtu.State{}, 1400); return err }},
		{"rollback", func(ctx context.Context) error {
			_, err := owner.RollbackStateContext(ctx, mobilemtu.State{})
			return err
		}},
		{"dial", func(ctx context.Context) error {
			_, err := owner.DialThroughTunnel(ctx, mobilemtu.State{}, "tcp", "1.1.1.1:443")
			return err
		}},
		{"constructor", func(ctx context.Context) error { _, err := newLinuxStandardServiceMTUOwner(ctx, launch); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- test.run(ctx) }()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("lost original deadline: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("owner remained queued after caller deadline")
			}
		})
	}
}
func TestLinuxStandardMTUExitCapturedBeforeStartIsDeepFrozen(t *testing.T) {
	launch := &linuxStandardServiceLaunch{prepared: &linuxLegacyStandardExitOwner{routerID: "standard:original", runtimeMode: "standard-socks5"}}
	exit := standardExit{ID: "original", Protocol: "socks5", ExpectedPublicIP: "203.0.113.1", WGAddresses: []string{"10.0.0.1/32"}, AWGParameters: map[string]string{"jmin": "4"}}
	if err := launch.CaptureMTUExit(exit); err != nil {
		t.Fatal(err)
	}
	exit.WGAddresses[0] = "10.0.0.2/32"
	exit.AWGParameters["jmin"] = "99"
	exit.ExpectedPublicIP = "203.0.113.2"
	if launch.mtuExit.WGAddresses[0] != "10.0.0.1/32" || launch.mtuExit.AWGParameters["jmin"] != "4" || launch.mtuExit.ExpectedPublicIP != "203.0.113.1" {
		t.Fatal("source edit replaced original exit authority")
	}
	if launch.CaptureMTUExit(exit) == nil {
		t.Fatal("captured a fresh exit on retained launch")
	}
	fresh := &linuxStandardServiceLaunch{prepared: launch.prepared, attempted: true}
	if fresh.CaptureMTUExit(exit) == nil {
		t.Fatal("captured exit after native launch")
	}
}

func TestLinuxStandardMTUUsesActivationAfterActualConnectCompletion(t *testing.T) {
	privateOperationRoot(t)
	f := newStandardMonitorFixture(t)
	f.finish()
	f.a.mu.Lock()
	f.a.state.Connected = false
	f.a.state.Phase = "off"
	f.a.mu.Unlock()
	operation, finish, err := f.a.beginConnectionTransaction()
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	f.finish = func() { once.Do(finish) }
	f.op = operation
	f.a.mu.Lock()
	f.a.state.Connected = true
	f.a.state.Phase = "connected"
	f.a.mu.Unlock()
	exit := validTestStandardExit("socks5")
	exit.ID = "provider"
	if err := persistStandardExitStore(standardExitStore{Exits: []standardExit{exit}}); err != nil {
		t.Fatal(err)
	}
	exit, err = standardExitByID(exit.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(exit)
	if err != nil {
		t.Fatal(err)
	}
	f.o.mtuExit = &exit
	f.o.mtuExitRaw = string(encoded)
	f.start(t, func(context.Context) error { return nil }, nil)
	owner := &linuxStandardServiceMTUOwner{launch: f.o, connection: operation, activation: f.m, exitRaw: string(encoded), retained: true}
	f.o.mtuOwner = owner
	// Invoke the production transaction's completion closure. A retained VPN
	// activation outlives the canceled and cleared Connect request context.
	f.finish()
	if operation.Err() == nil || f.a.connectionContext != nil {
		t.Fatal("actual Connect completion did not clear its transient request")
	}
	observe, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f.o.mu.Lock()
	err = owner.intentLocked(observe)
	f.o.mu.Unlock()
	if err != nil {
		t.Fatal("completed Connect invalidated original successful activation", err)
	}
	replacement, cancelReplacement := context.WithCancel(context.Background())
	defer cancelReplacement()
	f.a.mu.Lock()
	f.a.connectionContext = replacement
	f.a.mu.Unlock()
	f.o.mu.Lock()
	err = owner.intentLocked(observe)
	f.o.mu.Unlock()
	if err == nil {
		t.Fatal("replacement Connect request acquired original MTU activation")
	}
	f.a.mu.Lock()
	f.a.connectionContext = nil
	f.a.mu.Unlock()
	f.m.cancel()
	f.o.mu.Lock()
	err = owner.intentLocked(observe)
	f.o.mu.Unlock()
	if err == nil {
		t.Fatal("retired original monitor remained MTU authority")
	}
}
