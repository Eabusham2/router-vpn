//go:build go1.25

package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobiletor"
)

// Only process/network/protection admission are modeled. The original compiler,
// sealed external policy validation and complete CurrentProof path are real.
func windowsExternalContextFixture(t *testing.T) (*desktopWindowsExternalRuntime, desktopExternalProof) {
	t.Helper()
	l := desktopExternalPhysicalLaunchVariant(t, "socks5", "always", "off", false, "")
	if err := prepareDesktopExternalPhysical(l, "windows"); err != nil {
		t.Fatal(err)
	}
	profile := l.external.profile
	root := t.TempDir()
	l.root = root
	l.command = exec.Command("modeled-original-windows-child")
	meta := l.external.physical.Metadata()
	l.configSHA256 = meta.ConfigSHA256
	a := &app{profiles: common.RouterProfileStore{Profiles: []common.RouterProfile{profile}}, cmd: l.command, state: state{RouterID: l.profileID, RuntimeMode: l.mode}}
	lifetime, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	host := &desktopWindowsExternalHost{app: a, capture: desktopOwnedNodePreparation{packageRoot: t.TempDir(), dataRoot: root, lifetime: lifetime, current: func() error { panic("strict proof called legacy controller callback") }, currentContext: func(ctx context.Context) error { return ctx.Err() }}, host: desktopNodeConnectionHost{startExternal: func(context.Context, *app, *desktopNodeLaunch, []string, []string, string) (desktopNodeProcess, error) {
		panic("proof tried to construct child")
	}, verify: func(context.Context, string) (string, error) { panic("proof tried to reverify package") }, externalPreflight: func(context.Context, string, []string, []string, string) error {
		panic("proof tried to rerun preflight")
	}}}
	done := make(chan struct{})
	child := &desktopWindowsExternalChild{done: done}
	slot := &desktopNodeProtectionSlot{}
	attempt := &desktopNodeProtectionAttempt{external: l.external.physical, prepared: &mobiletor.DesktopWindowsProtectionTarget{Capture: mobiletor.DesktopSocketCapture{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256}, Policy: meta.KillSwitchPolicy}}
	slot.active = attempt
	a.nodeProtection = slot
	owner := &desktopWindowsExternalRuntime{app: a, launch: l, host: host, policy: l.external.physical, operation: lifetime, profileToken: desktopOwnedNodeProfileToken(profile), persistedToken: desktopOwnedNodeProfileToken(profile), savedOptions: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, activated: true, published: true, slot: slot, attempt: attempt, process: child, done: done}
	l.external.windows = owner
	l.external.retained = owner
	l.external.windowsHost = host
	l.external.network = "explicit-original-network"
	l.external.networkIdentityContext = func(ctx context.Context) (string, error) { return "explicit-original-network", ctx.Err() }
	l.external.networkIdentity = func() string { panic("strict proof called legacy network observer") }
	desktopExternalRetainedLaunches.Store(a, l)
	t.Cleanup(func() { desktopExternalRetainedLaunches.Delete(a) })
	receipt, err := desktopnetwork.CanonicalDesktopNetworkReceipt(desktopnetwork.DesktopNetworkReceipt{Schema: 1, TargetOS: "windows", Incarnation: strings.Repeat("1", 32), Name: "routervpn-external", Index: 71, LUID: 710, MTU: 1360, Addresses: []string{"172.19.0.1/30"}, Objects: []desktopnetwork.DesktopNetworkObject{}})
	if err != nil {
		t.Fatal(err)
	}
	proof := desktopExternalProof{ExternalProofResult: l.external.expected, Healthy: true, Physical: &meta, NetworkReceipt: receipt}
	proof.DNSProven = true
	proof.Execution = "local"
	return owner, proof
}
func TestDesktopWindowsExternalCurrentProofContext(t *testing.T) {
	for _, scenario := range []string{"current", "owner-lock", "app-lock", "source-lock", "slot-lock", "process-done-lock", "missing-host-observer", "missing-process-observer", "wrong-session", "wrong-slot"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				owner, proof := windowsExternalContextFixture(t)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := owner.CurrentProof(ctx, proof); err != nil {
					t.Fatal("actual policy fixture did not reach strict proof", err)
				}
				var mu *sync.Mutex
				switch scenario {
				case "owner-lock", "process-done-lock":
					mu = &owner.mu
				case "app-lock":
					mu = &owner.app.mu
				case "source-lock":
					mu = &owner.launch.external.mu
				case "slot-lock":
					mu = &owner.slot.mu
				case "missing-host-observer":
					owner.host.capture.currentContext = nil
				case "missing-process-observer":
					owner.process = &desktopNodeProcessFakeLegacyObservation{}
				case "wrong-session":
					proof.SessionID = strings.Repeat("f", 32)
				case "wrong-slot":
					owner.slot.active = &desktopNodeProtectionAttempt{}
				}
				if mu != nil {
					mu.Lock()
				}
				var err error
				if scenario == "process-done-lock" {
					_, err = owner.ProcessDoneContext(ctx)
				} else {
					err = owner.CurrentProof(ctx, proof)
				}
				if mu != nil {
					mu.Unlock()
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("held original lock did not expire with caller", err)
					}
				} else if scenario == "current" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil {
					t.Fatal("invalid original proof or missing explicit observer accepted")
				}
				if owner.retiring || owner.retired || owner.closed {
					t.Fatal("proof expiry retired a healthy original owner")
				}
				select {
				case <-owner.done:
					t.Fatal("proof expiry manufactured child exit")
				default:
				}
			})
		})
	}
}

type desktopNodeProcessFakeLegacyObservation struct{}

func (*desktopNodeProcessFakeLegacyObservation) Started() bool {
	panic("strict observation called legacy Started")
}
func (*desktopNodeProcessFakeLegacyObservation) Alive() error {
	panic("strict observation called legacy Alive")
}
func (*desktopNodeProcessFakeLegacyObservation) Wait(context.Context) (uint32, error) {
	panic("strict observation entered waiter")
}
func (*desktopNodeProcessFakeLegacyObservation) Close(context.Context) error {
	panic("strict observation closed child")
}

type desktopNodeBoundedObservationChild struct{ observe func(context.Context) error }

func (c *desktopNodeBoundedObservationChild) Alive() error {
	panic("strict process called legacy child")
}
func (c *desktopNodeBoundedObservationChild) AliveContext(ctx context.Context) error {
	return c.observe(ctx)
}
func (c *desktopNodeBoundedObservationChild) Close(context.Context) error {
	panic("observation closed child")
}
func TestDesktopNodeProcessOwnerContextPreservesOriginalCallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	child := &desktopNodeBoundedObservationChild{observe: func(got context.Context) error {
		if got != ctx {
			t.Fatal("child received refreshed caller")
		}
		calls++
		return got.Err()
	}}
	owner := newDesktopNodeProcessOwner(func() error { panic("strict process called legacy controller") })
	owner.started = true
	owner.child = child
	if owner.AliveContext(ctx) == nil {
		t.Fatal("missing explicit controller callback accepted")
	}
	owner.controllerContext = func(got context.Context) error {
		if got != ctx {
			t.Fatal("controller received refreshed caller")
		}
		calls++
		return got.Err()
	}
	if err := owner.AliveContext(ctx); err != nil || calls != 3 {
		t.Fatal("actual strict process chain not invoked", calls, err)
	}
	cancel()
	if !errors.Is(owner.AliveContext(ctx), context.Canceled) || owner.retiring.Load() {
		t.Fatal("caller expiry retired original process")
	}
}
