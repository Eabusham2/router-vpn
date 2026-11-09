package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/routechoice"
)

type torIdentityProbeFixture struct {
	mobiletor.Comparison
	legacy int
	seen   []context.Context
}

func (p *torIdentityProbeFixture) Identity() string {
	p.legacy++
	return p.Comparison.Identity()
}
func (p *torIdentityProbeFixture) IdentityContext(ctx context.Context) (string, error) {
	p.seen = append(p.seen, ctx)
	return p.Comparison.(routechoice.ContextIdentitySession).IdentityContext(ctx)
}

// The real native mailbox and process are retained. Only the physical network
// observer is controlled by the original private-IPC fixture; its response
// times do not claim Tor wire traffic or device acceptance.
func torContextIdentityFixture(t *testing.T) (*desktopTorComparisonSession, *desktopTorComparisonClient, *torIdentityProbeFixture) {
	t.Helper()
	a, launch, client := desktopTorComparisonFixture(t, "tor-compare-context")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	identity, err := client.IdentityContext(ctx)
	if err != nil || identity == "" {
		t.Fatal("native fixture did not retain its original comparison identity", err)
	}
	operation, finish := context.WithCancel(context.Background())
	t.Cleanup(finish)
	profile := cloneRouterProfile(a.profiles.Profiles[0])
	a.connectionContext = operation
	selection := &desktopTorSelection{profile: profile, policy: profile, profileToken: desktopTorSourceIdentityToken(profile)}
	driver := &desktopTorComparisonDriver{app: a, profile: profile, operation: operation, selected: profile.ID,
		network: launch.tor.network, readNetwork: launch.tor.currentNetworkIdentityContext,
		selections: map[routechoice.Execution]*desktopTorSelection{routechoice.Local: selection}}
	probe := &torIdentityProbeFixture{Comparison: client}
	session := &desktopTorComparisonSession{driver: driver, selection: selection, command: launch.command,
		prelaunch: &torBridgePrelaunch{workspace: launch}, probe: probe, identity: identity, target: client.base.Target}
	return session, client, probe
}

func TestDesktopTorComparisonSessionIdentityKeepsCallerAndNativeOwner(t *testing.T) {
	session, client, probe := torContextIdentityFixture(t)
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), desktopTorComparisonCallerKey{}, "original-session"), 3*time.Second)
	defer cancel()
	identity, err := session.IdentityContext(ctx)
	if err != nil || identity != session.identity || probe.legacy != 0 || len(probe.seen) != 1 || probe.seen[0] != ctx {
		t.Fatal("session identity did not reach its original native contextual observer", identity, err, probe.legacy, probe.seen)
	}
	if err := session.Verify(ctx); err != nil {
		t.Fatal("original contextual session could not prove its native mailbox", err)
	}
	last, err := session.ProbeLast(ctx)
	if err != nil || last != 17*time.Millisecond {
		t.Fatal("last-node observation lost its native duration", last, err)
	}
	external, err := session.ProbeExternal(ctx, client.base.Target)
	if err != nil || external != 31*time.Millisecond {
		t.Fatal("external observation lost its same captured target", external, err)
	}
	for _, observed := range probe.seen {
		if observed != ctx || observed.Value(desktopTorComparisonCallerKey{}) != "original-session" {
			t.Fatal("session proof or measurement detached its original caller")
		}
	}
	if probe.legacy != 0 || !client.claimed() || client.closed || desktopNodeProcessExited(session.prelaunch.workspace) {
		t.Fatal("contextual observation lost or replaced the original native owner")
	}
}

func TestDesktopTorComparisonSessionIdentityHeldOwnersCancel(t *testing.T) {
	for _, boundary := range []string{"app", "session", "native-identity"} {
		t.Run(boundary, func(t *testing.T) {
			session, client, _ := torContextIdentityFixture(t)
			var mutex *sync.Mutex
			switch boundary {
			case "app":
				mutex = &session.driver.app.mu
			case "session":
				mutex = &session.mu
			case "native-identity":
				mutex = &client.mu
			}
			release := measurementHeldLock(mutex)
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				value, err := session.IdentityContext(ctx)
				if value != "" {
					err = errors.New("cancelled identity returned a retained session")
				}
				done <- err
			}()
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("session identity waited beyond its original held-owner deadline", err)
			}
			release()
			if client.closed || session.closed || !client.claimed() || desktopNodeProcessExited(session.prelaunch.workspace) {
				t.Fatal("expired identity discarded its still-owned native path")
			}
		})
	}
}

func TestDesktopTorComparisonDriverRejectsLateOrReplacedObservation(t *testing.T) {
	for _, fault := range []string{"cancelled", "operation", "selected", "source", "network", "missing-observer"} {
		t.Run(fault, func(t *testing.T) {
			session, _, _ := torContextIdentityFixture(t)
			driver := session.driver
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			driver.readNetwork = func(original context.Context) (string, error) {
				if original != ctx {
					t.Error("driver network observation replaced the original caller")
				}
				a := driver.app
				a.mu.Lock()
				defer a.mu.Unlock()
				switch fault {
				case "cancelled":
					cancel()
				case "operation":
					a.connectionContext = context.Background()
				case "selected":
					a.profiles.SelectedID = "replacement-profile"
				case "source":
					a.profiles.Profiles[0].DNSHost = "198.51.100.53"
				case "network":
					return "replacement-network", nil
				}
				return driver.network, nil
			}
			if fault == "missing-observer" {
				driver.readNetwork = nil
			}
			if err := driver.currentContext(ctx); err == nil || fault == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("late or replacement observation retained a captured comparison", fault, err)
			}
		})
	}
}

func TestDesktopTorComparisonCapturedSourceAdmissionKeepsCaller(t *testing.T) {
	for _, source := range []string{"selection", "startup"} {
		t.Run(source, func(t *testing.T) {
			a := &app{}
			selection := &desktopTorSelection{profile: common.RouterProfile{ID: "original-node"}, profileToken: "original-token"}
			startup := &startupPolicyCapture{}
			release := measurementHeldLock(&a.mu)
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if source == "selection" {
					done <- selection.currentContext(ctx, a)
				} else {
					done <- startup.currentContext(ctx, a)
				}
			}()
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("captured source ignored the original caller at admission", err)
			}
		})
	}
}
