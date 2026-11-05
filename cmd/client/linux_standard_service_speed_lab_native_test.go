//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The existing fixture uses actual authenticated Unix endpoints, pidfd/image/
// namespace captures, sealed startup bytes and a real original child. Native
// network observations and the preexisting successful DNS/proof receipt are
// explicitly modeled; this suite does not claim public TUN throughput.
func standardServiceSpeedLabFixture(t *testing.T) (*app, *linuxStandardServiceLaunch, context.Context) {
	t.Helper()
	_, f, o, _, ctx := linuxStandardControllerEpochFixture(t)
	if err := persistStandardExitStore(standardExitStore{Exits: []standardExit{f.exit}}); err != nil {
		t.Fatal(err)
	}
	exit, err := standardExitByID(f.exit.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.CaptureMTUExit(exit); err != nil {
		t.Fatal(err)
	}
	if err := o.CaptureStandardServicePolicy(ctx, standardExitConnectRequest{StandardExitID: exit.ID, Direct: true}, f.a.profiles.Profiles[0], exit); err != nil {
		t.Fatal(err)
	}
	if err := o.Start(ctx); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	f.a.state.Connected = true
	f.a.state.Phase = "connected"
	f.a.state.Mode = "standard-exit"
	f.a.state.LogicalMode = "standard-exit"
	f.a.state.RuntimeMode = o.request.RuntimeMode
	f.a.state.Base = o.request.Base
	f.a.state.RouterID = o.request.RouterID
	f.a.mu.Unlock()
	o.dnsProved = true
	tracker := &sessionTracker{a: f.a, session: &connectionSession{ID: o.request.Session, RouterID: o.request.RouterID, Phase: "connected", Connected: true, PathProof: "passed"}}
	sessionTrackers.Store(f.a, tracker)
	if err := o.activateMonitor(ctx, func(context.Context) error { return nil }, func() error { return errors.New("fixture refuses fabricated healthy retirement") }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		call, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = o.stopMonitor(call)
		sessionTrackers.Delete(f.a)
	})
	return f.a, o, ctx
}

func TestLinuxStandardServiceSpeedLabCapturesOriginalService(t *testing.T) {
	for _, scenario := range []string{"original", "command", "profile", "dns", "activation", "pending", "run", "sockets", "mtu", "session", "exit"} {
		t.Run(scenario, func(t *testing.T) {
			a, o, ctx := standardServiceSpeedLabFixture(t)
			identity, path, err := captureSpeedLabIdentity(a)
			if err != nil {
				t.Fatal("captured service cannot enter current Speed Lab", err)
			}
			p := identity.Standard.(*linuxStandardServiceSpeedLabPath)
			if identity.RouterID != o.request.RouterID || path.NodeID != o.request.ProfileID || path.StandardExitID != o.mtuExit.ID || path.ExitID != o.mtuExit.ID || p.live.MTU == 0 || o.mtuOwner != nil {
				t.Fatal("capture replaced policy, exit or actual reader")
			}
			switch scenario {
			case "original":
				response := httptest.NewRecorder()
				a.speedLabOptions(response, httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil).WithContext(ctx))
				var options map[string]json.RawMessage
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &options) != nil {
					t.Fatal("service options unavailable", response.Code, response.Body.String())
				}
				var current map[string]any
				if json.Unmarshal(options["current"], &current) != nil || current["router_id"] != o.request.RouterID || current["policy_profile_id"] != o.request.ProfileID || current["standard_exit_id"] != o.mtuExit.ID || current["exit_id"] != o.mtuExit.ID || current["execution"] != "local" {
					t.Fatal("options conflated policy profile with private exit", current)
				}
				plan, err := a.speedLabCaptureRestorePlan(speedLabTemporarySnapshot{Profiles: cloneRouterProfileStore(a.profiles), State: a.state, Runtime: a.cmd})
				if err != nil || plan.standard == nil || plan.profile.ID != o.request.ProfileID {
					t.Fatal("source-complete restore capture unavailable", err)
				}
				expected := speedLabRequest{ExpectedSelectedNodeID: a.profiles.SelectedID, ExpectedProfileTokens: map[string]string{o.request.ProfileID: publicProfileToken(a.profiles.Profiles[0])}}
				if err := a.validateSpeedLabExpectedProfiles(expected, &path); err != nil {
					t.Fatal("standard exit demanded a fictitious linked profile", err)
				}
				return
			case "command":
				a.mu.Lock()
				a.cmd = nil
				a.mu.Unlock()
			case "profile":
				a.mu.Lock()
				a.profiles.Profiles[0].DNSHost = "changed"
				a.mu.Unlock()
			case "dns":
				o.mu.Lock()
				o.dnsProved = false
				o.mu.Unlock()
			case "activation":
				raw, _ := linuxStandardServiceMonitors.Load(o)
				linuxStandardServiceMonitors.Store(o, &linuxStandardServiceMonitor{})
				defer linuxStandardServiceMonitors.Store(o, raw)
			case "pending":
				o.mu.Lock()
				o.mtuOwner = &linuxStandardServiceMTUOwner{pending: &linuxStandardServiceMTURequest{ID: "owned-pending"}}
				o.mu.Unlock()
			case "run":
				o.mu.Lock()
				o.mtuOwner = &linuxStandardServiceMTUOwner{}
				o.mtuOwner.run.Store(&linuxStandardMTUClientRun{})
				o.mu.Unlock()
			case "sockets":
				o.mu.Lock()
				o.mtuOwner = &linuxStandardServiceMTUOwner{}
				o.mtuOwner.sockets.Store(1)
				o.mu.Unlock()
			case "mtu":
				o.mu.Lock()
				var r map[string]any
				if err := json.Unmarshal([]byte(o.prepared.requestEpoch.mtuReceipt), &r); err != nil {
					t.Fatal(err)
				}
				r["mtu"] = 1280
				raw, _ := json.Marshal(r)
				o.prepared.requestEpoch.mtuReceipt = string(raw)
				o.mu.Unlock()
			case "session":
				tracker := sessionTrackerFor(a)
				tracker.mu.Lock()
				tracker.session.ID = "replacement"
				tracker.mu.Unlock()
			case "exit":
				changed := *o.mtuExit
				changed.Password += "changed"
				if err := persistStandardExitStore(standardExitStore{Exits: []standardExit{changed}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.current(ctx, a, identity); err == nil {
				t.Fatal("changed standard capture remained valid", scenario)
			}
		})
	}
}
