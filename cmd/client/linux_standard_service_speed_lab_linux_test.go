//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestLinuxStandardServiceSpeedLabPolicyCapture(t *testing.T) {
	for _, name := range []string{"original", "profile", "exit", "hopped", "late", "duplicate", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			p := common.RouterProfile{ID: "policy", Name: "Original", MTUPolicy: "auto", HomeLANCIDRs: []string{"192.168.50.0/24"}, CustomLayers: []string{"wg", "shadowsocks"}}
			digest, err := linuxStandardProfileDigest(p)
			if err != nil {
				t.Fatal(err)
			}
			x := validTestStandardExit("socks5")
			x.ID = "provider"
			raw, err := json.Marshal(x)
			if err != nil {
				t.Fatal(err)
			}
			o := &linuxStandardServiceLaunch{prepared: &linuxLegacyStandardExitOwner{}, request: linuxStandardServiceRequest{ProfileID: p.ID, ProfileSHA256: digest, RouterID: "standard:" + x.ID}, mtuExitRaw: string(raw)}
			q := standardExitConnectRequest{StandardExitID: x.ID, Direct: true}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch name {
			case "profile":
				p.DNSHost = "changed"
			case "exit":
				x.Password = "changed"
			case "hopped":
				q.Direct = false
			case "late":
				o.attempted = true
			case "duplicate":
				o.speedLabPolicy = &linuxStandardServicePolicy{}
			case "cancelled":
				cancel()
			}
			err = o.CaptureStandardServicePolicy(ctx, q, p, x)
			if name != "original" {
				if err == nil {
					t.Fatal("changed or late policy captured")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			frozen := o.speedLabPolicy
			p.HomeLANCIDRs[0] = "10.0.0.0/8"
			p.CustomLayers[0] = "tor"
			x.Password = "replacement"
			if frozen.profile.HomeLANCIDRs[0] != "192.168.50.0/24" || frozen.profile.CustomLayers[0] != "wg" || frozen.exitRaw != string(raw) || frozen.profileDigest != digest || frozen.request != q {
				t.Fatal("source capture shared mutable private inputs")
			}
		})
	}
}

func TestLinuxStandardServiceSpeedLabHeldCaptureKeepsCaller(t *testing.T) {
	a := &app{}
	o := &linuxStandardServiceLaunch{app: a}
	p := &linuxStandardServiceSpeedLabPath{owner: o}
	id := speedLabPathIdentity{Standard: p}
	linuxStandardServiceOwners.Store(a, o)
	defer linuxStandardServiceOwners.Delete(a)
	for _, name := range []string{"capture", "current", "dial", "options"} {
		t.Run(name, func(t *testing.T) {
			o.mu.Lock()
			defer o.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch name {
				case "capture":
					_, _, _, err = captureStandardServiceSpeedLabContext(ctx, a, o)
				case "current":
					err = p.current(ctx, a, id)
				case "options":
					_, err = standardServiceSpeedLabCurrentOptions(ctx, a, state{Connected: true, Phase: "connected"}, nil)
				case "dial":
					p.identity = id
					_, err = p.DialContext(ctx, "tcp", "speed.cloudflare.com:443")
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("lost caller deadline", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Speed Lab queued beyond original caller")
			}
		})
	}
}

func TestLinuxStandardServiceSpeedLabRestoreKeepsPolicySelection(t *testing.T) {
	profile := common.RouterProfile{ID: "policy", Name: "Original", DNSHost: "10.66.0.1", MTUPolicy: "auto", HomeLANCIDRs: []string{"192.168.50.0/24"}}
	store := common.RouterProfileStore{SchemaVersion: 4, SelectedID: "another", Profiles: []common.RouterProfile{profile, {ID: "another", Name: "Other"}}}
	original := &exec.Cmd{}
	prior := state{Connected: true, Phase: "connected", RouterID: "standard:provider", Mode: "standard-exit", LogicalMode: "standard-exit", RuntimeMode: "standard-socks5", Base: "external"}
	intent, cancelIntent := context.WithCancel(context.Background())
	defer cancelIntent()
	trial, cancelTrial := context.WithCancel(intent)
	defer cancelTrial()
	current := &exec.Cmd{}
	owner := &speedLabTemporaryOwner{intent: intent, cancelIntent: cancelIntent, test: trial, cancelTest: cancelTrial, current: trial, runtime: current, mutated: true, network: "explicit-model-network"}
	a := &app{profiles: cloneRouterProfileStore(store), cmd: current, connectionContext: trial}
	speedLabTemporaryOwners.Store(a, owner)
	defer speedLabTemporaryOwners.Delete(a)
	saved := &linuxStandardServiceSpeedLabRestore{}
	snapshot := speedLabTemporarySnapshot{Profiles: cloneRouterProfileStore(store), State: prior, Runtime: original, Owner: owner, Plan: speedLabRestorePlan{profile: cloneRouterProfile(profile), standard: saved}}
	restarted := false
	err := a.speedLabRestoreWith(snapshot, speedLabRestoreActions{
		stop: speedLabFakeStop(a, snapshot.Owner),
		restart: func(plan speedLabRestorePlan) error {
			a.mu.Lock()
			defer a.mu.Unlock()
			if plan.standard != saved || a.profiles.SelectedID != plan.profile.ID || strings.HasPrefix(a.profiles.SelectedID, "standard:") {
				return errors.New("restore substituted the exit ID for its policy profile")
			}
			if a.connectionContext != snapshot.Owner.current || a.connectionContext == snapshot.Owner.test {
				return errors.New("restore replaced the captured transaction")
			}
			a.cmd = snapshot.Runtime
			snapshot.Owner.runtime = a.cmd
			a.state = snapshot.State
			restarted = true
			return nil
		}, persist: func(common.RouterProfileStore) error { return nil }, network: func() string { return snapshot.Owner.network },
	})
	if err != nil || !restarted || a.state != snapshot.State || !reflect.DeepEqual(a.profiles, snapshot.Profiles) {
		t.Fatal("complete standard restore transaction changed prior state", err)
	}
}

func TestLinuxStandardServiceSpeedLabSessionKeepsCaller(t *testing.T) {
	for _, scenario := range []string{"held", "cancelled", "missing", "replaced"} {
		t.Run(scenario, func(t *testing.T) {
			a := &app{}
			tracker := &sessionTracker{a: a, session: &connectionSession{ID: "original"}}
			sessionTrackers.Store(a, tracker)
			defer sessionTrackers.Delete(a)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
			defer cancel()
			switch scenario {
			case "held":
				tracker.mu.Lock()
				defer tracker.mu.Unlock()
			case "cancelled":
				cancel()
			case "missing":
				sessionTrackers.Delete(a)
			case "replaced":
				sessionTrackers.Store(a, &sessionTracker{a: &app{}})
			}
			done := make(chan error, 1)
			go func() { _, err := standardServiceSpeedLabSession(ctx, a); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid tracker supplied original session")
				}
				if scenario == "held" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
				if scenario == "cancelled" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("session observation exceeded original caller")
			}
		})
	}
}

func TestLinuxStandardServiceSpeedLabRestoreRejectsChangedSource(t *testing.T) {
	for _, scenario := range []string{"original", "profile", "exit", "selection", "intent", "captured-profile", "mtu", "held-app", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HOMEVPN_ROOT", t.TempDir())
			x := validTestStandardExit("socks5")
			x.ID = "original-exit"
			if err := persistStandardExitStore(standardExitStore{Exits: []standardExit{x}}); err != nil {
				t.Fatal(err)
			}
			intent, cancelIntent := context.WithCancel(context.Background())
			defer cancelIntent()
			work, cancelWork := context.WithTimeout(intent, 2*time.Second)
			defer cancelWork()
			profile := common.RouterProfile{ID: "policy", DNSHost: "10.66.0.1", MTUPolicy: "auto", HomeLANCIDRs: []string{"192.168.50.0/24"}}
			digest, err := linuxStandardProfileDigest(profile)
			if err != nil {
				t.Fatal(err)
			}
			store, err := standardServiceStoreDigest(work)
			if err != nil {
				t.Fatal(err)
			}
			policy := &linuxStandardServicePolicy{request: standardExitConnectRequest{StandardExitID: x.ID, Direct: true}, profile: common.CloneRouterProfile(profile), profileDigest: digest}
			saved := &linuxStandardServiceSpeedLabRestore{policy: policy, profile: common.CloneRouterProfile(profile), profileDigest: digest, storeDigest: store, network: "original-network", mtu: 1360}
			a := &app{profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: profile.ID, Profiles: []common.RouterProfile{common.CloneRouterProfile(profile)}}, connectionContext: intent}
			switch scenario {
			case "profile":
				a.profiles.Profiles[0].DNSHost = "1.1.1.1"
			case "exit":
				x.Password += "changed"
				if err := persistStandardExitStore(standardExitStore{Exits: []standardExit{x}}); err != nil {
					t.Fatal(err)
				}
			case "selection":
				a.profiles.SelectedID = "replacement"
			case "intent":
				a.connectionContext = context.Background()
			case "captured-profile":
				saved.policy.profile.HomeLANCIDRs[0] = "10.0.0.0/8"
			case "mtu":
				saved.mtu = 9001
			case "held-app":
				cancelWork()
				work, cancelWork = context.WithTimeout(intent, 15*time.Millisecond)
				defer cancelWork()
				a.mu.Lock()
				defer a.mu.Unlock()
			case "cancelled":
				cancelWork()
			}
			done := make(chan error, 1)
			go func() { done <- saved.sourceCurrent(work, a, intent) }()
			select {
			case err := <-done:
				if scenario == "original" {
					if err != nil {
						t.Fatal("derived work budget lost original connection intent", err)
					}
				} else if err == nil {
					t.Fatal("changed restore source was admitted")
				}
				if scenario == "held-app" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("source capture lost deadline", err)
				}
			case <-time.After(time.Second):
				t.Fatal("restoration source check outlived original caller")
			}
		})
	}
}
