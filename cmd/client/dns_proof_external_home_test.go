package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The existing isolated child exercises the real native controller mailbox.
// Its proof receipt is explicit fixture data, not physical-network evidence.
func externalHomeProofFixture(t *testing.T, protocol string) (*app, *desktopNodeLaunch, observedConnection) {
	t.Helper()
	entry, files := desktopNodeFixture(t, "198.51.100.44")
	profile, exit := desktopExternalNativeFixture(t, "hysteria2")
	profile.MultihopEnabled, profile.MultihopEntryID, profile.MultihopExitID = true, entry.ID, profile.ID
	profile.MultihopEntryMode, profile.MultihopExecution = "wg", "local"
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "home", protocol, entry.AdGuardIPv4, 8443
	if protocol == "tls" || protocol == "https" || protocol == "h3" {
		profile.DNSServerName = "home.example.test"
	}
	if protocol == "https" || protocol == "h3" {
		profile.DNSPath = "/owned-query"
	}
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := desktopDNSPreparedController(t, launch, profile, entry)
	a.mu.Lock()
	a.state.Mode, a.state.RuntimeMode = "external-node", launch.mode
	a.mu.Unlock()
	if err := registerActiveDNSRuntimeConfig(a, profile.ID, launch.mode, filepath.Join(launch.directory, "sing-box.json")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clearActiveDNSRuntimeConfig(a) })
	return a, launch, observedConnection{Connected: true, Phase: "connected", Mode: "external-node", RuntimeMode: launch.mode, RouterID: profile.ID, Profile: profile}
}

func TestExternalHomeDNSUsesExactNativeEntryProofWithoutAmbientLookup(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			a, launch, snapshot := externalHomeProofFixture(t, protocol)
			calls := 0
			proof := proveSelectedDNSWithLookup(context.Background(), a, snapshot, launch.mode, func(context.Context, string) ([]string, error) { calls++; return []string{"192.0.2.1"}, nil })
			if proof.Status != "passed" || proof.Host != launch.external.entry.AdGuardIPv4 || proof.LatencyMs != 0 || calls != 0 || !strings.Contains(proof.Reason, protocol+"://") {
				t.Fatal("Home did not retain its actual captured native proof", proof, calls)
			}
			if launch.external.execution != "local" {
				t.Fatal("Home proof reran execution selection")
			}
		})
	}
}

func TestExternalHomeDNSRejectsChangedCaptureAndProof(t *testing.T) {
	for _, change := range []string{"observation", "entry-credential", "exit-policy", "source", "configuration", "owner", "context", "network", "missing-baseline"} {
		t.Run(change, func(t *testing.T) {
			a, launch, snapshot := externalHomeProofFixture(t, "https")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch change {
			case "observation":
				snapshot.Profile.DNSHost = "10.92.0.53"
			case "entry-credential":
				a.profiles.Profiles[1].APIToken = "rotated-private-entry"
			case "exit-policy":
				a.profiles.Profiles[0].DNSPath = "/other-query"
			case "source":
				launch.external.source = []byte(`{}`)
			case "configuration":
				var config map[string]any
				original, err := os.ReadFile(filepath.Join(launch.directory, "sing-box.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(original, &config); err != nil {
					t.Fatal(err)
				}
				config["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] = "direct"
				raw, _ := json.Marshal(config)
				if err := os.WriteFile(filepath.Join(launch.directory, "sing-box.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "owner":
				desktopNodeOwners.Delete(a)
			case "context":
				cancel()
			case "network":
				launch.external.networkIdentity = func() string { return "replacement-network" }
			case "missing-baseline":
				launch.external.mtu = nil
			}
			calls := 0
			proof := proveSelectedDNSWithLookup(ctx, a, snapshot, launch.mode, func(context.Context, string) ([]string, error) { calls++; return []string{"192.0.2.1"}, nil })
			if proof.Status != "failed" || proof.LatencyMs != 0 || calls != 0 || strings.Contains(proof.Reason, "rotated-private-entry") {
				t.Fatal("changed Home proof admitted or leaked credentials", proof, calls)
			}
		})
	}
}

func TestExternalHomeDNSObserverCapturesEntryAndRetiresPassedProof(t *testing.T) {
	a, launch, snapshot := externalHomeProofFixture(t, "https")
	session := connectionSession{ID: "native-home-proof-session", RouterID: snapshot.RouterID, Connected: true, Phase: "connected", PathProof: "passed", ActualMode: launch.mode}
	tracker := &sessionTracker{a: a, session: &session}
	sessionTrackers.Store(a, tracker)
	t.Cleanup(func() { sessionTrackers.Delete(a) })
	tracker.proveDNSAsyncWithProbe(session.ID, snapshot, launch.mode, proveSelectedDNSContext)
	if tracker.snapshot(0).DNSProof.Status != "passed" {
		t.Fatal("native Home DNS was not adopted")
	}
	ctx, stop, err := tracker.dnsProofPathContext(session.ID, snapshot, launch.mode)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	a.mu.Lock()
	a.profiles.Profiles[1].APIToken = "replacement-entry-private-token"
	a.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("entry credential change did not cancel DNS work")
	}
	tracker.mu.Lock()
	tracker.invalidateDNSProofBindingLocked()
	tracker.mu.Unlock()
	if tracker.snapshot(0).DNSProof.Status == "passed" {
		t.Fatal("proved Home DNS survived entry replacement")
	}
	if !a.state.Connected {
		t.Fatal("proof invalidation disconnected the native VPN")
	}
}
