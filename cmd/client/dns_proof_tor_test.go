package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// The child publishes explicit controller fixture receipts. These tests prove
// the shipping receipt/config/owner checks, not a live Tor or resolver service.
func torDNSProofFixture(t *testing.T, entry, home bool, protocol string) (*app, *desktopNodeLaunch, observedConnection) {
	t.Helper()
	a, profile, _ := desktopTorEntryFixture(t, "198.51.100.8")
	profile.DNSMode, profile.DNSProtocol, profile.DNSPort = "custom", protocol, 5353
	if home {
		profile.DNSMode, profile.DNSHost = "home", a.profiles.Profiles[1].AdGuardIPv4
	}
	if protocol == "tls" || protocol == "https" || protocol == "h3" {
		profile.DNSServerName = "captured-resolver.example.test"
	}
	if protocol == "https" || protocol == "h3" {
		profile.DNSPath = "/captured-query?node=one"
	}
	if !entry {
		profile.MultihopEnabled, profile.MultihopEntryID, profile.MultihopExitID = false, "", ""
		profile.MultihopEntryMode, profile.MultihopExecution = "", ""
	}
	a.profiles.Profiles[0] = cloneRouterProfile(profile)
	var predecessor *desktopTorPredecessorCapture
	var err error
	if entry {
		predecessor, err = captureDesktopTorPredecessor(a, profile, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	prepared, err := stageDesktopTorInputsWithPredecessor(clientRoot(a), profile, profile, installFakeExecutable(t, t.TempDir(), "tor"), installFakeExecutable(t, t.TempDir(), "native"), predecessor)
	if err != nil {
		t.Fatal(err)
	}
	launch := prepared.Launch
	launch.tor.network, launch.tor.networkIdentity = "dns-captured-network", func() string { return "dns-captured-network" }
	owner := desktopTorPreparedOwner(t, a, prepared)
	expected, _ := json.Marshal(launch.tor.expected)
	command := exec.Command(os.Args[0], "-test.run=^TestDesktopTorProcessFixture$")
	command.Env = append(os.Environ(), "ROUTERVPN_TOR_TEST_CHILD=proof", "ROUTERVPN_TOR_TEST_DIRECTORY="+launch.directory,
		"ROUTERVPN_TOR_TEST_EXPECTED="+base64.StdEncoding.EncodeToString(expected), "ROUTERVPN_TOR_TEST_RELEASE="+filepath.Join(t.TempDir(), "release"), "GORACE=atexit_sleep_ms=0")
	var output desktopTorFixtureOutput
	command.Stdout, command.Stderr = &output, &output
	owner.command = command
	if err := owner.start(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	a.cmd = command
	a.state.RouterID, a.state.Mode, a.state.RuntimeMode = profile.ID, "external-node", launch.mode
	t.Cleanup(func() {
		_ = command.Process.Kill()
		<-desktopNodeProcessDone(launch)
		if t.Failed() {
			t.Log(output.String())
		}
		desktopNodeOwners.CompareAndDelete(a, launch)
		clearActiveDNSRuntimeConfig(a)
		_ = launch.directoryRoot.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	a.state.Connected, a.state.Phase = true, "connected"
	captureDesktopMTUBaselineLocked(a, launch)
	return a, launch, observedConnection{Connected: true, Phase: "connected", Mode: "external-node", RuntimeMode: launch.mode, RouterID: profile.ID, Profile: cloneRouterProfile(profile)}
}

func TestTorSelectedDNSUsesNativeReceiptForDirectAndRouterPaths(t *testing.T) {
	for _, path := range []string{"direct", "entry-exit-dns", "entry-home-dns"} {
		protocols := []string{"tcp", "tls", "https"}
		if path == "entry-home-dns" {
			protocols = append(protocols, "udp", "h3")
		}
		for _, protocol := range protocols {
			t.Run(path+"/"+protocol, func(t *testing.T) {
				a, launch, observed := torDNSProofFixture(t, path != "direct", path == "entry-home-dns", protocol)
				calls := 0
				proof := proveSelectedDNSWithLookup(context.Background(), a, observed, launch.mode, func(context.Context, string) ([]string, error) {
					calls++
					return []string{"192.0.2.1"}, nil
				})
				if proof.Status != "passed" || proof.Host != launch.tor.expected.DNS.Address || proof.Mode != observed.Profile.DNSMode || proof.LatencyMs != 0 || calls != 0 || !strings.Contains(proof.Reason, protocol+"://") {
					t.Fatal("Tor DNS proof lost its native path or invented timing", proof, calls)
				}
				if path == "entry-home-dns" && !strings.Contains(proof.Reason, "Router entry") || path != "entry-home-dns" && !strings.Contains(proof.Reason, "Tor exit") {
					t.Fatal("Tor DNS proof names the wrong resolver path", proof)
				}
			})
		}
	}
}

func TestTorSelectedDNSRejectsStaleOrUnownedNativeEvidence(t *testing.T) {
	for _, change := range []string{"observation", "wrong-runtime", "wrong-node", "disconnected", "entry-credential", "entry-source", "exit-credential", "configuration", "owner", "network", "proof", "metadata-route", "dns-owner", "context", "nil-context", "ordinary-home-owner"} {
		t.Run(change, func(t *testing.T) {
			a, launch, observed := torDNSProofFixture(t, true, true, "https")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runtimeID := launch.mode
			switch change {
			case "observation":
				observed.Profile.DNSPath = "/stale-policy"
			case "wrong-runtime":
				runtimeID = "external-hysteria2"
			case "wrong-node":
				observed.RouterID = "different-node"
			case "disconnected":
				a.state.Connected = false
			case "entry-credential":
				a.profiles.Profiles[1].APIToken = "private-replacement-token"
			case "entry-source":
				path := filepath.Join(clientRoot(a), "generated", "captured", "wg", "wg.conf")
				bytes, err := os.ReadFile(path)
				if err != nil || os.WriteFile(path, append(bytes, []byte("\n# another source\n")...), 0600) != nil {
					t.Fatal("fixture source replacement failed", err)
				}
			case "exit-credential":
				a.profiles.Profiles[0].External.TorBridge.Bridges[0] = clientMeekBridge
			case "configuration":
				path := filepath.Join(launch.directory, "sing-box.json")
				bytes, err := os.ReadFile(path)
				if err != nil || os.WriteFile(path, append(bytes, ' '), 0600) != nil {
					t.Fatal("fixture config replacement failed", err)
				}
			case "owner":
				desktopNodeOwners.Delete(a)
			case "network":
				launch.tor.networkIdentity = func() string { return "replacement-network" }
			case "proof":
				launch.tor.started = time.Now().Add(time.Minute)
			case "metadata-route":
				launch.tor.expected.DNSDetour = "direct"
			case "dns-owner":
				activeDNSRuntimeIdentities.Store(a, activeDNSRuntimeIdentity{ProfileID: observed.RouterID, RuntimeID: runtimeID, Config: filepath.Join(clientRoot(a), "run", "another", "sing-box.json")})
			case "context":
				cancel()
			case "nil-context":
				ctx = nil
			case "ordinary-home-owner":
				proof := proveExternalHomeDNS(ctx, a, observed, runtimeID)
				if proof.Status != "failed" {
					t.Fatal("ordinary external Home DNS borrowed a Tor runtime", proof)
				}
				return
			}
			calls := 0
			proof := proveSelectedDNSWithLookup(ctx, a, observed, runtimeID, func(context.Context, string) ([]string, error) { calls++; return []string{"192.0.2.1"}, nil })
			if proof.Status != "failed" || proof.LatencyMs != 0 || calls != 0 || strings.Contains(proof.Reason, "private-replacement-token") {
				t.Fatal("stale Tor DNS evidence passed or invoked an ambient resolver", proof, calls)
			}
		})
	}
}

func replaceTorDNSObservationOwner(t *testing.T, a *app, launch *desktopNodeLaunch, change string) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	switch change {
	case "entry-credential":
		a.profiles.Profiles[1].APIToken = "changed-private-entry"
	case "entry-source":
		path := filepath.Join(clientRoot(a), "generated", "captured", "wg", "wg.conf")
		bytes, err := os.ReadFile(path)
		if err != nil || os.WriteFile(path, append(bytes, []byte("\n# newly linked same-ID source\n")...), 0600) != nil {
			t.Fatal("fixture source replacement failed", err)
		}
	case "native-owner":
		desktopNodeOwners.Store(a, &desktopNodeLaunch{profileID: launch.profileID, command: launch.command, mode: launch.mode})
		t.Cleanup(func() { desktopNodeOwners.Delete(a) })
	case "process":
		a.cmd = exec.Command("not-started-replacement")
	case "network":
		launch.tor.networkIdentity = func() string { return "replacement-network" }
	case "session":
		launch.tor.expected.SessionID = strings.Repeat("f", 32)
	default:
		t.Fatal("unknown fixture change")
	}
}

func TestTorSelectedDNSObserverRetiresCapturedPathProof(t *testing.T) {
	for _, change := range []string{"entry-credential", "entry-source", "native-owner", "process", "network", "session"} {
		t.Run(change, func(t *testing.T) {
			a, launch, observed := torDNSProofFixture(t, true, true, "https")
			session := connectionSession{ID: "captured-tor-dns-session", RouterID: observed.RouterID, Connected: true, Phase: "connected", PathProof: "passed", ActualMode: launch.mode}
			tracker := &sessionTracker{a: a, session: &session}
			sessionTrackers.Store(a, tracker)
			t.Cleanup(func() { sessionTrackers.Delete(a) })
			tracker.proveDNSAsyncWithProbe(session.ID, observed, launch.mode, proveSelectedDNSContext)
			if proof := tracker.snapshot(0).DNSProof; proof.Status != "passed" {
				t.Fatal("actual DNS observer did not adopt the native Tor proof", proof)
			}
			replaceTorDNSObservationOwner(t, a, launch, change)
			tracker.mu.Lock()
			tracker.invalidateDNSProofBindingLocked()
			tracker.mu.Unlock()
			if tracker.snapshot(0).DNSProof.Status == "passed" || !a.state.Connected || desktopNodeProcessExited(launch) {
				t.Fatal("Tor DNS retained a stale path or stopped a process")
			}
		})
	}
}

func TestTorSelectedDNSObserverRejectsReplacementBeforeAdoption(t *testing.T) {
	for _, change := range []string{"entry-credential", "entry-source", "native-owner", "process", "network", "session"} {
		t.Run(change, func(t *testing.T) {
			a, launch, observed := torDNSProofFixture(t, true, true, "https")
			session := connectionSession{ID: "captured-tor-dns-session", RouterID: observed.RouterID, Connected: true, Phase: "connected", PathProof: "passed", ActualMode: launch.mode}
			tracker := &sessionTracker{a: a, session: &session}
			sessionTrackers.Store(a, tracker)
			t.Cleanup(func() { sessionTrackers.Delete(a) })
			called := false
			tracker.proveDNSAsyncWithProbe(session.ID, observed, launch.mode, func(ctx context.Context, a *app, s observedConnection, runtimeID string) dnsProofState {
				proof := proveSelectedDNSContext(ctx, a, s, runtimeID)
				if proof.Status != "passed" {
					t.Fatal("baseline native proof failed", proof)
				}
				called = true
				replaceTorDNSObservationOwner(t, a, launch, change)
				return proof
			})
			if !called || tracker.snapshot(0).DNSProof.Status == "passed" || !a.state.Connected || desktopNodeProcessExited(launch) {
				t.Fatal("Tor DNS published into a replacement owner or stopped a process")
			}
		})
	}
}

func TestTorSelectedDNSCannotFallThroughWithoutNativeOwner(t *testing.T) {
	p := common.RouterProfile{ID: "tor", NodeKind: "external", DNSMode: "custom", External: &common.ExternalNodeConfig{Protocol: "tor-bridge"}}
	observed := observedConnection{Connected: true, Phase: "connected", Mode: "external-node", RuntimeMode: "external-tor-bridge", RouterID: p.ID, Profile: p}
	calls := 0
	proof := proveSelectedDNSWithLookup(context.Background(), &app{}, observed, observed.RuntimeMode, func(context.Context, string) ([]string, error) { calls++; return []string{"192.0.2.1"}, nil })
	if proof.Status != "failed" || calls != 0 {
		t.Fatal("unowned Tor observation borrowed the ordinary resolver", proof, calls)
	}
}
