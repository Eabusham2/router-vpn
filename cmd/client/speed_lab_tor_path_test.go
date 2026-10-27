package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func speedLabTorPipelineFixture(t *testing.T) *desktopTorConnectFixture {
	t.Helper()
	f := newDesktopTorConnectFixture(t)
	var launches []*desktopNodeLaunch
	runtime := f.driver.runtime
	f.driver.runtime = func(root string, policy, source common.RouterProfile, entry *desktopTorPredecessorCapture) (torBridgeRuntime, error) {
		f.preflight = 0
		prepared, err := runtime(root, policy, source, entry)
		if prepared.Launch != nil {
			launches = append(launches, prepared.Launch)
		}
		return prepared, err
	}
	// Exercise the shipping session observer, with a joined fixture lifetime.
	// The explicit native peer already supplies selected-DNS proof; tests below
	// also call the real synchronous Tor DNS verifier. No ambient probe runs.
	tracker := sessionTrackerFor(f.a)
	tracker.dnsProofLastAttempt = time.Now()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				tracker.observe(tracker.capture())
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
		// Retire the explicit fixture lifetime before killing its last child.
		// Joining any in-flight monitor transaction prevents a late cleanup
		// request from racing TempDir retirement after the test has returned.
		f.a.operationMu.Lock()
		defer f.a.operationMu.Unlock()
		f.a.mu.Lock()
		f.a.cmd, f.a.state.Connected = nil, false
		f.a.mu.Unlock()
		speedLabTemporaryOwners.Delete(f.a)
		for _, launch := range launches {
			desktopNodeOwners.CompareAndDelete(f.a, launch)
			if launch.command != nil && launch.command.Process != nil {
				_ = launch.command.Process.Kill()
				<-desktopNodeProcessDone(launch)
			}
			_ = launch.directoryRoot.Close()
		}
	})
	return f
}

func connectSpeedLabTorPrior(t *testing.T, f *desktopTorConnectFixture, direct bool) *desktopNodeLaunch {
	t.Helper()
	response := f.request(t, externalProfileConnectRequest{ProfileID: f.a.profiles.SelectedID, Base: "auto", Direct: &direct})
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	if _, err := waitForSpeedLabConnectedIdentity(f.a, time.Second); err != nil {
		t.Fatal(err)
	}
	return f.launch
}

func TestSpeedLabTorShippingPrepareStartAndRestoreExactNativePath(t *testing.T) {
	for _, prior := range []string{"direct-override", "saved-router", "home-router", "saved-server", "home-server"} {
		for _, temporary := range []string{"direct", "router", "server"} {
			if strings.HasPrefix(prior, "home-") && temporary == "direct" {
				continue
			}
			t.Run(prior+"/"+temporary, func(t *testing.T) {
				f := speedLabTorPipelineFixture(t)
				if strings.HasPrefix(prior, "home-") {
					f.a.mu.Lock()
					p := &f.a.profiles.Profiles[0]
					p.DNSMode, p.DNSHost, p.DNSProtocol, p.DNSPort = "home", "", "https", 8443
					p.DNSServerName, p.DNSPath = "private-home.example.test", "/private-query"
					f.a.mu.Unlock()
				}
				if strings.HasSuffix(prior, "server") {
					f.a.mu.Lock()
					f.a.profiles.Profiles[0].MultihopExecution = "server"
					f.a.mu.Unlock()
				}
				previous := connectSpeedLabTorPrior(t, f, prior == "direct-override")
				oldDNS, _ := activeDNSRuntimeIdentities.Load(f.a)
				q := speedLabRequest{Scope: "temporary", Topology: "external", NodeID: previous.profileID, Base: "auto", Execution: "local"}
				if temporary != "direct" {
					q.EntryID, q.EntryMode = "captured", "wg"
				}
				if temporary == "server" {
					q.Execution = "server"
				}
				_, snapshot, finish, err := f.a.beginSpeedLabTemporaryOperationExpected(&q)
				if err != nil {
					t.Fatal(err)
				}
				defer finish()
				if snapshot.Plan.tor == nil || (snapshot.Plan.request.EntryID != "") != (prior != "direct-override") {
					t.Fatal("restore capture adopted the saved preference instead of the actual running path", snapshot.Plan.request)
				}
				prepared, err := f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
				if err != nil {
					t.Fatal(err)
				}
				defer prepared.releaseUnused()
				q.preparedExternal = prepared
				if f.a.cmd != previous.command || desktopNodeProcessExited(previous) || prepared.tor.command.Process != nil {
					t.Fatal("preflight replaced or stopped the previous Tor path")
				}
				if current, _ := activeDNSRuntimeIdentities.Load(f.a); current != oldDNS {
					t.Fatal("temporary preflight replaced the active DNS identity")
				}
				if err := f.a.speedLabSuspendPrevious(snapshot, false); err != nil {
					t.Fatal(err)
				}
				path, err := f.a.startSpeedLabTemporaryPath(q)
				if err != nil {
					t.Fatal(err)
				}
				trial := f.launch
				if path.Execution != q.Execution || path.ExternalProtocol != "tor-bridge" || (path.EntryID != "") != (temporary != "direct") || trial.tor.expected.SessionID == previous.tor.expected.SessionID {
					t.Fatal("temporary public dispatcher lost the exact requested native path", path)
				}
				identity, observedPath, err := captureSpeedLabIdentity(f.a)
				if err != nil || observedPath.EntryID != path.EntryID || observedPath.EntryMode != path.EntryMode || identity.TorEntry != trial.tor.predecessor {
					t.Fatal("measurement captured a different Tor entry", observedPath, err)
				}
				if err := verifySpeedLabPath(context.Background(), f.a, identity); err != nil {
					t.Fatal(err)
				}
				// HTTP/test cancellation leaves restore intent live. Execute the
				// actual shipping restart switch with only its process boundary
				// supplied by the isolated native peer.
				snapshot.Owner.cancelTest()
				err = f.a.speedLabRestoreWith(snapshot, speedLabRestoreActions{
					stop: f.a.speedLabStopRuntime, persist: f.a.speedLabWriteStore, network: physicalNetworkIdentity,
					restart: func(plan speedLabRestorePlan) error { return f.a.speedLabRestartPlanWithTorRuntime(plan, f.driver) },
				})
				if err != nil {
					t.Fatal("actual native Tor restore transaction failed", err)
				}
				restored := f.launch
				if restored == trial || restored.tor.expected.SessionID == previous.tor.expected.SessionID || restored.tor.expected.SessionID == trial.tor.expected.SessionID || restored.tor.predecessor != snapshot.Plan.tor.selection.predecessor {
					t.Fatal("restoration reused a session or reselected its captured entry")
				}
				if restored.tor.expected.EntryID != previous.tor.expected.EntryID || restored.tor.expected.EntryMode != previous.tor.expected.EntryMode || restored.tor.expected.EntryAssetsSHA256 != previous.tor.expected.EntryAssetsSHA256 || restored.tor.expected.Execution != previous.tor.expected.Execution || restored.tor.expected.ServerSourceSHA256 != previous.tor.expected.ServerSourceSHA256 || restored.tor.expected.ServerDNSPolicySHA256 != previous.tor.expected.ServerDNSPolicySHA256 || restored.tor.expected.DNS != previous.tor.expected.DNS || restored.tor.expected.DNSDetour != previous.tor.expected.DNSDetour || !desktopNodeProcessExited(previous) || !desktopNodeProcessExited(trial) {
					t.Fatal("restored Tor path changed private source/DNS or left an earlier process alive")
				}
				f.a.mu.Lock()
				store, connected := cloneRouterProfileStore(f.a.profiles), f.a.state.Connected
				f.a.mu.Unlock()
				if !connected || !reflect.DeepEqual(store, snapshot.Profiles) || !snapshot.Owner.restored {
					t.Fatal("restoration failed to retain the complete profile and proved state")
				}
			})
		}
	}
}

func TestSpeedLabTorPreparationFailureKeepsCurrentRuntimeAndSource(t *testing.T) {
	for _, fault := range []string{"native-preflight", "entry-source", "cancelled", "operation", "owner"} {
		t.Run(fault, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			previous := connectSpeedLabTorPrior(t, f, true)
			q := speedLabRequest{Topology: "external", NodeID: previous.profileID, EntryID: "captured", EntryMode: "wg", Base: "auto", Execution: "local"}
			_, snapshot, finish, err := f.a.beginSpeedLabTemporaryOperation()
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			oldDNS, _ := activeDNSRuntimeIdentities.Load(f.a)
			original := f.driver.preflight
			f.driver.preflight = func(ctx context.Context, binary string, args, environment []string, directory string) error {
				if err := original(ctx, binary, args, environment, directory); err != nil {
					return err
				}
				if f.preflight != 2 {
					return nil
				}
				switch fault {
				case "native-preflight":
					return errors.New("native parser fixture rejected the private graph")
				case "entry-source":
					path := filepath.Join(clientRoot(f.a), "generated", "captured", "wg", "wg.conf")
					raw, err := os.ReadFile(path)
					if err != nil || os.WriteFile(path, append(raw, []byte("\n# relinked entry\n")...), 0600) != nil {
						t.Fatal(err)
					}
				case "cancelled":
					snapshot.Owner.cancelTest()
				case "operation":
					f.a.mu.Lock()
					f.a.connectionContext = context.Background()
					f.a.mu.Unlock()
				case "owner":
					speedLabTemporaryOwners.Store(f.a, &speedLabTemporaryOwner{})
				}
				return nil
			}
			prepared, err := f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
			if err == nil || prepared != nil {
				t.Fatal("retired Tor preparation passed", fault)
			}
			f.a.mu.Lock()
			current, connected := f.a.cmd, f.a.state.Connected
			f.a.mu.Unlock()
			if current != previous.command || !connected || desktopNodeProcessExited(previous) {
				t.Fatal("failed preparation destroyed the previous connection")
			}
			if dns, _ := activeDNSRuntimeIdentities.Load(f.a); dns != oldDNS {
				t.Fatal("failed preparation installed new DNS")
			}
			if f.launch == previous || f.launch.command != nil && f.launch.command.Process != nil {
				t.Fatal("rejected trial was started")
			}
			if _, err := os.Lstat(f.launch.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed private trial was not cleaned", err)
			}
		})
	}
}

func TestSpeedLabTorRetainedRouterRejectsRelinkOrBorrowedPath(t *testing.T) {
	for _, fault := range []string{"source", "credentials", "mode", "entry", "direct", "policy", "native-owner", "other-exit", "mixed-mode"} {
		t.Run(fault, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			previous := connectSpeedLabTorPrior(t, f, false)
			snapshot, err := f.a.speedLabSnapshotTemporary()
			if err != nil {
				t.Fatal(err)
			}
			plan := snapshot.Plan
			switch fault {
			case "source":
				path := filepath.Join(clientRoot(f.a), "generated", "captured", "wg", "wg.conf")
				raw, err := os.ReadFile(path)
				if err != nil || os.WriteFile(path, append(raw, []byte("\n# replaced credentials\n")...), 0600) != nil {
					t.Fatal(err)
				}
			case "credentials":
				f.a.mu.Lock()
				f.a.profiles.Profiles[1].APIToken = "relinked-private-token"
				f.a.mu.Unlock()
			case "mode":
				plan.request.EntryMode = "awg2-strong"
			case "entry":
				plan.request.EntryID = "replacement"
			case "direct":
				plan.request.EntryID, plan.request.EntryMode = "", ""
			case "policy":
				plan.tor.policyToken = strings.Repeat("0", 64)
			case "native-owner":
				plan.tor.selection.predecessor = nil
			case "other-exit":
				plan.request.ExitID = "replacement"
			case "mixed-mode":
				plan.request.ExitMode = "shadowsocks"
			}
			if _, err := f.a.speedLabTorRestoreProfile(plan); err == nil {
				t.Fatal("unowned retained Router path was admitted", fault)
			}
			if fault != "source" && fault != "credentials" && desktopNodeProcessExited(previous) {
				t.Fatal("invalid restore request stopped the existing path")
			}
		})
	}
}

func TestSpeedLabTorPreparedTrialRejectsStaleAdmissionBeforeStop(t *testing.T) {
	for _, fault := range []string{"selection", "operation", "owner", "network", "replacement-runtime", "changed-request"} {
		t.Run(fault, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			previous := connectSpeedLabTorPrior(t, f, true)
			q := speedLabRequest{Topology: "external", NodeID: previous.profileID, EntryID: "captured", EntryMode: "wg", Base: "auto", Execution: "local"}
			_, _, finish, err := f.a.beginSpeedLabTemporaryOperation()
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			prepared, err := f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			originalDNS, _ := activeDNSRuntimeIdentities.Load(f.a)
			f.a.mu.Lock()
			switch fault {
			case "selection":
				f.a.profiles.SelectedID = "captured"
			case "operation":
				f.a.connectionContext = context.Background()
			case "owner":
				speedLabTemporaryOwners.Store(f.a, &speedLabTemporaryOwner{})
			case "network":
				prepared.tor.prelaunch.workspace.tor.networkIdentity = func() string { return "replacement-network" }
			case "replacement-runtime":
				f.a.cmd = exec.Command("never-started-replacement-owner")
				f.a.state.RouterID, f.a.state.RuntimeMode = "replacement", "replacement"
			case "changed-request":
				q.EntryMode = "awg2-strong"
			}
			command, state := f.a.cmd, f.a.state
			f.a.mu.Unlock()
			if _, err := f.a.startPreparedSpeedLabTorPath(q, prepared.profile, prepared.tor); err == nil {
				t.Fatal("stale prepared trial was admitted", fault)
			}
			f.a.mu.Lock()
			unchanged := f.a.cmd == command && f.a.state == state
			f.a.mu.Unlock()
			if !unchanged || desktopNodeProcessExited(previous) || prepared.tor.command.Process != nil {
				t.Fatal("stale trial stopped or mutated another runtime", fault)
			}
			if dns, _ := activeDNSRuntimeIdentities.Load(f.a); dns != originalDNS {
				t.Fatal("stale trial removed another DNS owner")
			}
			if _, err := os.Lstat(prepared.tor.prelaunch.workspace.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("stale prepared workspace was not retired", err)
			}
		})
	}
}

func TestSpeedLabTorTemporaryPolicyIsPreparedBeforeItsOwnedApplication(t *testing.T) {
	f := speedLabTorPipelineFixture(t)
	f.a.mu.Lock()
	f.a.profiles.Profiles[0].BaseTunnel = "awg"
	original := cloneRouterProfileStore(f.a.profiles)
	f.a.mu.Unlock()
	requireEncrypted := true
	q := speedLabRequest{Topology: "external", NodeID: original.SelectedID, EntryID: "captured", EntryMode: "wg", Base: "wg", Execution: "local", RequireEncrypted: &requireEncrypted}
	_, snapshot, finish, err := f.a.beginSpeedLabTemporaryOperationExpected(&q)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	prepared, err := f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.releaseUnused()
	q.preparedExternal = prepared
	f.a.mu.Lock()
	unchanged := reflect.DeepEqual(f.a.profiles, original)
	f.a.mu.Unlock()
	if !unchanged || prepared.profile.BaseTunnel != "wg" || !prepared.profile.AutoRequireEncrypted {
		t.Fatal("preflight either wrote the saved source or omitted explicit temporary policy")
	}
	if err := f.a.speedLabSuspendPrevious(snapshot, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.startSpeedLabTemporaryPath(q); err != nil {
		t.Fatal(err)
	}
	if err := f.a.speedLabRestoreWith(snapshot, speedLabRestoreActions{stop: f.a.speedLabStopRuntime, persist: f.a.speedLabWriteStore, network: physicalNetworkIdentity, restart: func(speedLabRestorePlan) error { t.Fatal("off snapshot started an unrelated VPN"); return nil }}); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	unchanged = reflect.DeepEqual(f.a.profiles, original) && !f.a.state.Connected && f.a.cmd == nil
	f.a.mu.Unlock()
	if !unchanged {
		t.Fatal("temporary Tor overrides escaped the owned restore transaction")
	}
}
