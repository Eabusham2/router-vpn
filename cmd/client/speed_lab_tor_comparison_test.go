package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/routechoice"
)

func speedLabTorCompareFixture(t *testing.T, protocol, prior, trial string) (*desktopTorPublicComparisonFixture, *desktopNodeLaunch) {
	t.Helper()
	kind := "tor-compare-driver"
	if prior == "local" {
		kind = "tor-compare-driver-final-failure"
	}
	f := newDesktopTorPublicComparisonFixture(t, kind)
	f.a.mu.Lock()
	if protocol == "tor" {
		f.a.profiles.Profiles[0].External.Protocol, f.a.profiles.Profiles[0].External.TorBridge = "tor", nil
	}
	p := &f.a.profiles.Profiles[0]
	p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "home", "udp", "", 53
	profileID := p.ID
	f.a.mu.Unlock()
	response := f.request(t, externalProfileConnectRequest{ProfileID: profileID})
	if response.Code != http.StatusOK || !f.a.state.Connected || desktopTorExecution(f.launch.tor.expected.Execution) != prior || f.a.profiles.Profiles[0].MultihopExecution != "auto" {
		t.Fatal("fixture did not prove and retain its original Compare winner", response.Code, response.Body.String())
	}
	if _, err := waitForSpeedLabConnectedIdentity(f.a, time.Second); err != nil {
		t.Fatal(err)
	}
	waitForSpeedLabTorPriorDNSAdoption(t, f.a)
	previous := f.launch
	f.launches, f.probes = nil, nil
	for len(f.created) != 0 {
		<-f.created
	}
	command := f.driver.command
	f.driver.command = func(a *app, runtime torBridgeRuntime, environment []string) (*exec.Cmd, error) {
		cmd, err := command(a, runtime, environment)
		if err == nil {
			selected := trial
			if selected == "tor-compare-driver-final-failure" {
				selected = "tor-compare-driver"
				if len(f.launches) == 3 {
					selected = "tor-compare-driver-failed"
				}
			}
			cmd.Env = envWithValue(cmd.Env, "ROUTERVPN_TOR_TEST_CHILD", selected)
		}
		return cmd, err
	}
	return f, previous
}

func speedLabTorCompareRequest(f *desktopTorPublicComparisonFixture) speedLabRequest {
	return speedLabRequest{Scope: "temporary", Topology: "external", NodeID: f.a.profiles.Profiles[0].ID,
		EntryID: "captured", EntryMode: "wg", Base: "auto", Execution: "auto", ComparisonRequestID: strings.Repeat("d", 32)}
}

func speedLabTorCompareRestore(t *testing.T, f *desktopTorPublicComparisonFixture, snapshot speedLabTemporarySnapshot) {
	t.Helper()
	if err := f.a.speedLabRestoreWith(snapshot, speedLabRestoreActions{
		stop: f.a.speedLabStopRuntime, persist: f.a.speedLabWriteStore, network: physicalNetworkIdentity,
		restart: func(plan speedLabRestorePlan) error { return f.a.speedLabRestartPlanWithTorRuntime(plan, f.driver) },
	}); err != nil {
		t.Fatal("actual Compare temporary transaction could not restore", err)
	}
}

func TestSpeedLabTorCompareRestoresOriginalProvedExecutionWithoutReselection(t *testing.T) {
	for _, protocol := range []string{"tor", "tor-bridge"} {
		for _, prior := range []string{"local", "server"} {
			t.Run(protocol+"/"+prior, func(t *testing.T) {
				f, previous := speedLabTorCompareFixture(t, protocol, prior, "tor-compare-driver")
				q := speedLabTorCompareRequest(f)
				encrypted := true
				q.RequireEncrypted = &encrypted
				_, snapshot, finish, err := f.a.beginSpeedLabTemporaryOperationExpected(&q)
				if err != nil {
					t.Fatal(err)
				}
				defer finish()
				before, err := os.ReadFile(f.a.cfg.ProfilesFile)
				if err != nil {
					t.Fatal(err)
				}
				startup, err := os.ReadFile(f.a.cfg.StateFile)
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
				if err != nil {
					t.Fatal("temporary Compare preflight failed", err)
				}
				defer prepared.releaseUnused()
				q.preparedExternal = prepared
				if prepared.tor.comparison == nil || len(prepared.tor.comparison.paths) != 2 || f.a.cmd != previous.command || desktopNodeProcessExited(previous) {
					t.Fatal("Compare did not preflight both native paths before suspending the previous VPN")
				}
				for _, candidate := range prepared.tor.comparison.paths {
					if candidate.command.Process != nil {
						t.Fatal("preflight started a competing native owner")
					}
				}
				if err := f.a.speedLabSuspendPrevious(snapshot, false); err != nil {
					t.Fatal(err)
				}
				path, err := f.a.startSpeedLabTemporaryPath(q)
				if err != nil {
					t.Fatal("shipping temporary Compare failed", err)
				}
				winner := f.launch
				if progress := comparisonProgress(f.a); progress.RequestID != q.ComparisonRequestID || progress.ID == progress.RequestID {
					t.Fatal("temporary progress belongs to a different or substituted request", progress)
				}
				if path.Execution != "server" || path.ExternalProtocol != protocol || path.Comparison == nil || path.Comparison.Final == nil || path.Comparison.Final.ScoreMS == nil || *path.Comparison.Final.ScoreMS != 20 ||
					path.LastNodeMeasurement != "tor-last-relay-http" || path.ExternalMeasurement != "same-captured-endpoint-http" || len(f.probes) != 3 || len(f.launches) != 3 || snapshot.Owner.runtime != winner.command {
					t.Fatal("temporary Compare lost its measured native winner or mislabeled the operands", path)
				}
				for _, probe := range f.probes {
					if probe.target != path.Comparison.Target || probe.last != 1 || probe.external != 1 || probe.verifies != 1 {
						t.Fatal("temporary Compare changed its shared target or omitted a fresh final operand")
					}
				}
				if now, err := os.ReadFile(f.a.cfg.ProfilesFile); err != nil || string(now) != string(before) {
					t.Fatal("temporary comparison saved a trial or winner over the private profile", err)
				}
				snapshot.Owner.cancelTest()
				speedLabTorCompareRestore(t, f, snapshot)
				restored := f.launch
				if len(f.probes) != 3 || len(f.launches) != 4 || desktopTorExecution(restored.tor.expected.Execution) != prior || restored.tor.predecessor != snapshot.Plan.tor.selection.predecessor ||
					restored.tor.expected.SessionID == previous.tor.expected.SessionID || restored.tor.expected.SessionID == winner.tor.expected.SessionID ||
					restored.tor.expected.DNS != previous.tor.expected.DNS || restored.tor.expected.ServerDNSPolicySHA256 != previous.tor.expected.ServerDNSPolicySHA256 ||
					!desktopNodeProcessExited(previous) || !desktopNodeProcessExited(winner) || !reflect.DeepEqual(f.a.profiles, snapshot.Profiles) || !f.a.state.Connected || !snapshot.Owner.restored {
					t.Fatal("restoration reran Compare or changed the proved private/DNS/runtime path")
				}
				if now, err := os.ReadFile(f.a.cfg.StateFile); err != nil || string(now) != string(startup) {
					t.Fatal("temporary Compare or restoration overwrote Startup Last", err)
				}
			})
		}
	}
}

func TestSpeedLabTorCompareFailedFinalFallsBackAndInvalidCandidatesReceiveNoScore(t *testing.T) {
	for _, trial := range []string{"tor-compare-driver-final-failure", "tor-compare-driver-failed"} {
		t.Run(trial, func(t *testing.T) {
			f, previous := speedLabTorCompareFixture(t, "tor-bridge", "server", trial)
			q := speedLabTorCompareRequest(f)
			_, snapshot, finish, err := f.a.beginSpeedLabTemporaryOperationExpected(&q)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			q.preparedExternal, err = f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			defer q.preparedExternal.releaseUnused()
			if err := f.a.speedLabSuspendPrevious(snapshot, false); err != nil {
				t.Fatal(err)
			}
			path, err := f.a.startSpeedLabTemporaryPath(q)
			if trial == "tor-compare-driver-failed" {
				if err == nil || f.a.state.Connected || snapshot.Owner.runtime != nil || f.a.cmd != nil || len(f.probes) != 2 {
					t.Fatal("invalid comparison retained a scored path or lost temporary cleanup ownership", err)
				}
				for _, measurement := range comparisonProgress(f.a).Measurements {
					if measurement.Eligible || measurement.ScoreMS != nil {
						t.Fatal("failed native candidate received a score")
					}
				}
			} else if err != nil || path.Execution != "local" || len(f.probes) != 4 || path.Comparison == nil || path.Comparison.Final == nil || !path.Comparison.Final.Eligible {
				t.Fatal("failed final Server trial did not repeat both operands through fallback Local", path, err)
			}
			if trial == "tor-compare-driver-final-failure" {
				progress := comparisonProgress(f.a)
				for _, measurements := range [][]routechoice.Measurement{path.Comparison.Measurements, progress.Measurements} {
					if len(measurements) != 2 || measurements[1].Eligible || measurements[1].ScoreMS != nil || measurements[1].Failure == "" {
						t.Fatal("temporary fallback retained the failed final Server candidate's obsolete score", measurements)
					}
				}
			}
			count := len(f.probes)
			speedLabTorCompareRestore(t, f, snapshot)
			if len(f.probes) != count || desktopTorExecution(f.launch.tor.expected.Execution) != "server" || !desktopNodeProcessExited(previous) || !reflect.DeepEqual(f.a.profiles, snapshot.Profiles) {
				t.Fatal("failed temporary comparison could not restore the original Server path")
			}
		})
	}
}

func TestSpeedLabTorComparePreflightFailurePreservesPreviousOwnerAndDisqualifiesOnlyThatCandidate(t *testing.T) {
	for _, fault := range []string{"server", "both", "source", "owner"} {
		t.Run(fault, func(t *testing.T) {
			f, previous := speedLabTorCompareFixture(t, "tor-bridge", "server", "tor-compare-driver")
			q := speedLabTorCompareRequest(f)
			_, snapshot, finish, err := f.a.beginSpeedLabTemporaryOperationExpected(&q)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			preflight := f.driver.preflight
			f.driver.preflight = func(ctx context.Context, binary string, args, environment []string, directory string) error {
				if err := preflight(ctx, binary, args, environment, directory); err != nil {
					return err
				}
				if f.preflight != 2 {
					return nil
				}
				switch fault {
				case "both":
					return errors.New("native preflight unavailable for both captured leaves")
				case "server":
					if f.launch.tor.expected.Execution == "server" {
						return errors.New("Server native preflight unavailable")
					}
				case "source":
					if f.launch.tor.expected.Execution == "server" {
						path := filepath.Join(clientRoot(f.a), "generated", "captured", "wg", "wg.conf")
						raw, err := os.ReadFile(path)
						if err != nil || os.WriteFile(path, append(raw, []byte("\n# relinked entry\n")...), 0600) != nil {
							t.Fatal(err)
						}
					}
				case "owner":
					if f.launch.tor.expected.Execution == "server" {
						speedLabTemporaryOwners.Store(f.a, &speedLabTemporaryOwner{})
					}
				}
				return nil
			}
			prepared, err := f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
			if f.a.cmd != previous.command || !f.a.state.Connected || desktopNodeProcessExited(previous) {
				t.Fatal("preflight failure destroyed the previous VPN")
			}
			if fault != "server" {
				if err == nil || prepared != nil || snapshot.Owner.mutated {
					t.Fatal("invalid preparation was allowed to suspend its captured previous path", fault, err)
				}
				for _, launch := range append(f.launches, f.launch) {
					if launch != previous {
						if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
							t.Fatal("failed preflight retained unstarted private inputs", fault, err)
						}
					}
				}
				return
			}
			if err != nil || prepared == nil || len(prepared.tor.comparison.paths) != 1 {
				t.Fatal("failed Server preflight discarded the eligible Local candidate", err)
			}
			defer prepared.releaseUnused()
			q.preparedExternal = prepared
			if err := f.a.speedLabSuspendPrevious(snapshot, false); err != nil {
				t.Fatal(err)
			}
			path, err := f.a.startSpeedLabTemporaryPath(q)
			if err != nil || path.Execution != "local" || path.Comparison == nil || len(path.Comparison.Measurements) != 2 || path.Comparison.Measurements[1].ScoreMS != nil || len(f.probes) != 2 {
				t.Fatal("preflight-ineligible Server received a score or suppressed the proved Local path", path, err)
			}
			f.driver.preflight = preflight
			speedLabTorCompareRestore(t, f, snapshot)
			if len(f.probes) != 2 || desktopTorExecution(f.launch.tor.expected.Execution) != "server" {
				t.Fatal("restoration reused comparison instead of the previous concrete receipt")
			}
		})
	}
}

func TestSpeedLabTorCompareOptionsUseVerifiedCapabilityAndActualCurrentWinner(t *testing.T) {
	f, previous := speedLabTorCompareFixture(t, "tor-bridge", "server", "tor-compare-driver")
	read := func() (map[string]any, []map[string]any) {
		t.Helper()
		response := httptest.NewRecorder()
		f.a.speedLabOptions(response, httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil))
		var result struct {
			Current map[string]any   `json:"current"`
			Nodes   []map[string]any `json:"nodes"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
			t.Fatal("Speed Lab options did not return the captured public graph")
		}
		if strings.Contains(response.Body.String(), clientTorBridge) {
			t.Fatal("Speed Lab options exposed a private bridge source")
		}
		return result.Current, result.Nodes
	}
	current, nodes := read()
	if current["execution"] != "server" || current["entry_id"] != "captured" || current["exit_id"] != previous.profileID || current["entry_mode"] != "wg" {
		t.Fatal("Speed Lab described the saved Compare preference instead of the actual proved current path", current)
	}
	found := false
	for _, node := range nodes {
		if node["id"] != previous.profileID {
			if _, exists := node["tor_compare_execution"]; exists {
				t.Fatal("ordinary Router node acquired Tor comparison capability")
			}
			continue
		}
		found = true
		// The process fixture bypasses only package verification. Public
		// capability must still reject these unverified test executables.
		if node["tor_compare_execution"] != false || node["tor_server_execution"] != false || node["tor_compare_requires_paired_source"] != true || node["has_response_probe"] != false || node["multihop_execution"] != "auto" {
			t.Fatal("Tor capability inferred support from an unverified helper or fabricated a fixed-node probe", node)
		}
	}
	if !found {
		t.Fatal("Speed Lab lost its safe public Tor node identity")
	}
	f.a.mu.Lock()
	f.a.cmd = &exec.Cmd{}
	f.a.mu.Unlock()
	current, _ = read()
	if current["execution"] != nil || current["entry_id"] != nil || current["exit_id"] != nil {
		t.Fatal("a retired Tor owner supplied the replacement path's public options", current)
	}
	f.a.mu.Lock()
	f.a.cmd = previous.command
	f.a.mu.Unlock()
}

func TestSpeedLabTorCompareCancellationJoinsActualTrialAndRespectsDisconnectIntent(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(map[bool]string{false: "test-cancel", true: "disconnect"}[disconnect], func(t *testing.T) {
			f, _ := speedLabTorCompareFixture(t, "tor", "server", "tor-compare-held")
			q := speedLabTorCompareRequest(f)
			_, snapshot, finish, err := f.a.beginSpeedLabTemporaryOperationExpected(&q)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			q.preparedExternal, err = f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			defer q.preparedExternal.releaseUnused()
			if err := f.a.speedLabSuspendPrevious(snapshot, false); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := f.a.startSpeedLabTemporaryPath(q); done <- err }()
			var captured *desktopTorComparisonClient
			select {
			case captured = <-f.created:
			case <-time.After(5 * time.Second):
				t.Fatal("temporary candidate did not reach native comparison")
			}
			waitDesktopTorComparisonAction(t, captured, mobiletor.DesktopTorCompareLast)
			if disconnect {
				snapshot.Owner.cancelIntent()
			} else {
				snapshot.Owner.cancelTest()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled comparison succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled temporary comparison did not join its native child")
			}
			if len(f.probes) != 1 || snapshot.Owner.runtime != nil || f.a.cmd != nil || f.a.state.Connected || !desktopNodeProcessExited(f.launches[0]) || captured.claimed() {
				t.Fatal("cancelled trial lost teardown ownership or started the other candidate")
			}
			speedLabTorCompareRestore(t, f, snapshot)
			if !reflect.DeepEqual(f.a.profiles, snapshot.Profiles) || !snapshot.Owner.restored || len(f.probes) != 1 {
				t.Fatal("cancelled temporary test did not restore the captured complete profile")
			}
			if disconnect {
				if f.a.state.Connected || f.a.cmd != nil {
					t.Fatal("Disconnect was undone by temporary restoration")
				}
			} else if !f.a.state.Connected || desktopTorExecution(f.launch.tor.expected.Execution) != "server" {
				t.Fatal("test cancellation failed to restore the captured Server winner")
			}
		})
	}
}
