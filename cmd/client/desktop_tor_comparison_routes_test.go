package main

import (
	"bytes"
	"context"
	"encoding/json"
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

type desktopTorPublicComparisonFixture struct {
	*desktopTorConnectFixture
	launches []*desktopNodeLaunch
	probes   []*desktopTorComparisonProbeFixture
	created  chan *desktopTorComparisonClient
}

func newDesktopTorPublicComparisonFixture(t *testing.T, kind string) *desktopTorPublicComparisonFixture {
	t.Helper()
	f := &desktopTorPublicComparisonFixture{desktopTorConnectFixture: speedLabTorPipelineFixture(t), created: make(chan *desktopTorComparisonClient, 8)}
	f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "last.json")
	p := &f.a.profiles.Profiles[0]
	p.MultihopExecution, p.StartupMode, p.AutoConnect = "auto", "last", true
	command := f.driver.command
	f.driver.command = func(a *app, runtime torBridgeRuntime, environment []string) (*exec.Cmd, error) {
		cmd, err := command(a, runtime, environment)
		if err == nil {
			f.launches = append(f.launches, runtime.Launch)
			selected := kind
			if kind == "tor-compare-driver-final-failure" {
				selected = "tor-compare-driver"
				if len(f.launches) == 3 {
					selected = "tor-compare-driver-failed"
				}
			}
			cmd.Env = envWithValue(cmd.Env, "ROUTERVPN_TOR_TEST_CHILD", selected)
		}
		return cmd, err
	}
	f.driver.comparison = func(a *app, launch *desktopNodeLaunch, target string) (mobiletor.Comparison, error) {
		client, err := newDesktopTorComparisonClient(a, launch, target)
		if client == nil {
			return nil, err
		}
		probe := &desktopTorComparisonProbeFixture{Comparison: client, target: target}
		f.probes = append(f.probes, probe)
		f.created <- client
		return probe, err
	}
	return f
}

func TestDesktopTorPublicCompareKeepsPreferenceAndRestoresExactWinner(t *testing.T) {
	for _, protocol := range []string{"tor", "tor-bridge"} {
		for _, route := range []string{"tor", "external"} {
			t.Run(protocol+"/"+route, func(t *testing.T) {
				f := newDesktopTorPublicComparisonFixture(t, "tor-compare-driver")
				f.unified = route == "external"
				p := &f.a.profiles.Profiles[0]
				if protocol == "tor" {
					p.External.Protocol, p.External.TorBridge = "tor", nil
				}
				p.DNSMode, p.DNSProtocol, p.DNSHost = "home", "udp", ""
				p.DNSPort = 53
				original, entry := cloneRouterProfile(*p), cloneRouterProfile(f.a.profiles.Profiles[1])
				q := externalProfileConnectRequest{ProfileID: p.ID, ComparisonRequestID: strings.Repeat("c", 32)}
				if route == "external" {
					p.MultihopExecution = "local"
					q.Execution = "auto" // Explicit Compare overrides the saved Local preference.
				}
				response := f.request(t, q)
				var result struct {
					Execution           string             `json:"execution"`
					Preference          string             `json:"execution_preference"`
					LastNodeMeasurement string             `json:"last_node_measurement"`
					ExternalMeasurement string             `json:"external_measurement"`
					Comparison          routechoice.Result `json:"comparison"`
				}
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
					t.Fatal("public Compare failed", response.Code, response.Body.String())
				}
				if result.Execution != "server" || result.Preference != "auto" || result.LastNodeMeasurement != "tor-last-relay-http" || result.ExternalMeasurement != "same-captured-endpoint-http" || result.Comparison.Final == nil || result.Comparison.Final.ScoreMS == nil || *result.Comparison.Final.ScoreMS != 20 {
					t.Fatal("public result lost the measured winner or mislabeled its operands", result)
				}
				if len(f.probes) != 3 || len(f.launches) != 3 || !f.a.state.Connected {
					t.Fatal("public Compare did not perform both trials and final recheck")
				}
				for _, probe := range f.probes {
					if probe.target != result.Comparison.Target || probe.last != 1 || probe.external != 1 || probe.verifies != 1 {
						t.Fatal("public comparison substituted a target or omitted a final operand")
					}
				}
				stored := cloneRouterProfile(f.a.profiles.Profiles[0])
				if stored.MultihopExecution != "auto" || stored.UseCount != original.UseCount+1 || !reflect.DeepEqual(stored.External, original.External) || !reflect.DeepEqual(f.a.profiles.Profiles[1], entry) || stored.DNSMode != "home" {
					t.Fatal("trial saved an intermediate choice or changed private node/DNS policy")
				}
				last, err := f.a.loadStartupSelection()
				if err != nil || last.External == nil || last.External.Execution != "server" || last.ProfileToken != startupExternalProfileToken(stored) {
					t.Fatal("Startup Last did not retain the actual winner", err)
				}
				progress := comparisonProgress(f.a)
				if !progress.Complete || progress.Stage != "selected" || progress.Execution != "server" || len(progress.Measurements) != 2 || progress.Failure != "" || progress.RequestID != q.ComparisonRequestID || progress.ID == progress.RequestID {
					t.Fatal("public comparison progress did not finish truthfully", progress)
				}
				winner := f.launch
				stopDesktopTorLifecycleFixture(t, f.a)
				capture, err := f.a.captureStartupPolicy()
				if err != nil || capture == nil {
					t.Fatal(err)
				}
				f.a.applyCapturedStartupPolicy(context.Background(), capture, externalConnectRuntime{tor: f.driver})
				if !f.a.state.Connected || len(f.probes) != 3 || len(f.launches) != 4 || f.launch == winner || f.launch.tor.expected.Execution != "server" || f.a.profiles.Profiles[0].MultihopExecution != "auto" {
					t.Fatal("Startup Last reran Compare, replaced its winner or changed the saved preference")
				}
				stopDesktopTorLifecycleFixture(t, f.a)
				response = desktopTorProfileRequest(t, f.desktopTorConnectFixture, "/api/connection-profile/save", map[string]any{"name": "Proved Tor Compare choice", "mode": "external"})
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"multihop_execution":"auto"`) {
					t.Fatal("complete profile lost the reusable Compare preference", response.Code, response.Body.String())
				}
			})
		}
	}
}

func TestDesktopTorPublicCompareFailureLeavesSavedConnectionUnchanged(t *testing.T) {
	for _, kind := range []string{"tor-compare-driver-failed", "tor-compare-driver-final-failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newDesktopTorPublicComparisonFixture(t, kind)
			if err := f.a.persistProfiles(); err != nil {
				t.Fatal(err)
			}
			before := desktopTorStoredProfile(t, f.desktopTorConnectFixture)
			response := f.request(t, externalProfileConnectRequest{ProfileID: f.a.profiles.SelectedID})
			if kind == "tor-compare-driver-final-failure" {
				if response.Code != http.StatusOK || !f.a.state.Connected || desktopTorExecution(f.launch.tor.expected.Execution) != "local" || len(f.launches) != 4 || f.a.profiles.Profiles[0].MultihopExecution != "auto" {
					t.Fatal("public comparison did not recheck the next eligible winner", response.Code, response.Body.String())
				}
				progress := comparisonProgress(f.a)
				if len(progress.Measurements) != 2 || progress.Measurements[1].Eligible || progress.Measurements[1].ScoreMS != nil || progress.Measurements[1].Failure == "" {
					t.Fatal("public fallback kept the failed final Server candidate's old score", progress)
				}
				stopDesktopTorLifecycleFixture(t, f.a)
				return
			}
			if response.Code != http.StatusBadGateway || f.a.state.Connected || f.a.cmd != nil || len(f.launches) != 2 || !bytes.Equal(before, desktopTorStoredProfile(t, f.desktopTorConnectFixture)) {
				t.Fatal("failed candidates saved or installed a result", response.Code, response.Body.String())
			}
			for _, measurement := range comparisonProgress(f.a).Measurements {
				if measurement.Eligible || measurement.ScoreMS != nil {
					t.Fatal("invalid public candidate received a score")
				}
			}
			if _, err := os.Stat(f.a.cfg.StateFile); !os.IsNotExist(err) {
				t.Fatal("failed comparison wrote Startup Last", err)
			}
		})
	}
}

func TestDesktopTorCompareDeviceEditsValidateBothPoliciesWithoutChoosingWinner(t *testing.T) {
	for _, protocol := range []string{"tor", "tor-bridge"} {
		t.Run(protocol, func(t *testing.T) {
			a := profileDeviceTorCoverApp(t, protocol)
			a.profiles.Profiles[0].MultihopExecution = "auto"
			before := cloneRouterProfileStore(a.profiles)
			capture := getDeviceSettingsForTest(t, a)
			if !capture.DevicePolicySupported || !capture.TorCoverSupported || !strings.Contains(capture.TorCoverNote, "each measured candidate") {
				t.Fatal("Compare settings lost their concrete candidate policy")
			}
			request := profileDeviceTorCoverRequest(t, capture)
			request["daita_enabled"], request["daita_rate_kbps"] = true, 64
			response := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, request)))
			stored := a.profiles.Profiles[0]
			if response.Code != http.StatusOK || !stored.DAITAEnabled || stored.DAITARateKbps != 64 || stored.MultihopExecution != "auto" || !reflect.DeepEqual(before.Profiles[1], a.profiles.Profiles[1]) || !reflect.DeepEqual(before.Profiles[0].External, stored.External) || a.cmd != nil || a.state.Connected {
				t.Fatal("Compare device edit changed the node, chose a winner or failed to save", response.Code, response.Body.String())
			}
			for _, execution := range []string{"local", "server"} {
				selected, err := captureDesktopTorSelection(a, stored, externalProfileConnectRequest{ProfileID: stored.ID, Execution: execution}, nil)
				if err != nil || selected.policy.MultihopExecution != execution || !selected.policy.DAITAEnabled || selected.policy.DAITARateKbps != 64 || stored.MultihopExecution != "auto" {
					t.Fatal("Compare preference did not lower into both exact concrete candidates", execution, err)
				}
			}
		})
	}
}

func TestDesktopTorPublicCompareHTTPCancellationDrainsOwnedTrial(t *testing.T) {
	f := newDesktopTorPublicComparisonFixture(t, "tor-compare-held")
	if err := f.a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	before := desktopTorStoredProfile(t, f.desktopTorConnectFixture)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	data, _ := json.Marshal(externalProfileConnectRequest{ProfileID: f.a.profiles.SelectedID})
	request := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/connect", bytes.NewReader(data)).WithContext(ctx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); f.a.torBridgeConnectWithRuntime(response, request, f.driver) }()
	var comparison *desktopTorComparisonClient
	select {
	case comparison = <-f.created:
	case <-time.After(5 * time.Second):
		t.Fatal("public candidate did not prepare")
	}
	waitDesktopTorComparisonAction(t, comparison, mobiletor.DesktopTorCompareLast)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP cancellation did not join the exact trial")
	}
	if response.Code == http.StatusOK || f.a.state.Connected || f.a.cmd != nil || len(f.launches) != 1 || !desktopNodeProcessExited(f.launch) || !bytes.Equal(before, desktopTorStoredProfile(t, f.desktopTorConnectFixture)) {
		t.Fatal("cancelled public Compare installed, saved or leaked a path", response.Code, response.Body.String())
	}
}

func TestDesktopTorCompareCancellationCannotSaveOrAdopt(t *testing.T) {
	for _, afterSave := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-save", true: "after-save"}[afterSave], func(t *testing.T) {
			f := prepareDesktopTorChoiceFixture(t, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.selection.preference, f.selection.adoption = "auto", ctx
			f.request.Execution = "auto"
			before := desktopTorStoredProfile(t, f.desktopTorConnectFixture)
			if !afterSave {
				cancel()
			}
			saved, err := f.a.commitDesktopTorChoice(f.selection, f.launch, f.request, nil, f.operation, f.selected, f.ip)
			if !afterSave {
				if err == nil || !bytes.Equal(before, desktopTorStoredProfile(t, f.desktopTorConnectFixture)) {
					t.Fatal("cancelled comparison changed durable preference")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			if _, err := saved.adopt(f.a); err == nil || f.a.state.Connected || f.a.profiles.Profiles[0].MultihopExecution != "auto" {
				t.Fatal("post-save cancellation adopted a stale runtime or pretended to undo disk state")
			}
		})
	}
}
