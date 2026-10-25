package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Explicit IPC fixtures drive the real controller launch/proof/stop path.
// They never install a host TUN, resolve a provider, or claim device acceptance.
func TestStartupExternalProcessFixture(t *testing.T) {
	kind := os.Getenv("ROUTERVPN_STARTUP_EXTERNAL_CHILD")
	if kind == "" || kind == "cleanup" {
		return
	}
	directory := os.Getenv("ROUTERVPN_STARTUP_EXTERNAL_DIRECTORY")
	raw, _ := base64.StdEncoding.DecodeString(os.Getenv("ROUTERVPN_STARTUP_EXTERNAL_EXPECTED"))
	var expected mobilemultihop.ExternalProofResult
	if json.Unmarshal(raw, &expected) != nil {
		os.Exit(91)
	}
	write := func(name string, value any) {
		raw, _ := json.Marshal(value)
		if atomicWritePrivate(filepath.Join(directory, name), raw) != nil {
			os.Exit(92)
		}
	}
	write("progress.json", desktopExternalProgressRecord{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256, Stage: "proving", Progress: mobilemultihop.Progress{Stage: "prepared"}})
	checked := time.Now().UnixMilli()
	for {
		if raw, err := os.ReadFile(filepath.Join(directory, "stop.json")); err == nil {
			var stop desktopExternalStop
			if decodeRelayControlJSON(raw, &stop) == nil && stop.SessionID == expected.SessionID && stop.SourceSHA256 == expected.SourceSHA256 {
				_ = os.Remove(filepath.Join(directory, "proof.json"))
				write("stopped.json", desktopExternalStop{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, Closed: true})
				return
			}
		}
		_, released := os.Stat(directory + ".fixture-release")
		if kind != "waiting" && (kind != "gated" || released == nil) {
			proof := expected
			proof.Execution, proof.CheckedAt = os.Getenv("ROUTERVPN_STARTUP_EXTERNAL_EXECUTION"), checked
			if kind == "wrong-session" {
				proof.SessionID = strings.Repeat("0", 32)
			}
			if kind == "wrong-dns" {
				proof.DNSProven = false
			}
			write("proof.json", desktopExternalProof{ExternalProofResult: proof, Healthy: true, HeartbeatAt: time.Now().UnixMilli()})
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type startupExternalHarness struct {
	driver      externalConnectRuntime
	calls       atomic.Int64
	staged      chan *desktopNodeLaunch
	beforeStage func(*desktopNodeLaunch)
	prepared    func(*desktopNodeLaunch, string)
}

func startupExternalTestApp(t *testing.T, protocol string) (*app, common.RouterProfile) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	profile, _ := desktopExternalNativeFixture(t, protocol)
	profile.AutoConnect, profile.StartupMode = true, "auto"
	profile.MTUPolicy, profile.ManualMTU, profile.EffectiveMTU = "manual", 1380, 9000
	profile.KillSwitch, profile.KillSwitchPolicy = true, "always"
	scripts := filepath.Join(root, "modes")
	if err := os.MkdirAll(scripts, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scripts, "kill-switch-platform.py"), []byte("# Isolated controller test: no host firewall is installed.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "client"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "client", "windows-kill-switch.ps1"), []byte("param([string]$Action,[string]$Root)\nexit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json"), StateFile: filepath.Join(root, "startup.json"), ScriptsDir: scripts},
		profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}, state: state{Mode: "off", Phase: "off"}}
	t.Cleanup(func() {
		a.cancelConnectionOperation()
		a.operationMu.Lock()
		if a.cmd != nil {
			if err := a.stopMode(); err != nil {
				t.Error("owned startup fixture cleanup failed", err)
			}
		}
		a.operationMu.Unlock()
	})
	return a, profile
}

func startupExternalDriver(t *testing.T, kind, execution string) *startupExternalHarness {
	t.Helper()
	h := &startupExternalHarness{staged: make(chan *desktopNodeLaunch, 8)}
	h.driver.prepare = func(a *app, profile, entry common.RouterProfile, exit standardExit, direct bool, retained string) (*desktopNodeLaunch, error) {
		h.calls.Add(1)
		var files, start map[string][]byte
		var err error
		if !direct && entry.NodeKind != "external" {
			files, err = readDesktopNodeAssets(clientRoot(a), entry.ID, profile.MultihopEntryMode)
			if err != nil {
				return nil, err
			}
			if entry.StartLayer != "" && entry.StartLayer != "off" {
				start, err = readDesktopNodeAssets(clientRoot(a), entry.ID, "shadowsocks")
				if err != nil {
					return nil, err
				}
			}
		}
		launch, err := compileDesktopExternalCaptured(a.connectionOperationContextOrBackground(), profile, entry, exit, direct, retained, files, start, nil)
		if err != nil {
			return nil, err
		}
		launch.root, launch.external.network = clientRoot(a), physicalNetworkIdentity()
		if h.prepared != nil {
			h.prepared(launch, retained)
		}
		return launch, nil
	}
	h.driver.stage = func(a *app, launch *desktopNodeLaunch) error {
		if err := stageDesktopNodeLaunch(a, launch); err != nil {
			return err
		}
		if h.beforeStage != nil {
			h.beforeStage(launch)
		}
		expected, _ := json.Marshal(launch.external.expected)
		command := exec.Command(os.Args[0], "-test.run=^TestStartupExternalProcessFixture$")
		command.Dir = launch.root
		command.Env = append(os.Environ(), "ROUTERVPN_STARTUP_EXTERNAL_CHILD="+kind, "ROUTERVPN_STARTUP_EXTERNAL_DIRECTORY="+launch.directory,
			"ROUTERVPN_STARTUP_EXTERNAL_EXPECTED="+base64.StdEncoding.EncodeToString(expected), "ROUTERVPN_STARTUP_EXTERNAL_EXECUTION="+execution)
		command.Stdout, command.Stderr = io.Discard, io.Discard
		launch.command = command
		// The real controller requires native stop acknowledgement and child
		// exit before it removes the captured workspace. This test helper only
		// substitutes the final platform firewall command, which has no host work.
		launch.stop = []string{os.Args[0], "-test.run=^TestStartupExternalProcessFixture$"}
		command.Env = envWithValue(command.Env, "ROUTERVPN_STARTUP_EXTERNAL_CHILD", kind)
		h.staged <- launch
		return nil
	}
	return h
}

func startupCaptureForTest(t *testing.T, a *app) *startupPolicyCapture {
	t.Helper()
	capture, err := a.captureStartupPolicy()
	if err != nil || capture == nil {
		t.Fatal("startup capture unavailable", err)
	}
	return capture
}

func startupWaitReady(t *testing.T, launch *desktopNodeLaunch) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(filepath.Join(launch.directory, "progress.json")); err == nil {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("startup child did not publish its explicit readiness record")
		case <-tick.C:
		}
	}
}

func TestStartupExternalSavedProtocolUsesActualOwnedChild(t *testing.T) {
	for _, mode := range []string{"auto", "smart-auto", "last"} {
		t.Run(mode, func(t *testing.T) {
			a, profile := startupExternalTestApp(t, "hysteria2")
			a.profiles.Profiles[0].StartupMode = mode
			h := startupExternalDriver(t, "proof", "local")
			var captured []byte
			h.prepared = func(launch *desktopNodeLaunch, retained string) {
				captured = append([]byte(nil), launch.config...)
				if retained != "" || launch.external.profile.External.Hysteria2.Password != profile.External.Hysteria2.Password {
					t.Fatal("direct startup substituted a relay selection or private protocol")
				}
			}
			a.applyCapturedStartupPolicy(context.Background(), startupCaptureForTest(t, a), h.driver)
			a.mu.Lock()
			st, command, saved := a.state, a.cmd, cloneRouterProfile(a.profiles.Profiles[0])
			a.mu.Unlock()
			if !st.Connected || st.Phase != "connected" || st.RuntimeMode != "external-hysteria2" || command == nil || command.Process == nil || h.calls.Load() != 1 {
				t.Fatal("startup did not adopt one proved native child", st)
			}
			if !bytes.Contains(captured, []byte(profile.DNSHost)) || !bytes.Contains(captured, []byte(`"server_port":5353`)) || !bytes.Contains(captured, []byte(`"mtu":1380`)) || saved.KillSwitchPolicy != "always" || saved.IPv6Mode != profile.IPv6Mode {
				t.Fatal("startup changed selected resolver, MTU or protection")
			}
			last, err := a.loadStartupSelection()
			if err != nil || last.External == nil || last.External.Execution != "local" || !last.External.Direct {
				t.Fatal("proved external startup path was not recorded", err, last)
			}
			raw, _ := os.ReadFile(a.cfg.StateFile)
			if bytes.Contains(raw, []byte(profile.External.Hysteria2.Password)) || bytes.Contains(raw, []byte("private_key")) || bytes.Contains(raw, []byte("source.json")) {
				t.Fatal("startup memory copied private runtime credentials")
			}
		})
	}
}

func startupAddRouterEntry(t *testing.T, a *app, mode string) common.RouterProfile {
	t.Helper()
	entry, files := viaEntryBaseFixture(t, mode)
	entry.SocksHost, entry.SocksPort, entry.SocksUsername, entry.SocksPassword = "10.77.0.1", 1080, "captured-entry", "captured-secret"
	entry.StartLayer = common.StartLayerOff
	dir, err := nativeGeneratedDir(clientRoot(a), entry.ID, mode)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	profile := &a.profiles.Profiles[0]
	profile.MultihopEnabled, profile.MultihopEntryID, profile.MultihopExitID = true, entry.ID, profile.ID
	profile.MultihopEntryMode, profile.MultihopExecution = mode, "auto"
	profile.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + profile.Endpoint + "/node-response", ServerName: "exit.example.test"}
	a.profiles.Profiles = append(a.profiles.Profiles, entry)
	return entry
}

func TestStartupExternalLastRetainsProvedExecutionWithoutCompare(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			a, _ := startupExternalTestApp(t, "hysteria2")
			startupAddRouterEntry(t, a, "awg2-strong")
			h := startupExternalDriver(t, "proof", execution)
			calls := 0
			h.prepared = func(launch *desktopNodeLaunch, retained string) {
				calls++
				if launch.external.profile.MultihopExecution != "auto" || launch.external.profile.MultihopEntryMode != "awg2-strong" || launch.external.predecessor == "" {
					t.Fatal("startup discarded saved Compare or AWG predecessor")
				}
				if calls == 1 && (retained != "" || launch.external.selection != "auto") || calls == 2 && (retained != execution || launch.external.selection != execution) {
					t.Fatal("Last did not retain the proved winner", calls, retained, launch.external.selection)
				}
			}
			a.applyCapturedStartupPolicy(context.Background(), startupCaptureForTest(t, a), h.driver)
			if !a.state.Connected {
				t.Fatal("initial saved graph did not prove", a.state.LastError)
			}
			a.operationMu.Lock()
			stopErr := a.stopMode()
			a.operationMu.Unlock()
			if stopErr != nil {
				t.Fatal(stopErr)
			}
			a.mu.Lock()
			a.profiles.Profiles[0].StartupMode = "last"
			a.profiles.Profiles[0].EffectiveMTU = 1400 // Historical measurement is not a new requested path.
			a.mu.Unlock()
			a.applyCapturedStartupPolicy(context.Background(), startupCaptureForTest(t, a), h.driver)
			if !a.state.Connected || calls != 2 || a.profiles.Profiles[0].MultihopExecution != "auto" {
				t.Fatal("Last did not restore the captured execution while preserving Compare preference", a.state)
			}
		})
	}
}

func TestStartupExternalCapturedSelectionAndSourceCannotDrift(t *testing.T) {
	for _, change := range []string{"selection", "dns", "credential", "entry", "entry-source", "auto-connect"} {
		t.Run(change, func(t *testing.T) {
			a, _ := startupExternalTestApp(t, "hysteria2")
			entry := startupAddRouterEntry(t, a, "wg")
			capture := startupCaptureForTest(t, a)
			switch change {
			case "selection":
				a.profiles.SelectedID = entry.ID
			case "dns":
				a.profiles.Profiles[0].DNSHost = "203.0.113.99"
			case "credential":
				a.profiles.Profiles[0].External.Hysteria2.Password = "new-private-secret"
			case "entry":
				a.profiles.Profiles[1].APIToken = "replacement-entry-credential"
			case "entry-source":
				dir, _ := nativeGeneratedDir(clientRoot(a), entry.ID, "wg")
				raw, _ := os.ReadFile(filepath.Join(dir, "wg.conf"))
				if err := os.WriteFile(filepath.Join(dir, "wg.conf"), append(raw, []byte("\n# replaced source\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "auto-connect":
				a.profiles.Profiles[0].AutoConnect = false
			}
			h := startupExternalDriver(t, "proof", "local")
			a.applyCapturedStartupPolicy(context.Background(), capture, h.driver)
			if h.calls.Load() != 0 || a.cmd != nil || a.state.Connected {
				t.Fatal("stale startup reached the runtime", change)
			}
		})
	}
}

func TestStartupExternalCancellationAndBadProofCannotConnect(t *testing.T) {
	for _, kind := range []string{"waiting", "wrong-session", "wrong-dns"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := startupExternalTestApp(t, "hysteria2")
			h := startupExternalDriver(t, kind, "local")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			capture := startupCaptureForTest(t, a)
			done := make(chan struct{})
			go func() { defer close(done); a.applyCapturedStartupPolicy(ctx, capture, h.driver) }()
			var launch *desktopNodeLaunch
			select {
			case launch = <-h.staged:
			case <-time.After(5 * time.Second):
				t.Fatal("startup never staged its child")
			}
			startupWaitReady(t, launch)
			if kind != "waiting" {
				deadline := time.Now().Add(time.Second)
				for {
					if raw, err := readDesktopRuntimeFile(launch, "proof.json", 256<<10); err == nil {
						if _, err := validateDesktopExternalProof(raw, launch.external, time.Now()); err == nil {
							t.Fatal("negative proof fixture was accepted")
						}
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("negative proof fixture did not arrive")
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Fatal("cancelled startup did not drain its owned child")
			}
			if a.state.Connected || a.cmd != nil {
				t.Fatal("cancelled or invalid startup was adopted", a.state)
			}
			if _, exists := desktopNodeOwners.Load(a); exists {
				t.Fatal("cancelled startup retained an active native owner")
			}
			if _, err := os.Stat(launch.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cancelled startup did not retire its private workspace", err)
			}
			if _, err := a.loadStartupSelection(); err == nil {
				t.Fatal("unproved startup became a Last restore point")
			}
		})
	}
}

func TestStartupExternalManualConnectAndDisconnectRetireDelay(t *testing.T) {
	for _, manual := range []bool{false, true} {
		t.Run(map[bool]string{false: "disconnect", true: "manual-connect"}[manual], func(t *testing.T) {
			a, _ := startupExternalTestApp(t, "hysteria2")
			ctx, cancel := context.WithCancel(context.Background())
			startupPolicyCancels.Store(a, context.CancelFunc(cancel))
			capture := startupCaptureForTest(t, a)
			if manual {
				_, finish, err := a.beginConnectionOperation()
				if err != nil {
					t.Fatal(err)
				}
				finish() // Even a manual connection which stops at preflight wins.
			} else {
				a.cancelConnectionOperation()
			}
			h := startupExternalDriver(t, "proof", "local")
			a.applyCapturedStartupPolicy(ctx, capture, h.driver)
			if ctx.Err() == nil || h.calls.Load() != 0 || a.state.Connected {
				t.Fatal("explicit user action did not retire scheduled startup")
			}
		})
	}
}

func TestStartupExternalLateProofCannotAdoptChangedSelectionOrReplacement(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-selection", true: "replacement-owner"}[replacement], func(t *testing.T) {
			a, profile := startupExternalTestApp(t, "hysteria2")
			h := startupExternalDriver(t, "gated", "local")
			capture := startupCaptureForTest(t, a)
			done := make(chan struct{})
			go func() { defer close(done); a.applyCapturedStartupPolicy(context.Background(), capture, h.driver) }()
			var launch *desktopNodeLaunch
			select {
			case launch = <-h.staged:
			case <-time.After(5 * time.Second):
				t.Fatal("startup did not stage its captured child")
			}
			startupWaitReady(t, launch)
			other := exec.Command(os.Args[0], "-test.run=^TestStartupExternalProcessFixture$")
			otherState := state{Connected: true, Phase: "connected", Mode: "replacement", RuntimeMode: "replacement", RouterID: "replacement"}
			a.mu.Lock()
			if replacement {
				a.cmd, a.state = other, otherState
			} else {
				a.profiles.SelectedID = "another-selected-node"
			}
			a.mu.Unlock()
			if err := os.WriteFile(launch.directory+".fixture-release", []byte("release only this fixture proof"), 0600); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Fatal("stale startup did not finish")
			}
			a.mu.Lock()
			if replacement {
				if a.cmd != other || a.state != otherState {
					a.mu.Unlock()
					t.Fatal("late startup altered the replacement runtime or connected state")
				}
				// Restore only the test's deliberately displaced pointer so its
				// cleanup can retire the original real child. The replacement
				// above is an ownership sentinel, never a started process.
				a.cmd = launch.command
				a.state = state{Mode: "external-node", RuntimeMode: "external-hysteria2", RouterID: profile.ID, Phase: "proving"}
			} else if a.state.Connected || a.cmd != nil || a.profiles.SelectedID != "another-selected-node" {
				a.mu.Unlock()
				t.Fatal("late startup adopted its retired selection")
			}
			a.mu.Unlock()
			if _, err := a.loadStartupSelection(); err == nil {
				t.Fatal("retired startup wrote a Last restore point")
			}
		})
	}
}

func TestStartupExternalLastEvidenceRejectsChangedPolicyEntryAndSource(t *testing.T) {
	a, _ := startupExternalTestApp(t, "hysteria2")
	entry := startupAddRouterEntry(t, a, "wg")
	a.profiles.Profiles[0].StartupMode = "last"
	capture := startupCaptureForTest(t, a)
	valid := startupSelection{RouterID: capture.profile.ID, RuntimeMode: "external-hysteria2", ProfileToken: startupExternalProfileToken(capture.profile),
		External: &startupExternalSelection{Protocol: "hysteria2", EntryID: entry.ID, EntryToken: startupExternalProfileToken(entry), EntryMode: "wg", SourceToken: capture.sourceToken, Execution: "server"}}
	if err := a.saveStartupSelection(valid); err != nil {
		t.Fatal(err)
	}
	if got := a.retainedExternalStartupExecution(capture); got != "server" {
		t.Fatal("valid retained winner missing", got)
	}
	for _, mutate := range []func(*startupSelection){
		func(s *startupSelection) { s.ProfileToken = strings.Repeat("0", 64) },
		func(s *startupSelection) { s.External.EntryToken = strings.Repeat("0", 64) },
		func(s *startupSelection) { s.External.SourceToken = strings.Repeat("0", 64) },
		func(s *startupSelection) { s.External.EntryMode = "awg2-strong" },
		func(s *startupSelection) { s.External.Execution = "auto" },
		func(s *startupSelection) { s.External.Protocol = "socks5" },
	} {
		changed := valid
		external := *valid.External
		changed.External = &external
		mutate(&changed)
		if err := a.saveStartupSelection(changed); err != nil {
			t.Fatal(err)
		}
		if got := a.retainedExternalStartupExecution(capture); got != "" {
			t.Fatal("unbound Last record bypassed fresh graph selection", got)
		}
	}
}

func TestStartupExternalHomeDNSNeverFallsBackToPublicResolver(t *testing.T) {
	a, _ := startupExternalTestApp(t, "socks5")
	a.profiles.Profiles[0].DNSMode = "home"
	a.profiles.Profiles[0].DNSHost = ""
	h := startupExternalDriver(t, "proof", "local")
	a.applyCapturedStartupPolicy(context.Background(), startupCaptureForTest(t, a), h.driver)
	if h.calls.Load() != 0 || a.state.Connected || a.profiles.Profiles[0].DNSMode != "home" || a.profiles.Profiles[0].DNSHost != "" {
		t.Fatal("startup fabricated a reachable Home resolver or substituted another policy")
	}
}

func TestStartupExternalTorRejectsRetiredCaptureBeforeRuntimeAccess(t *testing.T) {
	a, _ := startupExternalTestApp(t, "socks5")
	profile := existingTorImportProfile("startup-tor")
	profile.AutoConnect, profile.StartupMode = true, "last"
	a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	capture := startupCaptureForTest(t, a)
	a.profiles.Profiles[0].External.TorBridge.Bridges = []string{torImportSnowflakeBridge}
	result := &startupConnectResponse{header: make(http.Header)}
	a.torBridgeConnectCapturedOwned(result, capture.profile, capture)
	if result.status != http.StatusConflict || !strings.Contains(result.body.String(), "startup profile or policy changed") || a.cmd != nil || a.state.Connected {
		t.Fatal("Tor startup used relinked bridge settings or reached a native runtime for a stale capture", result.status, result.body.String())
	}
}

func TestStartupExternalImportsRemainManualUntilEnabled(t *testing.T) {
	a, _ := startupExternalTestApp(t, "socks5")
	profile, err := externalProfileFromCreateRequest(createRequestFor("socks5"))
	if err != nil {
		t.Fatal(err)
	}
	if profile.AutoConnect {
		t.Fatal("new external import enabled startup without consent")
	}
	a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	if capture, err := a.captureStartupPolicy(); err != nil || capture != nil {
		t.Fatal("new external import scheduled a connection", err)
	}
}
