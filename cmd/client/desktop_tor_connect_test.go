package main

import (
	"bytes"
	"context"
	"encoding/base64"
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

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

type desktopTorConnectFixture struct {
	a         *app
	driver    desktopTorConnectRuntime
	launch    *desktopNodeLaunch
	preflight int
	commands  int
	output    desktopTorFixtureOutput
	unified   bool
}

// Only executable verification and the subprocess are explicit fixture
// boundaries. HTTP decoding, selection, native configuration compilation,
// staging, final admission, public/DNS proof and teardown are shipping code.
func newDesktopTorConnectFixture(t *testing.T) *desktopTorConnectFixture {
	t.Helper()
	a, profile, _ := desktopTorEntryFixture(t, "198.51.100.8")
	profile.MTUPolicy, profile.ManualMTU = "manual", 1280
	a.profiles.Profiles[0] = profile
	a.state.Mode, a.state.Phase = "off", "off"
	t.Setenv("HOMEVPN_ROOT", clientRoot(a))
	a.cfg.ScriptsDir = filepath.Join(clientRoot(a), "modes")
	for _, directory := range []string{a.cfg.ScriptsDir, filepath.Join(clientRoot(a), "client")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// The IPC child never installs a host firewall. Keep the controller's
	// explicit release call, using only an isolated no-firewall platform peer.
	if err := os.WriteFile(filepath.Join(a.cfg.ScriptsDir, "kill-switch-platform.py"), []byte("# Controller fixture: no host firewall was installed.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clientRoot(a), "client", "windows-kill-switch.ps1"), []byte("param([string]$Action,[string]$Root)\nexit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sessionTrackers.Store(a, &sessionTracker{a: a})
	f := &desktopTorConnectFixture{a: a}
	tor := installFakeExecutable(t, t.TempDir(), "tor")
	native := installFakeExecutable(t, t.TempDir(), "native")
	f.driver.capability = func() standardExitCapability { return standardExitCapability{Supported: true} }
	f.driver.runtime = func(root string, policy, original common.RouterProfile, entry *desktopTorPredecessorCapture) (torBridgeRuntime, error) {
		prepared, err := stageDesktopTorInputsWithPredecessor(root, policy, original, tor, native, entry)
		f.launch = prepared.Launch
		return prepared, err
	}
	f.driver.preflight = func(ctx context.Context, executable string, args, environment []string, directory string) error {
		f.preflight++
		if executable != native || f.launch == nil || directory != f.launch.directory || ctx.Err() != nil {
			t.Fatal("native preflight lost its captured inputs", args)
		}
		if f.preflight%2 == 1 && !reflect.DeepEqual(args, []string{"routervpn-tor", "--help"}) ||
			f.preflight%2 == 0 && !reflect.DeepEqual(args, []string{"check", "-D", directory, "-c", filepath.Join(directory, "sing-box.json")}) {
			t.Fatal("native admission did not exercise both capability and configuration checks", args)
		}
		return nil
	}
	f.driver.command = func(_ *app, prepared torBridgeRuntime, environment []string) (*exec.Cmd, error) {
		f.commands++
		launch := prepared.Launch
		if launch != f.launch || f.preflight != 2 {
			t.Fatal("child was prepared before both native admission checks")
		}
		vars := map[string]string{}
		for _, item := range environment {
			name, value, _ := strings.Cut(item, "=")
			vars[name] = value
		}
		if vars["HOMEVPN_POLICY_PROFILE_ID"] != launch.profileID || vars["HOMEVPN_TOR_SESSION"] != launch.tor.expected.SessionID {
			t.Fatal("launch environment mixed policy or session owners")
		}
		if entry := launch.tor.predecessor; entry != nil {
			// Admission may deliberately replace the saved profile. The wrapper
			// must still carry only the immutable plan staged for this launch;
			// the controller rejects the changed source before process start.
			raw, readErr := readDesktopRuntimeFile(launch, "tor-profile.json", desktopTorInputLimit("tor-profile.json"))
			var staged common.RouterProfile
			if readErr != nil || json.Unmarshal(raw, &staged) != nil || staged.External == nil || staged.External.TorBridge == nil {
				t.Fatal("fixture lost the staged Tor transport plan", readErr)
			}
			plan, planErr := mobiletor.NewPlan(*staged.External.TorBridge)
			want, err := entry.native.PhysicalEgress(plan)
			var got []mobilemultihop.PhysicalEgress
			if planErr != nil || err != nil || json.Unmarshal([]byte(vars["HOMEVPN_NATIVE_EGRESS_JSON"]), &got) != nil || !reflect.DeepEqual(want, got) ||
				vars["HOMEVPN_PROFILE_ID"] != entry.entry.ID || vars["HOMEVPN_EXTERNAL_SESSION"] != launch.tor.expected.SessionID {
				t.Fatal("predecessor's captured physical firewall tuples did not reach the wrapper", got, want, planErr, err)
			}
		} else if vars["HOMEVPN_NATIVE_EGRESS_JSON"] != "" || vars["HOMEVPN_EXTERNAL_SESSION"] != "" {
			t.Fatal("Direct borrowed a Router physical route")
		}
		expected, _ := json.Marshal(launch.tor.expected)
		command := exec.Command(os.Args[0], "-test.run=^TestDesktopTorProcessFixture$")
		command.Env = append(environment, "ROUTERVPN_TOR_TEST_CHILD=proof", "ROUTERVPN_TOR_TEST_DIRECTORY="+launch.directory,
			"ROUTERVPN_TOR_TEST_EXPECTED="+base64.StdEncoding.EncodeToString(expected), "GORACE=atexit_sleep_ms=0")
		command.Stdout, command.Stderr = &f.output, &f.output
		return command, nil
	}
	t.Cleanup(func() {
		if launch := f.launch; launch != nil {
			if launch.command != nil && launch.command.Process != nil {
				_ = launch.command.Process.Kill()
				<-desktopNodeProcessDone(launch)
			}
			desktopNodeOwners.CompareAndDelete(a, launch)
			if launch.directoryRoot != nil {
				_ = launch.directoryRoot.Close()
			}
		}
		clearActiveDNSRuntimeConfig(a)
		sessionTrackers.Delete(a)
		if t.Failed() {
			t.Log(f.output.String())
		}
	})
	return f
}

func (f *desktopTorConnectFixture) request(t *testing.T, request externalProfileConnectRequest) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if f.unified {
		f.a.externalProfileConnectWithRuntime(w, httptest.NewRequest(http.MethodPost, "/api/external-profile/connect", bytes.NewReader(data)), externalConnectRuntime{tor: f.driver})
	} else {
		f.a.torBridgeConnectWithRuntime(w, httptest.NewRequest(http.MethodPost, "/api/tor-bridge/connect", bytes.NewReader(data)), f.driver)
	}
	return w
}

func TestDesktopTorPublicConnectCapturesDirectSavedAndExplicitRouterPath(t *testing.T) {
	for _, route := range []string{"tor", "external"} {
		for _, path := range []string{"saved-router", "saved-router-auto", "explicit-router", "explicit-router-auto", "direct-override", "direct-auto", "home-router"} {
			t.Run(route+"/"+path, func(t *testing.T) {
				f := newDesktopTorConnectFixture(t)
				f.unified = route == "external"
				profile := &f.a.profiles.Profiles[0]
				q := externalProfileConnectRequest{ProfileID: profile.ID}
				if strings.Contains(path, "auto") {
					q.Base = "auto"
				}
				wantEntry := true
				if strings.HasPrefix(path, "explicit") {
					profile.MultihopEnabled, profile.MultihopEntryID, profile.MultihopExitID, profile.MultihopEntryMode = false, "", "", ""
					q.EntryID, q.EntryMode, q.Execution = f.a.profiles.Profiles[1].ID, "wg", "local"
				}
				if strings.HasPrefix(path, "direct") {
					wantEntry = false
					direct := true
					q.Direct = &direct
				}
				if path == "home-router" {
					profile.DNSMode, profile.DNSHost, profile.DNSProtocol, profile.DNSPort = "home", "", "https", 8443
					profile.DNSServerName, profile.DNSPath = "home-resolver.example.test", "/owned-dns-query"
				}
				q.ExpectedSelectedNodeID = &f.a.profiles.SelectedID
				q.ExpectedProfileTokens = map[string]string{profile.ID: publicProfileToken(*profile)}
				if wantEntry {
					entry := f.a.profiles.Profiles[1]
					q.ExpectedProfileTokens[entry.ID] = publicProfileToken(entry)
				}
				original, entrySource := desktopTorSourceIdentityToken(*profile), cloneRouterProfile(f.a.profiles.Profiles[1])
				wantSaved := cloneRouterProfile(*profile)
				wantSaved.MultihopEnabled, wantSaved.MultihopExecution = wantEntry, "local"
				wantSaved.MultihopEntryID, wantSaved.MultihopExitID, wantSaved.MultihopEntryMode = "", "", ""
				if wantEntry {
					wantSaved.MultihopEntryID, wantSaved.MultihopExitID, wantSaved.MultihopEntryMode = entrySource.ID, profile.ID, "wg"
				}
				response := f.request(t, q)
				if response.Code != http.StatusOK {
					t.Fatal(response.Code, response.Body.String())
				}
				var reply struct {
					Direct    bool   `json:"direct"`
					EntryID   string `json:"entry_id"`
					EntryMode string `json:"entry_mode"`
					Execution string `json:"execution"`
				}
				if json.Unmarshal(response.Body.Bytes(), &reply) != nil || reply.Direct == wantEntry || reply.Execution != "local" ||
					wantEntry && (reply.EntryID != entrySource.ID || reply.EntryMode != "wg") || !wantEntry && (reply.EntryID != "" || reply.EntryMode != "") {
					t.Fatal("public response lost the requested path", response.Body.String())
				}
				f.a.mu.Lock()
				current := cloneRouterProfile(f.a.profiles.Profiles[0])
				connected, base := f.a.state.Connected, f.a.state.Base
				f.a.mu.Unlock()
				if !connected || desktopTorSourceIdentityToken(wantSaved) != desktopTorSourceIdentityToken(current) || f.launch.tor.profileToken != original || f.launch.tor.sourceIdentityToken() != desktopTorSourceIdentityToken(current) || !reflect.DeepEqual(entrySource, f.a.profiles.Profiles[1]) ||
					wantEntry && base != "wg" || !wantEntry && base != "tor" || f.preflight != 2 || f.commands != 1 {
					t.Fatal("public Connect lost the proved saved choice or changed the captured private source", base)
				}
				if got, ok := activeDNSRuntimeIdentities.Load(f.a); !ok || got.(activeDNSRuntimeIdentity).Config != filepath.Join(f.launch.directory, "sing-box.json") {
					t.Fatal("admitted Tor runtime did not publish its own DNS configuration")
				}
				observed := observedConnection{Connected: true, Phase: "connected", Mode: "external-node", RuntimeMode: f.launch.mode, RouterID: current.ID, Profile: current}
				proof := proveSelectedDNSWithLookup(context.Background(), f.a, observed, f.launch.mode, func(context.Context, string) ([]string, error) {
					t.Fatal("public Tor connection escaped to the ordinary DNS resolver")
					return nil, nil
				})
				if proof.Status != "passed" || path == "home-router" && f.launch.tor.expected.DNS.Address != entrySource.AdGuardIPv4 {
					t.Fatal("public Connect lost its selected DNS path", proof)
				}
				if err := f.a.stopModeWithIntent(true); err != nil {
					t.Fatal("public runtime did not join owned shutdown", err)
				}
				if _, present := desktopNodeOwners.Load(f.a); present || !desktopNodeProcessExited(f.launch) {
					t.Fatal("owned Tor shutdown left a child or native owner")
				}
			})
		}
	}
}

func TestDesktopTorPublicConnectRejectsSelectionBeforePreparation(t *testing.T) {
	for _, fault := range []string{"direct-entry", "direct-mode", "direct-wg-base", "unknown-base", "unknown-mode", "server", "compare", "missing-entry", "same-node", "external-entry", "wrong-saved-exit", "stale-token"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopTorConnectFixture(t)
			profile := &f.a.profiles.Profiles[0]
			q := externalProfileConnectRequest{ProfileID: profile.ID}
			switch fault {
			case "direct-entry", "direct-mode", "direct-wg-base":
				direct := true
				q.Direct = &direct
				if fault == "direct-entry" {
					q.EntryID = f.a.profiles.Profiles[1].ID
				}
				if fault == "direct-mode" {
					q.EntryMode = "wg"
				}
				if fault == "direct-wg-base" {
					q.Base = "wg"
				}
			case "unknown-base":
				q.Base = "guess"
			case "unknown-mode":
				q.EntryMode = "guess"
			case "server":
				q.Execution = "server"
			case "compare":
				q.Execution = "auto"
			case "missing-entry":
				q.EntryID = "missing"
			case "same-node":
				q.EntryID = profile.ID
			case "external-entry":
				f.a.profiles.Profiles[1].NodeKind = "external"
			case "wrong-saved-exit":
				profile.MultihopExitID = "different-exit"
			case "stale-token":
				q.ExpectedSelectedNodeID = &f.a.profiles.SelectedID
				q.ExpectedProfileTokens = map[string]string{profile.ID: strings.Repeat("a", 64)}
			}
			response := f.request(t, q)
			if response.Code != http.StatusBadRequest && response.Code != http.StatusConflict || f.launch != nil || f.preflight != 0 || f.commands != 0 {
				t.Fatal("unowned selection reached native preparation", response.Code, response.Body.String())
			}
		})
	}
}

func TestDesktopTorPublicConnectPreparationCannotRetirePreviousOwner(t *testing.T) {
	for _, route := range []string{"tor", "external"} {
		for _, fault := range []string{"native-preflight", "entry-credential", "entry-source", "exit-credential", "cancelled", "selection-token"} {
			t.Run(route+"/"+fault, func(t *testing.T) {
				f := newDesktopTorConnectFixture(t)
				f.unified = route == "external"
				oldCommand := exec.Command("never-started-previous-owner")
				f.a.cmd = oldCommand
				oldDNS := activeDNSRuntimeIdentity{ProfileID: "previous", RuntimeID: "previous", Config: "previous-owned-config"}
				activeDNSRuntimeIdentities.Store(f.a, oldDNS)
				selected := f.a.profiles.SelectedID
				q := externalProfileConnectRequest{ProfileID: selected, ExpectedSelectedNodeID: &selected, ExpectedProfileTokens: map[string]string{}}
				for _, p := range f.a.profiles.Profiles {
					q.ExpectedProfileTokens[p.ID] = publicProfileToken(p)
				}
				original := f.driver.preflight
				f.driver.preflight = func(ctx context.Context, executable string, args, env []string, dir string) error {
					if err := original(ctx, executable, args, env, dir); err != nil {
						return err
					}
					if got, _ := activeDNSRuntimeIdentities.Load(f.a); got != oldDNS || f.a.cmd != oldCommand {
						t.Fatal("preparation replaced the previous native/DNS owner")
					}
					if f.preflight != 2 {
						return nil
					}
					switch fault {
					case "native-preflight":
						return errors.New("native parser rejected captured input")
					case "entry-credential":
						f.a.profiles.Profiles[1].APIToken = "changed-private-entry"
					case "entry-source":
						path := filepath.Join(clientRoot(f.a), "generated", "captured", "wg", "wg.conf")
						raw, err := os.ReadFile(path)
						if err != nil || os.WriteFile(path, append(raw, []byte("\n# changed source\n")...), 0600) != nil {
							t.Fatal("source fixture failed", err)
						}
					case "exit-credential":
						f.a.profiles.Profiles[0].External.TorBridge.Bridges[0] = clientMeekBridge
					case "cancelled":
						f.a.cancelConnectionOperation()
					case "selection-token":
						f.a.profiles.SelectedID = f.a.profiles.Profiles[1].ID
					}
					return nil
				}
				response := f.request(t, q)
				if response.Code != http.StatusBadRequest && response.Code != http.StatusConflict || f.a.cmd != oldCommand {
					t.Fatal("failed capture retired the previous owner", response.Code, response.Body.String())
				}
				if got, _ := activeDNSRuntimeIdentities.Load(f.a); got != oldDNS {
					t.Fatal("failed preparation replaced the previous DNS owner", got)
				}
				if f.launch == nil || f.preflight != 2 {
					t.Fatal("fixture did not reach the owned native admission boundary", response.Body.String())
				}
				if _, err := os.Lstat(f.launch.directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed preparation retained its own unstarted workspace", err)
				}
				if f.launch.command != nil && f.launch.command.Process != nil {
					t.Fatal("rejected preparation started its child")
				}
			})
		}
	}
}

func TestDesktopTorPublicConnectJoinsFailedNativeAdmission(t *testing.T) {
	for _, route := range []string{"tor", "external"} {
		for _, failure := range []string{"exec-start", "pre-native-exit"} {
			t.Run(route+"/"+failure, func(t *testing.T) {
				f := newDesktopTorConnectFixture(t)
				f.unified = route == "external"
				command := f.driver.command
				f.driver.command = func(a *app, prepared torBridgeRuntime, environment []string) (*exec.Cmd, error) {
					cmd, err := command(a, prepared, environment)
					if err != nil {
						return nil, err
					}
					if failure == "exec-start" {
						cmd.Path = filepath.Join(t.TempDir(), "missing-native-wrapper")
					} else {
						cmd.Env = envWithValue(cmd.Env, "ROUTERVPN_TOR_TEST_CHILD", "prelaunch-failed")
					}
					return cmd, nil
				}
				response := f.request(t, externalProfileConnectRequest{ProfileID: f.a.profiles.SelectedID, Base: "auto"})
				if response.Code != http.StatusInternalServerError && response.Code != http.StatusBadGateway || f.a.state.Connected || f.launch == nil {
					t.Fatal("failed admission reported a connected Tor path", response.Code, response.Body.String())
				}
				if _, exists := desktopNodeOwners.Load(f.a); exists {
					t.Fatal("failed admission retained a native owner", response.Body.String())
				}
				if _, exists := activeDNSRuntimeIdentities.Load(f.a); exists {
					t.Fatal("failed admission retained a DNS owner")
				}
				if f.launch.command.Process != nil && !desktopNodeProcessExited(f.launch) {
					t.Fatal("failed admission left its subprocess alive")
				}
				if _, err := os.Lstat(f.launch.directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed admission retained its unused private inputs", err)
				}
			})
		}
	}
}
