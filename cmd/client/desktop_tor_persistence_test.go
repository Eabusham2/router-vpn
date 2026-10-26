package main

import (
	"bytes"
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
)

func desktopTorStoredProfile(t *testing.T, f *desktopTorConnectFixture) []byte {
	t.Helper()
	raw, err := os.ReadFile(f.a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func desktopTorProfileRequest(t *testing.T, f *desktopTorConnectFixture, route string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerConnectionProfileRoutes(mux, f.a)
	result := httptest.NewRecorder()
	mux.ServeHTTP(result, httptest.NewRequest(http.MethodPost, route, bytes.NewReader(raw)))
	return result
}

func TestDesktopTorSavedChoiceDrivesStartupLastAndCompleteProfiles(t *testing.T) {
	for _, direct := range []bool{true, false} {
		name := "explicit-router"
		if direct {
			name = "direct-overrides-saved-router"
		}
		t.Run(name, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "last.json")
			p := &f.a.profiles.Profiles[0]
			p.AutoConnect, p.StartupMode = true, "last"
			if !direct {
				p.MultihopEnabled = false
				p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = "", "", ""
			}
			original, entry := cloneRouterProfile(*p), cloneRouterProfile(f.a.profiles.Profiles[1])
			q := externalProfileConnectRequest{ProfileID: p.ID, Base: "auto", Direct: &direct}
			if !direct {
				q.EntryID, q.EntryMode = entry.ID, "wg"
			}
			response := f.request(t, q)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"choice_saved":true`) {
				t.Fatal("proved public choice was not saved", response.Code, response.Body.String())
			}
			first := f.launch
			f.a.mu.Lock()
			stored := cloneRouterProfile(f.a.profiles.Profiles[0])
			f.a.mu.Unlock()
			if stored.MultihopEnabled == direct || stored.MultihopExecution != "local" || !reflect.DeepEqual(stored.External, original.External) || !reflect.DeepEqual(f.a.profiles.Profiles[1], entry) {
				t.Fatal("saved choice lost its exact path or copied private source")
			}
			if direct && (stored.MultihopEntryID != "" || stored.MultihopExitID != "" || stored.MultihopEntryMode != "") || !direct && (stored.MultihopEntryID != entry.ID || stored.MultihopExitID != stored.ID || stored.MultihopEntryMode != "wg") {
				t.Fatal("saved graph differs from public Connect")
			}
			var onDisk struct {
				Profiles []json.RawMessage `json:"profiles"`
			}
			if err := json.Unmarshal(desktopTorStoredProfile(t, f), &onDisk); err != nil || len(onDisk.Profiles) != 2 {
				t.Fatal("profile store was not durably written", err)
			}
			var savedPath struct {
				Enabled bool   `json:"multihop_enabled"`
				Entry   string `json:"multihop_entry_id"`
				Mode    string `json:"multihop_entry_mode"`
			}
			if json.Unmarshal(onDisk.Profiles[0], &savedPath) != nil || savedPath.Enabled != stored.MultihopEnabled || savedPath.Entry != stored.MultihopEntryID || savedPath.Mode != stored.MultihopEntryMode {
				t.Fatal("disk and admitted saved graph differ")
			}
			last, err := f.a.loadStartupSelection()
			if err != nil || last.External == nil || last.External.Direct != direct || last.External.EntryID != stored.MultihopEntryID || last.External.EntryMode != stored.MultihopEntryMode || last.External.Execution != "local" || last.ProfileToken != startupExternalProfileToken(stored) || last.RuntimeMode != "external-tor-bridge" {
				t.Fatal("Startup Last lost its proved choice", err)
			}
			lastBytes, err := os.ReadFile(f.a.cfg.StateFile)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"bridges", "private_key", "api_token", "password"} {
				if bytes.Contains(lastBytes, []byte(secret)) {
					t.Fatal("Startup Last copied private material", secret)
				}
			}
			if err := f.a.stopModeWithIntent(true); err != nil {
				t.Fatal(err)
			}
			capture, err := f.a.captureStartupPolicy()
			if err != nil || capture == nil {
				t.Fatal("saved path could not be captured for Startup Last", err)
			}
			f.a.applyCapturedStartupPolicy(context.Background(), capture, externalConnectRuntime{tor: f.driver})
			if !f.a.state.Connected || f.launch == first || f.launch.tor.expected.SessionID == first.tor.expected.SessionID || f.launch.tor.expected.EntryID != first.tor.expected.EntryID || f.launch.tor.expected.EntryMode != first.tor.expected.EntryMode || f.launch.tor.expected.DNS != first.tor.expected.DNS {
				t.Fatal("Startup Last did not freshly prove the saved path")
			}
			if err := f.a.stopModeWithIntent(true); err != nil {
				t.Fatal(err)
			}
			response = desktopTorProfileRequest(t, f, "/api/connection-profile/save", map[string]any{"name": "Saved proved Tor choice", "mode": "external"})
			var record struct {
				Profile connectionProfileRecord `json:"profile"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &record) != nil || record.Profile.External == nil || record.Profile.External.MultihopEnabled != stored.MultihopEnabled || record.Profile.External.MultihopEntryID != stored.MultihopEntryID || record.Profile.External.MultihopEntryMode != stored.MultihopEntryMode {
				t.Fatal("complete profile did not capture the remembered Tor path", response.Code, response.Body.String())
			}
			f.a.mu.Lock()
			f.a.profiles.Profiles[0].MultihopEnabled = !stored.MultihopEnabled
			f.a.profiles.Profiles[0].MultihopEntryID, f.a.profiles.Profiles[0].MultihopExitID, f.a.profiles.Profiles[0].MultihopEntryMode = "", "", ""
			if !stored.MultihopEnabled {
				f.a.profiles.Profiles[0].MultihopEntryID, f.a.profiles.Profiles[0].MultihopExitID, f.a.profiles.Profiles[0].MultihopEntryMode = entry.ID, stored.ID, "wg"
			}
			f.a.mu.Unlock()
			response = desktopTorProfileRequest(t, f, "/api/connection-profile/load", map[string]any{"id": record.Profile.ID})
			if response.Code != http.StatusOK {
				t.Fatal("complete profile could not restore remembered path", response.Code, response.Body.String())
			}
			loaded := f.a.profiles.Profiles[0]
			if loaded.MultihopEnabled != stored.MultihopEnabled || loaded.MultihopEntryID != stored.MultihopEntryID || loaded.MultihopEntryMode != stored.MultihopEntryMode || !reflect.DeepEqual(loaded.External, original.External) || f.a.state.Connected {
				t.Fatal("complete profile load changed credentials or failed to restore choice")
			}
			response = desktopTorProfileRequest(t, f, "/api/connection-profile/delete", map[string]any{"id": record.Profile.ID})
			if response.Code != http.StatusOK || !reflect.DeepEqual(f.a.profiles.Profiles[0].External, original.External) {
				t.Fatal("deleting saved choice affected its linked private node")
			}
		})
	}
}

type desktopTorChoiceFixture struct {
	*desktopTorConnectFixture
	selection *desktopTorSelection
	request   externalProfileConnectRequest
	operation context.Context
	selected  string
	ip        string
}

// Stage the same shipping command/admission/proof path as public Connect, then
// stop at its real commit/adoption boundary so stale completions are controlled
// without a scheduler delay or a production persistence injection hook.
func prepareDesktopTorChoiceFixture(t *testing.T, direct bool) desktopTorChoiceFixture {
	t.Helper()
	f := speedLabTorPipelineFixture(t)
	f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "last.json")
	if !direct {
		p := &f.a.profiles.Profiles[0]
		p.MultihopEnabled = false
		p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = "", "", ""
	}
	if err := f.a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	operation, finish, err := f.a.beginConnectionTransaction()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(finish)
	profile := cloneRouterProfile(f.a.profiles.Profiles[0])
	q := externalProfileConnectRequest{ProfileID: profile.ID, Base: "auto", Direct: &direct}
	selected := f.a.profiles.SelectedID
	q.ExpectedSelectedNodeID = &selected
	q.ExpectedProfileTokens = map[string]string{profile.ID: publicProfileToken(profile)}
	if !direct {
		q.EntryID, q.EntryMode = f.a.profiles.Profiles[1].ID, "wg"
		q.ExpectedProfileTokens[q.EntryID] = publicProfileToken(f.a.profiles.Profiles[1])
	}
	selection, err := captureDesktopTorSelection(f.a, profile, q, nil)
	if err != nil {
		t.Fatal(err)
	}
	command, prelaunch, err := prepareTorBridgeCommandWithRuntime(f.a, selection.policy, profile, selection.predecessor, f.driver)
	if err != nil {
		t.Fatal(err)
	}
	check := func() error {
		if err := operation.Err(); err != nil {
			return err
		}
		return selection.current(f.a)
	}
	if err := prelaunch.start(check); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	f.a.cmd = command
	f.a.state = state{Mode: "external-node", LogicalMode: "external-node", RuntimeMode: "external-tor-bridge", RouterID: profile.ID, Base: "tor", Phase: "tor-bridge:proving-exit"}
	if !direct {
		f.a.state.Base = "wg"
	}
	f.a.mu.Unlock()
	proof, err := f.a.waitDesktopTorProof(operation, f.launch)
	if err != nil {
		t.Fatal(err)
	}
	return desktopTorChoiceFixture{f, selection, q, operation, selected, proof.Proof.IP}
}

func TestDesktopTorChoiceCommitRejectsStaleSourceBeforeDiskWrite(t *testing.T) {
	for _, fault := range []string{"cancelled", "operation", "selection", "source", "entry-credential", "entry-asset", "request-token", "runtime", "state-path", "owner", "public-exit", "unproved-mode"} {
		t.Run(fault, func(t *testing.T) {
			f := prepareDesktopTorChoiceFixture(t, false)
			before := desktopTorStoredProfile(t, f.desktopTorConnectFixture)
			switch fault {
			case "cancelled":
				f.a.cancelConnectionOperation()
			case "operation":
				f.a.mu.Lock()
				f.a.connectionContext = context.Background()
				f.a.mu.Unlock()
			case "selection":
				f.a.mu.Lock()
				f.a.profiles.SelectedID = f.a.profiles.Profiles[1].ID
				f.a.mu.Unlock()
			case "source":
				f.a.mu.Lock()
				f.a.profiles.Profiles[0].External.TorBridge.Bridges[0] = clientMeekBridge
				f.a.mu.Unlock()
			case "entry-credential":
				f.a.mu.Lock()
				f.a.profiles.Profiles[1].APIToken = "replacement-private-source"
				f.a.mu.Unlock()
			case "entry-asset":
				path := filepath.Join(clientRoot(f.a), "generated", "captured", "wg", "wg.conf")
				raw, err := os.ReadFile(path)
				if err != nil || os.WriteFile(path, append(raw, []byte("\n# replacement source\n")...), 0600) != nil {
					t.Fatal("entry source fixture failed", err)
				}
			case "request-token":
				f.request.ExpectedProfileTokens[f.selection.profile.ID] = strings.Repeat("a", 64)
			case "runtime":
				f.a.mu.Lock()
				f.a.cmd = exec.Command("never-started-replacement")
				f.a.mu.Unlock()
			case "state-path":
				f.a.mu.Lock()
				f.a.state.Base = "unrelated-base"
				f.a.mu.Unlock()
			case "owner":
				desktopNodeOwners.Store(f.a, &desktopNodeLaunch{})
				defer desktopNodeOwners.Store(f.a, f.launch)
			case "public-exit":
				f.ip = "203.0.113.91"
			case "unproved-mode":
				f.selection.policy.MultihopEntryMode = "awg2-strong"
			}
			if _, err := f.a.commitDesktopTorChoice(f.selection, f.launch, f.request, nil, f.operation, f.selected, f.ip); err == nil {
				t.Fatal("stale completion saved an unowned choice", fault)
			}
			if !bytes.Equal(before, desktopTorStoredProfile(t, f.desktopTorConnectFixture)) || f.launch.tor.committedChoice.Load() != nil || f.a.state.Connected {
				t.Fatal("rejected choice changed disk or adopted runtime", fault)
			}
		})
	}
}

func TestDesktopTorSavedChoiceCannotAdoptStaleRuntimeOrPreviousToken(t *testing.T) {
	for _, fault := range []string{"cancelled", "operation", "selection", "source", "entry-credential", "entry-asset", "old-source-token", "runtime", "state-path", "owner", "foreign-saved-session", "startup-write"} {
		t.Run(fault, func(t *testing.T) {
			f := prepareDesktopTorChoiceFixture(t, !strings.HasPrefix(fault, "entry-"))
			saved, err := f.a.commitDesktopTorChoice(f.selection, f.launch, f.request, nil, f.operation, f.selected, f.ip)
			if err != nil {
				t.Fatal(err)
			}
			before := desktopTorStoredProfile(t, f.desktopTorConnectFixture)
			if f.launch.tor.profileToken != f.selection.profileToken || f.launch.tor.sourceIdentityToken() == f.selection.profileToken || f.a.state.Connected {
				t.Fatal("commit changed native capture, accepted both tokens, or prematurely connected")
			}
			switch fault {
			case "cancelled":
				f.a.cancelConnectionOperation()
			case "operation":
				f.a.mu.Lock()
				f.a.connectionContext = context.Background()
				f.a.mu.Unlock()
			case "selection":
				f.a.mu.Lock()
				f.a.profiles.SelectedID = f.a.profiles.Profiles[1].ID
				f.a.mu.Unlock()
			case "source":
				f.a.mu.Lock()
				f.a.profiles.Profiles[0].DNSHost = "8.8.8.8"
				f.a.mu.Unlock()
			case "entry-credential":
				f.a.mu.Lock()
				f.a.profiles.Profiles[1].APIToken = "replacement-private-source"
				f.a.mu.Unlock()
			case "entry-asset":
				path := filepath.Join(clientRoot(f.a), "generated", "captured", "wg", "wg.conf")
				raw, err := os.ReadFile(path)
				if err != nil || os.WriteFile(path, append(raw, []byte("\n# replacement source\n")...), 0600) != nil {
					t.Fatal("entry source fixture failed", err)
				}
			case "old-source-token":
				f.a.mu.Lock()
				f.a.profiles.Profiles[0] = cloneRouterProfile(f.selection.profile)
				f.a.mu.Unlock()
				if f.a.desktopTorCurrent(f.launch) == nil {
					t.Fatal("native owner accepted the previous source after saving a different choice")
				}
			case "runtime":
				f.a.mu.Lock()
				f.a.cmd = exec.Command("never-started-replacement")
				f.a.mu.Unlock()
			case "state-path":
				f.a.mu.Lock()
				f.a.state.RouterID = "unrelated-node"
				f.a.mu.Unlock()
			case "owner":
				desktopNodeOwners.Store(f.a, &desktopNodeLaunch{})
				defer desktopNodeOwners.Store(f.a, f.launch)
			case "foreign-saved-session":
				foreign := *saved.choice
				foreign.sessionID = "unrelated-session"
				f.launch.tor.committedChoice.Store(&foreign)
			case "startup-write":
				if err := os.Mkdir(f.a.cfg.StateFile, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := saved.adopt(f.a); err == nil {
				t.Fatal("saved choice adopted stale completion", fault)
			}
			if !bytes.Equal(before, desktopTorStoredProfile(t, f.desktopTorConnectFixture)) || f.a.state.Connected {
				t.Fatal("post-save failure claimed rollback or adopted a retired runtime", fault)
			}
		})
	}
}

func TestDesktopTorSavedChoiceRetiresOldDNSAndMeasurementCapture(t *testing.T) {
	f := prepareDesktopTorChoiceFixture(t, true)
	f.a.mu.Lock()
	st := f.a.state
	f.a.mu.Unlock()
	previous, err := captureDesktopTorMeasurementBinding(f.a, st)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := f.a.commitDesktopTorChoice(f.selection, f.launch, f.request, nil, f.operation, f.selected, f.ip)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saved.adopt(f.a); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	oldErr := previous.currentLocked(f.a)
	currentProfile, currentState := cloneRouterProfile(f.a.profiles.Profiles[0]), f.a.state
	f.a.mu.Unlock()
	if oldErr == nil {
		t.Fatal("measurement retained the previous saved graph token")
	}
	current, err := captureDesktopTorMeasurementBinding(f.a, currentState)
	if err != nil || current.profileToken == previous.profileToken || current.profileToken != saved.choice.profileToken || current.source != previous.source || current.config != previous.config || current.session != previous.session {
		t.Fatal("saved choice lost the current measurement owner or rewrote native input identity", err)
	}
	observation := observedConnection{Connected: true, Phase: "connected", Mode: "external-node", RuntimeMode: "external-tor-bridge", RouterID: currentProfile.ID, Profile: currentProfile}
	if proof := proveDesktopTorDNS(context.Background(), f.a, observation, observation.RuntimeMode); proof.Status != "passed" {
		t.Fatal("saved source lost actual selected DNS proof", proof)
	}
	observation.Profile = cloneRouterProfile(f.selection.profile)
	if proof := proveDesktopTorDNS(context.Background(), f.a, observation, observation.RuntimeMode); proof.Status != "failed" || !strings.Contains(proof.Reason, "captured private policy") {
		t.Fatal("DNS accepted the previous saved graph token", proof)
	}
}

func TestDesktopTorPublicChoicePersistenceFailureReportsActualCommitState(t *testing.T) {
	for _, fault := range []string{"profiles-write", "startup-write"} {
		t.Run(fault, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "last.json")
			before := cloneRouterProfileStore(f.a.profiles)
			path := f.a.cfg.ProfilesFile
			if fault == "startup-write" {
				path = f.a.cfg.StateFile
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			direct := true
			response := f.request(t, externalProfileConnectRequest{ProfileID: before.SelectedID, Direct: &direct, Base: "auto"})
			if response.Code < 400 || f.a.state.Connected || f.a.cmd != nil || f.launch == nil || !desktopNodeProcessExited(f.launch) {
				t.Fatal("failed durable choice was reported connected or kept its process", response.Code, response.Body.String())
			}
			if fault == "profiles-write" {
				if !reflect.DeepEqual(before, f.a.profiles) || f.launch.tor.committedChoice.Load() != nil || !strings.Contains(response.Body.String(), errDesktopTorChoiceSave.Error()) {
					t.Fatal("pre-commit failure did not restore prior source", response.Body.String())
				}
			} else if f.a.profiles.Profiles[0].MultihopEnabled || f.launch.tor.committedChoice.Load() == nil || !strings.Contains(response.Body.String(), "path choice was saved") || len(desktopTorStoredProfile(t, f)) == 0 {
				t.Fatal("post-commit failure falsely reported a disk rollback", response.Body.String())
			}
			if _, found := desktopNodeOwners.Load(f.a); found {
				t.Fatal("failed persistence left a native owner")
			}
			if _, found := activeDNSRuntimeIdentities.Load(f.a); found {
				t.Fatal("failed persistence left a DNS owner")
			}
			if _, err := f.a.loadStartupSelection(); err == nil || !errors.Is(err, os.ErrNotExist) && fault == "profiles-write" {
				t.Fatal("failed persistence wrote a Last record", err)
			}
		})
	}
}
