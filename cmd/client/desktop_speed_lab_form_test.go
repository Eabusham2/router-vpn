package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopSpeedLabFormApp(t *testing.T) *app {
	t.Helper()
	// Select the shipped native branch for Linux callback validation too.
	// Actual payload/receipt integrity is checked by the native bundle tests;
	// this isolated form test never launches or blesses a runtime.
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	manifest := filepath.Join(root, "runtime", "native", "NATIVE-RUNTIME.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	profile, err := externalProfileFromCreateRequest(desktopOpenVPNCreateFixture(t, common.StartLayerOff))
	if err != nil {
		t.Fatal(err)
	}
	profile.ID, profile.Name = "exit", "Paired OpenVPN exit"
	profile.MultihopEnabled, profile.MultihopEntryID, profile.MultihopExitID = true, "entry", "exit"
	profile.MultihopEntryMode, profile.MultihopExecution = "awg2-strong", "auto"
	entry, _ := desktopNodeFixture(t, "203.0.113.8")
	entry.ID, entry.Name, entry.BaseTunnel = "entry", "Router entry", "awg"
	exit, _ := desktopNodeFixture(t, "198.51.100.9")
	exit.ID, exit.Name = "exit-router", "Router exit"
	ordinary, _ := desktopExternalNativeFixture(t, "socks5")
	ordinary.ID, ordinary.Name = "external-entry", "External entry"
	a := &app{profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion, SelectedID: profile.ID,
		Profiles: []common.RouterProfile{profile, entry, ordinary, exit}}, state: state{Mode: "off", Phase: "off"}}
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &a.modes); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDesktopSpeedLabPathFormCatalog(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_EXTERNAL_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("native UI runner supplies its callback payload directory")
	}
	a := desktopSpeedLabFormApp(t)
	response := httptest.NewRecorder()
	a.speedLabOptions(response, httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil))
	if response.Code != http.StatusOK {
		t.Fatal("native Speed Lab options failed")
	}
	if err := os.WriteFile(filepath.Join(directory, "speed-lab-options.json"), response.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSpeedLabPathFormPayload(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_EXTERNAL_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("native UI runner supplies its callback payload directory")
	}
	a := desktopSpeedLabFormApp(t)
	profile, _ := profileByID(a.profiles.Profiles, "exit")
	read := func(name string) (speedLabRequest, map[string]json.RawMessage) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(directory, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var request speedLabRequest
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			t.Fatal(name, err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := normalizeSpeedLabDuration(request.DurationMode, request.MinSeconds, request.MaxSeconds); err != nil {
			t.Fatal(name, err)
		}
		if os.Getenv("ROUTERVPN_SPEED_LAB_FORM_CAPTURE_REQUIRED") == "1" && !request.hasExpectedProfiles() {
			t.Fatal(name, "native Run omitted its captured source revisions")
		}
		if request.hasExpectedProfiles() {
			expectedSelected := "exit"
			if strings.HasPrefix(name, "speed-lab-main-entry-") {
				expectedSelected = "entry"
			}
			for _, mode := range mobilemultihop.NodeMultihopExitModes() {
				if strings.HasPrefix(name, "speed-lab-multihop-"+mode+"-") {
					expectedSelected = "entry"
				}
			}
			if request.ExpectedSelectedNodeID != expectedSelected {
				t.Fatal(name, "Run substituted another visible main selection")
			}
			previous := a.profiles.SelectedID
			a.profiles.SelectedID = expectedSelected
			if err := a.validateSpeedLabExpectedProfiles(request, nil); err != nil {
				t.Fatal(name, "actual form revisions differ from the captured private fixture", err)
			}
			changed := request
			changed.ExpectedProfileTokens = make(map[string]string, len(request.ExpectedProfileTokens))
			for id, token := range request.ExpectedProfileTokens {
				changed.ExpectedProfileTokens[id] = token
			}
			delete(changed.ExpectedProfileTokens, expectedSelected)
			if a.validateSpeedLabExpectedProfiles(changed, nil) == nil {
				t.Fatal(name, "partial form capture did not fail closed")
			}
			a.profiles.SelectedID = previous
		}
		return request, fields
	}
	for _, mode := range a.externalRouterEntryModes() {
		for _, execution := range []string{"local", "server", "auto"} {
			t.Run(mode["id"]+"/"+execution, func(t *testing.T) {
				request, _ := read("speed-lab-external-" + mode["id"] + "-" + execution)
				if request.Scope != "temporary" || request.Topology != "external" || request.NodeID != "exit" || request.EntryID != "entry" || request.EntryMode != mode["id"] || request.Execution != execution || request.ExitID != "" || request.Base != "" {
					t.Fatal("native Speed Lab callback substituted its external path")
				}
				entry, kind, direct, err := speedLabExternalEntry(a.profiles.Profiles, profile, request)
				if err != nil || kind != "router-vpn" || direct {
					t.Fatal("native external entry rejected", err)
				}
				captured, err := desktopExternalEntryMode(profile, entry, request.EntryMode, request.Base)
				if err != nil || captured != mode["id"] {
					t.Fatal("native entry mode changed", err)
				}
				chosen, err := externalExecutionChoice(profile, request.Execution, direct)
				if err != nil || chosen != execution {
					t.Fatal("native execution changed", err)
				}
			})
		}
	}
	for _, name := range []string{"speed-lab-external-direct", "speed-lab-external-entry"} {
		t.Run(name, func(t *testing.T) {
			request, fields := read(name)
			if request.Scope != "temporary" || request.Topology != "external" || request.NodeID != "exit" || request.EntryMode != "" || request.Execution != "local" {
				t.Fatal("native Local path carried another execution or Router mode")
			}
			if _, ok := fields["entry_mode"]; ok {
				t.Fatal("inactive entry_mode was serialized")
			}
			_, kind, direct, err := speedLabExternalEntry(a.profiles.Profiles, profile, request)
			if err != nil {
				t.Fatal(err)
			}
			if name == "speed-lab-external-direct" {
				if !direct || request.EntryID != "" {
					t.Fatal("Direct acquired a hop")
				}
			} else if direct || kind != "external" || request.EntryID != "external-entry" {
				t.Fatal("ordinary external entry changed")
			}
		})
	}
	for _, execution := range []string{"local", "server", "auto"} {
		request, _ := read("speed-lab-multihop-" + execution)
		if request.Scope != "temporary" || request.Topology != "multihop" || request.EntryID != "entry" || request.ExitID != "exit-router" || request.Execution != execution {
			t.Fatal("native Router multihop callback changed its path")
		}
		if request.EntryMode != "" {
			t.Fatal("legacy Router multihop lost its saved entry/base fallback")
		}
		parsed, err := routeExecution(multihopConnectRequest{Execution: request.Execution})
		if err != nil || string(parsed) != execution {
			t.Fatal("native multihop execution changed", err)
		}
	}
	control, _ := profileByID(a.profiles.Profiles, "entry")
	for _, mode := range mobilemultihop.NodeMultihopExitModes() {
		for _, execution := range []string{"local", "server", "auto"} {
			t.Run("router/"+mode+"/"+execution, func(t *testing.T) {
				request, _ := read("speed-lab-multihop-" + mode + "-" + execution)
				if request.Scope != "temporary" || request.Topology != "multihop" || request.EntryID != "entry" || request.ExitID != "exit-router" || request.ExitMode != mode || request.Execution != execution {
					t.Fatal("native Router callback substituted its selected exit mode or execution")
				}
				if request.EntryMode != "" {
					t.Fatal("legacy exit form changed its saved entry/base fallback")
				}
				selected, err := a.resolveSpeedLabMultihop(request, control, a.profiles.Profiles)
				if err != nil || selected.ExitMode != mode || selected.Entry.ID != "entry" || selected.Exit.ID != "exit-router" || selected.Base != request.Base {
					t.Fatal("shipping Speed Lab resolver changed native form graph", err)
				}
			})
		}
	}
	for _, prefix := range []string{"speed-lab-multihop-entry-", "speed-lab-main-entry-"} {
		for _, mode := range mobilemultihop.NodeMultihopEntryModes() {
			for _, execution := range []string{"local", "server", "auto"} {
				t.Run(prefix+mode+"/"+execution, func(t *testing.T) {
					request, fields := read(prefix + mode + "-" + execution)
					if request.Scope != "temporary" || request.Topology != "multihop" || request.EntryID != "entry" || request.ExitID != "exit-router" || request.EntryMode != mode || request.ExitMode != "shadowsocks" || request.Execution != execution || fields["entry_mode"] == nil {
						t.Fatal("native Router form substituted its captured raw entry or execution")
					}
					entry, ok := profileByID(a.profiles.Profiles, request.EntryID)
					if !ok {
						t.Fatal("native Router form lost the linked entry")
					}
					selected, err := a.resolveSpeedLabTemporaryMultihop(request, control, entry, a.profiles.Profiles)
					if err != nil || selected.EntryMode != mode || selected.Base != desktopExternalEntryBase(mode) || selected.ExitMode != "shadowsocks" || selected.Entry.ID != request.EntryID || selected.Exit.ID != request.ExitID || selected.Control.ID != entry.ID {
						t.Fatal("shipping temporary resolver changed the form's exact graph or policy owner", err)
					}
				})
			}
		}
	}
	for _, name := range []string{"speed-lab-current", "speed-lab-system-direct"} {
		request, fields := read(name)
		if name == "speed-lab-current" {
			if request.Scope != "current" {
				t.Fatal("current path changedscope")
			}
		} else if request.Scope != "temporary" || request.Topology != "system-direct" {
			t.Fatal("system direct scope changed")
		}
		for _, key := range []string{"entry_mode", "execution", "entry_id", "exit_id", "node_id"} {
			if _, ok := fields[key]; ok {
				t.Fatalf("inactive %s entered %s", key, name)
			}
		}
	}
	if !reflect.DeepEqual(a.profiles.Profiles[0], profile) {
		t.Fatal("form capture changed durable private node")
	}
}
