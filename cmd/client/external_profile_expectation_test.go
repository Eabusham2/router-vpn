package main

import (
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
)

func expectedExternalFixture(t *testing.T, path string) (*app, externalProfileConnectRequest, common.RouterProfile) {
	t.Helper()
	a := setupProfileTestApp(t)
	root, err := filepath.EvalSymlinks(os.Getenv("HOMEVPN_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	a.cfg.ProfilesFile = filepath.Join(root, "routers.json")
	profile := externalConnectionTestNode(t, "socks5")
	profile.External.SOCKS5.Password = "owned-exit-secret"
	entry, assets := desktopNodeFixture(t, "198.51.100.11")
	entry.ID = "entry"
	if path == "external-entry" {
		entry = externalConnectionTestNode(t, "socks5")
		entry.ID = "entry"
		entry.External.SOCKS5.Password = "owned-entry-secret"
	}
	a.profiles.Profiles[1], a.profiles.Profiles[3] = entry, profile
	a.profiles.SelectedID = "home"
	q := externalProfileConnectRequest{ProfileID: profile.ID, Execution: "local"}
	switch path {
	case "direct":
		direct := true
		q.Direct = &direct
	case "saved", "external-entry":
		profile.MultihopEnabled = true
		profile.MultihopEntryID, profile.MultihopExitID = entry.ID, profile.ID
		a.profiles.Profiles[3] = profile
	case "explicit":
		q.EntryID, q.EntryMode = entry.ID, "wg"
	case "direct-override":
		profile.MultihopEnabled = true
		profile.MultihopEntryID, profile.MultihopExitID = entry.ID, profile.ID
		a.profiles.Profiles[3] = profile
		direct := true
		q.Direct = &direct
	default:
		t.Fatal("unsupported expected-profile fixture path", path)
	}
	if path != "external-entry" {
		directory, err := nativeGeneratedDir(root, entry.ID, "wg")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		for name, body := range assets {
			if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	selected := a.profiles.SelectedID
	q.ExpectedSelectedNodeID = &selected
	q.ExpectedProfileTokens = map[string]string{}
	for _, id := range []string{selected, profile.ID, externalConnectExpectedEntry(q, profile)} {
		if id != "" {
			p, _ := a.profileByIDLocked(id)
			q.ExpectedProfileTokens[id] = publicProfileToken(p)
		}
	}
	t.Cleanup(func() { sessionTrackers.Delete(a); desktopNodeOwners.Delete(a) })
	return a, q, profile
}

func TestExternalProfileExpectationJSONCannotDowngradeMalformedCaptures(t *testing.T) {
	token := strings.Repeat("a", 64)
	valid := `{"profile_id":"external","expected_selected_node_id":"external","expected_profile_tokens":{"external":"` + token + `"}}`
	for _, raw := range []string{`{"profile_id":"external"}`, valid, strings.Replace(valid, `"expected_selected_node_id":"external"`, `"expected_selected_node_id":""`, 1)} {
		q, err := decodeExternalProfileConnectRequest(strings.NewReader(raw))
		if err != nil || (q.hasExpectedProfiles() != strings.Contains(raw, "expected_profile_tokens")) {
			t.Fatal("valid or legacy contract rejected", raw, err)
		}
		roundTrip, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		var decoded externalProfileConnectRequest
		if json.Unmarshal(roundTrip, &decoded) != nil || !reflect.DeepEqual(q, decoded) {
			t.Fatal("explicit empty selection or legacy omission changed in request serialization")
		}
	}
	bad := map[string]string{
		"null-object":       "null",
		"array-object":      "[]",
		"selected-only":     `{"profile_id":"external","expected_selected_node_id":"external"}`,
		"tokens-only":       `{"profile_id":"external","expected_profile_tokens":{"external":"` + token + `"}}`,
		"null-selection":    strings.Replace(valid, `"expected_selected_node_id":"external"`, `"expected_selected_node_id":null`, 1),
		"null-map":          strings.Replace(valid, `{"external":"`+token+`"}`, "null", 1),
		"array-map":         strings.Replace(valid, `{"external":"`+token+`"}`, "[]", 1),
		"null-token":        strings.Replace(valid, `"`+token+`"`, "null", 1),
		"number-token":      strings.Replace(valid, `"`+token+`"`, "123", 1),
		"uppercase-token":   strings.Replace(valid, token, strings.ToUpper(token), 1),
		"unsafe-id":         strings.Replace(valid, `{"external":`, `{"../external":`, 1),
		"duplicate-token":   strings.Replace(valid, `{"external":"`+token+`"}`, `{"external":"`+token+`","external":"`+token+`"}`, 1),
		"duplicate-field":   strings.Replace(valid, `"expected_selected_node_id":"external"`, `"expected_selected_node_id":"external","expected_selected_node_id":"external"`, 1),
		"case-folded-field": strings.Replace(valid, "expected_profile_tokens", "EXPECTED_PROFILE_TOKENS", 1),
		"unknown-field":     strings.Replace(valid, `"profile_id":`, `"unowned_option":true,"profile_id":`, 1),
		"trailing-request":  valid + valid,
	}
	oversized := map[string]string{}
	for i := 0; i < 65; i++ {
		oversized[strings.Repeat("x", i+1)] = token
	}
	encoded, _ := json.Marshal(oversized)
	bad["oversized-map"] = strings.Replace(valid, `{"external":"`+token+`"}`, string(encoded), 1)
	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeExternalProfileConnectRequest(strings.NewReader(raw)); err == nil {
				t.Fatal("malformed capture downgraded to an unguarded request")
			}
			a, _, _ := expectedExternalFixture(t, "direct")
			command := &exec.Cmd{}
			a.cmd = command
			state, profiles := a.state, cloneRouterProfileStore(a.profiles)
			response := httptest.NewRecorder()
			a.externalProfileConnect(response, httptest.NewRequest(http.MethodPost, "/api/external-profile/connect", strings.NewReader(raw)))
			if response.Code != http.StatusBadRequest || a.cmd != command || a.state != state || !reflect.DeepEqual(a.profiles, profiles) {
				t.Fatal("malformed HTTP request changed a runtime or profile", response.Code, response.Body.String())
			}
			if !a.operationMu.TryLock() {
				t.Fatal("malformed HTTP request retained the connection transaction")
			}
			a.operationMu.Unlock()
		})
	}
}

func TestExternalProfileExpectationsCoverResolvedPathAndIgnoreTelemetry(t *testing.T) {
	for _, path := range []string{"direct", "explicit", "saved", "external-entry", "direct-override"} {
		t.Run(path, func(t *testing.T) {
			a, q, captured := expectedExternalFixture(t, path)
			if err := a.validateExternalProfileExpectedProfiles(q, captured); err != nil {
				t.Fatal("matching source was rejected", err)
			}
			for i := range a.profiles.Profiles {
				a.profiles.Profiles[i].Name = "new display name"
				a.profiles.Profiles[i].LatencyMedianMs = 8.2
				a.profiles.Profiles[i].EffectiveMTU = 1392
			}
			if err := a.validateExternalProfileExpectedProfiles(q, captured); err != nil {
				t.Fatal("telemetry invalidated captured credentials", err)
			}
			for id, token := range q.ExpectedProfileTokens {
				delete(q.ExpectedProfileTokens, id)
				if a.validateExternalProfileExpectedProfiles(q, captured) == nil {
					t.Fatal("missing required source was accepted", id)
				}
				q.ExpectedProfileTokens[id] = token
			}
			if path == "direct-override" {
				if _, exists := q.ExpectedProfileTokens["entry"]; exists {
					t.Fatal("Direct borrowed the saved entry source")
				}
			}
			// Empty selected identity is still an explicit precondition. It is
			// not the absence of a guarded request for this explicit exit.
			a.profiles.SelectedID = ""
			*q.ExpectedSelectedNodeID = ""
			delete(q.ExpectedProfileTokens, "home")
			if err := a.validateExternalProfileExpectedProfiles(q, captured); err != nil {
				t.Fatal("explicit no-selection capture was rejected", err)
			}
			a.profiles.SelectedID = "home"
			if a.validateExternalProfileExpectedProfiles(q, captured) == nil {
				t.Fatal("empty selection failed to protect a later selected node")
			}
		})
	}
}

func TestExternalProfileExpectedHTTPRejectsRelinkBeforePreparation(t *testing.T) {
	for _, fault := range []string{"selected", "exit-credential", "entry-credential", "selected-credential", "node-proof", "policy", "saved-entry", "missing", "duplicate", "incomplete", "extra-node"} {
		t.Run(fault, func(t *testing.T) {
			a, q, _ := expectedExternalFixture(t, "saved")
			switch fault {
			case "selected":
				a.profiles.SelectedID = "exit"
			case "exit-credential":
				a.profiles.Profiles[3].External.SOCKS5.Password = "replacement-exit-secret"
			case "entry-credential":
				a.profiles.Profiles[1].APIToken = "replacement-entry-secret"
			case "selected-credential":
				a.profiles.Profiles[0].APIToken = "replacement-selected-secret"
			case "node-proof":
				a.profiles.Profiles[1].NodeProofID = strings.Repeat("e", 64)
			case "policy":
				a.profiles.Profiles[3].DNSHost = "1.1.1.1"
			case "saved-entry":
				a.profiles.Profiles[3].MultihopEntryID = "exit"
			case "missing":
				a.profiles.Profiles = append(a.profiles.Profiles[:1], a.profiles.Profiles[2:]...)
			case "duplicate":
				a.profiles.Profiles = append(a.profiles.Profiles, cloneRouterProfile(a.profiles.Profiles[1]))
			case "incomplete":
				delete(q.ExpectedProfileTokens, "entry")
			case "extra-node":
				q.ExpectedProfileTokens["unlinked"] = strings.Repeat("a", 64)
			}
			before, profiles := a.state, cloneRouterProfileStore(a.profiles)
			command := &exec.Cmd{}
			a.cmd = command
			raw, err := json.Marshal(q)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			a.externalProfileConnect(response, httptest.NewRequest(http.MethodPost, "/api/external-profile/connect", strings.NewReader(string(raw))))
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), errExternalProfileSelectionChanged.Error()) || a.cmd != command || a.state != before || !reflect.DeepEqual(a.profiles, profiles) {
				t.Fatal("stale HTTP request reached native preparation or changed its predecessor", response.Code, response.Body.String())
			}
			for _, secret := range []string{"owned-exit-secret", "replacement-exit-secret", "replacement-entry-secret", "replacement-selected-secret"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatal("stale source rejection disclosed credentials")
				}
			}
			if _, exists := desktopNodeOwners.Load(a); exists || a.connectionContext != nil {
				t.Fatal("stale HTTP request retained a native or connection owner")
			}
		})
	}
}

func TestExternalProfileExpectedPreparationRechecksBeforeStopAndStage(t *testing.T) {
	for _, path := range []string{"direct", "saved", "external-entry"} {
		for _, fault := range []string{"none", "selection", "exit", "entry", "selected", "legacy"} {
			if path == "direct" && fault == "entry" {
				continue
			}
			t.Run(path+"/"+fault, func(t *testing.T) {
				a, q, captured := expectedExternalFixture(t, path)
				if fault == "legacy" {
					q.ExpectedSelectedNodeID, q.ExpectedProfileTokens = nil, nil
				}
				command, original := &exec.Cmd{}, a.state
				a.cmd = command
				_, finish, err := a.beginConnectionOperation()
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if finish != nil {
						finish()
					}
				}()
				calls := 0
				boundary := errors.New("fixture reached the exact preparation boundary")
				driver := externalConnectRuntime{
					prepare: func(_ *app, profile, entry common.RouterProfile, exit standardExit, direct bool, retained string) (*desktopNodeLaunch, error) {
						calls++
						if profile.ID != captured.ID || profile.External.SOCKS5.Password != "owned-exit-secret" || entry.ID != externalConnectExpectedEntry(q, captured) || direct != (path == "direct") || retained != "" {
							t.Fatal("request adopted the wrong captured source at preparation")
						}
						if fault == "none" || fault == "legacy" {
							return nil, boundary
						}
						a.mu.Lock()
						switch fault {
						case "selection":
							a.profiles.SelectedID = "exit"
						case "exit":
							a.profiles.Profiles[3].External.SOCKS5.Password = "replacement-after-capture"
						case "entry":
							if a.profiles.Profiles[1].External != nil {
								a.profiles.Profiles[1].External.SOCKS5.Password = "replacement-entry-after-capture"
							} else {
								a.profiles.Profiles[1].APIToken = "replacement-entry-after-capture"
							}
						case "selected":
							a.profiles.Profiles[0].APIToken = "replacement-selected-after-capture"
						}
						a.mu.Unlock()
						return &desktopNodeLaunch{}, nil
					},
					stage: func(*app, *desktopNodeLaunch) error {
						t.Fatal("stale preparation reached private staging")
						return errors.New("unexpected stage")
					},
				}
				response := httptest.NewRecorder()
				a.externalProfileConnectOwned(response, q, "", nil, driver)
				finish()
				finish = nil
				want := http.StatusConflict
				if fault == "none" || fault == "legacy" {
					want = http.StatusBadRequest
					if !strings.Contains(response.Body.String(), boundary.Error()) {
						t.Fatal("valid or legacy capture never reached preparation", response.Body.String())
					}
				}
				if calls != 1 || response.Code != want || a.cmd != command || a.state != original {
					t.Fatal("source change stopped or adopted the preceding runtime", calls, response.Code, response.Body.String())
				}
				if _, exists := sessionTrackers.Load(a); exists {
					t.Fatal("rejected capture declared a replacement connection")
				}
			})
		}
	}
}

func TestExternalProfileExpectationCapabilityIsExplicit(t *testing.T) {
	a := &app{}
	response := httptest.NewRecorder()
	a.externalProfileCapabilities(response, httptest.NewRequest(http.MethodGet, "/api/external-profile/capabilities", nil))
	var value map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || value["profile_source_preconditions"] != true {
		t.Fatal("native forms cannot detect the source-bound Connect contract", response.Body.String())
	}
}
