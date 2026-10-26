package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

type desktopEntryModeFormCatalog struct {
	SourcePreconditions bool `json:"profile_source_preconditions"`
	Modes               []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"router_vpn_entry_modes"`
}

// Both the catalog-producing process and the payload consumer use these exact
// synthetic private sources. No random certificate, key, directory, or runtime
// capability is included in the source-token projection.
func desktopExternalEntryModeSourceFixture(t *testing.T) (*app, common.RouterProfile, common.RouterProfile) {
	t.Helper()
	control := externalConnectionTestNode(t, "shadowsocks")
	control.ID, control.Name = "exit", "Captured external exit"
	control.MultihopEnabled = true
	control.MultihopEntryID, control.MultihopExitID = "entry", control.ID
	control.MultihopEntryMode, control.MultihopExecution = "wg", "local"
	control.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://proof.example.test/response", ServerName: "proof.example.test"}
	entry, _ := desktopNodeFixture(t, "198.51.100.11")
	entry.ID, entry.Name, entry.BaseTunnel = "entry", "Captured Router entry", "awg"
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal(err)
	}
	a := &app{profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion, SelectedID: control.ID, Profiles: []common.RouterProfile{control, entry}}}
	return a, cloneRouterProfile(control), cloneRouterProfile(entry)
}

func desktopExternalEntryModePublicSources(t *testing.T, a *app) []byte {
	t.Helper()
	response := httptest.NewRecorder()
	a.listPublicNodes(response, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
	if response.Code != http.StatusOK || response.Header().Get("cache-control") != "no-store" {
		t.Fatal("source catalog did not use the public node response", response.Code)
	}
	var catalog publicProfileStore
	if err := json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.SelectedID != "exit" || len(catalog.Profiles) != 2 || catalog.Profiles[0].ID != "exit" || catalog.Profiles[1].ID != "entry" || catalog.Profiles[0].External == nil || !catalog.Profiles[0].External.HasResponseProbe {
		t.Fatal("form source topology or actual response-probe capability changed")
	}
	for i, public := range catalog.Profiles {
		if public.ProfileToken != publicProfileToken(a.profiles.Profiles[i]) || !validExternalProfileExpectationToken(public.ProfileToken) {
			t.Fatal("public node revision does not represent its exact private source")
		}
	}
	for _, secret := range []string{"ss-secret", "private-token", "api_token", "password", "private_key"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("public source fixture contains credentials", secret)
		}
	}
	return response.Body.Bytes()
}

// The native UI fixtures consume the shipping capability response, including
// catalog names and the shared compiler's supported mode set.
func TestDesktopExternalEntryModeFormCatalog(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_EXTERNAL_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("native callback payload directory is supplied by the platform form runner")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var modes []common.Mode
	if err := json.Unmarshal(data, &modes); err != nil {
		t.Fatal(err)
	}
	a, _, _ := desktopExternalEntryModeSourceFixture(t)
	a.modes = modes
	response := httptest.NewRecorder()
	a.externalProfileCapabilities(response, httptest.NewRequest(http.MethodGet, "/api/external-profile/capabilities", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("native capability response: %d", response.Code)
	}
	var catalog desktopEntryModeFormCatalog
	if err := json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Modes) != 19 || !catalog.SourcePreconditions {
		t.Fatalf("expected the 19 supported raw Router entry modes, got %d", len(catalog.Modes))
	}
	seen := map[string]bool{}
	for _, mode := range catalog.Modes {
		if !mobilemultihop.NodeProfileMode(mode.ID) || seen[mode.ID] || mode.Name == "" {
			t.Fatalf("invalid native entry capability: %+v", mode)
		}
		seen[mode.ID] = true
	}
	if err := os.WriteFile(filepath.Join(directory, "entry-mode-catalog.json"), response.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "external-source-catalog.json"), desktopExternalEntryModePublicSources(t, a), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopExternalEntryModeFormPayload(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_EXTERNAL_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("native callback payload directory is supplied by the platform form runner")
	}
	data, err := os.ReadFile(filepath.Join(directory, "entry-mode-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog desktopEntryModeFormCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Modes) != 19 || !catalog.SourcePreconditions {
		t.Fatalf("unexpected entry mode count %d", len(catalog.Modes))
	}
	a, control, entry := desktopExternalEntryModeSourceFixture(t)
	sourceData, err := os.ReadFile(filepath.Join(directory, "external-source-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sourceCatalog publicProfileStore
	if err := json.Unmarshal(sourceData, &sourceCatalog); err != nil {
		t.Fatal(err)
	}
	if sourceCatalog.SelectedID != control.ID || len(sourceCatalog.Profiles) != 2 {
		t.Fatal("native form consumed an unrelated source catalog")
	}
	for _, source := range sourceCatalog.Profiles {
		private, exists := a.profileByIDLocked(source.ID)
		if !exists || source.ProfileToken != publicProfileToken(private) {
			t.Fatal("separate form processes did not retain the exact private source identity")
		}
	}
	for _, mode := range catalog.Modes {
		for _, execution := range []string{"local", "server", "auto"} {
			t.Run(mode.ID+"/"+execution, func(t *testing.T) {
				payload, err := os.ReadFile(filepath.Join(directory, "entry-mode-"+mode.ID+"-"+execution+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var request externalProfileConnectRequest
				decoder := json.NewDecoder(strings.NewReader(string(payload)))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&request); err != nil {
					t.Fatal(err)
				}
				if request.ProfileID != control.ID || request.EntryID != entry.ID || request.EntryMode != mode.ID || request.Execution != execution || request.Base != "" || (request.Direct != nil && *request.Direct) {
					t.Fatalf("native form changed the captured path: %+v", request)
				}
				if request.ExpectedSelectedNodeID == nil || *request.ExpectedSelectedNodeID != control.ID || len(request.ExpectedProfileTokens) != 2 {
					t.Fatal("native form omitted its captured source revisions")
				}
				if err := a.validateExternalProfileExpectedProfiles(request, control); err != nil {
					t.Fatal("actual emitted form cannot pass the shipping source expectation guard", err)
				}
				for _, relink := range []string{control.ID, entry.ID} {
					replaced, captured, _ := desktopExternalEntryModeSourceFixture(t)
					for i := range replaced.profiles.Profiles {
						if replaced.profiles.Profiles[i].ID == relink {
							if relink == control.ID {
								replaced.profiles.Profiles[i].External.Shadowsocks.Password = "replacement-exit-credential"
							} else {
								replaced.profiles.Profiles[i].APIToken = "replacement-entry-credential"
							}
						}
					}
					if replaced.validateExternalProfileExpectedProfiles(request, captured) == nil {
						t.Fatal("native form adopted a same-ID credential replacement", relink)
					}
				}
				resolved, err := desktopExternalEntryMode(control, entry, request.EntryMode, request.Base)
				if err != nil || resolved != mode.ID {
					t.Fatalf("native mode substituted during controller capture: %q, %v", resolved, err)
				}
			})
		}
	}
	for _, invalid := range []string{"all", "auto", "smart-auto", "custom", "unknown", " wg", "wg "} {
		if _, err := desktopExternalEntryMode(control, entry, invalid, ""); err == nil {
			t.Fatalf("controller accepted an uncompiled entry selection %q", invalid)
		}
	}
}
