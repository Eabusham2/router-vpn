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
	Modes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"router_vpn_entry_modes"`
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
	a := &app{modes: modes}
	response := httptest.NewRecorder()
	a.externalProfileCapabilities(response, httptest.NewRequest(http.MethodGet, "/api/external-profile/capabilities", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("native capability response: %d", response.Code)
	}
	var catalog desktopEntryModeFormCatalog
	if err := json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Modes) != 19 {
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
	if len(catalog.Modes) != 19 {
		t.Fatalf("unexpected entry mode count %d", len(catalog.Modes))
	}
	control := common.RouterProfile{ID: "exit", NodeKind: "external", MultihopEntryMode: "wg", BaseTunnel: "wg"}
	entry := common.RouterProfile{ID: "entry", NodeKind: "router-vpn", BaseTunnel: "awg"}
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
