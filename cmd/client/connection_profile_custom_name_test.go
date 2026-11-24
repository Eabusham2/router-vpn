package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestConnectionProfileCustomNameSurvivesSetupLifecycle(t *testing.T) {
	for label, name := range map[string]string{
		"case": "Gaming", "space": "My Preset", "unicode": "東京 😀",
		"full-length-unicode": strings.Repeat("😀", 64), "new": "new",
		"legacy-colon": "Gaming:private", "desktop-punctuation": "[Privacy]",
	} {
		t.Run(label, func(t *testing.T) {
			a := setupProfileTestApp(t)
			mode := "custom:" + name
			body := map[string]any{"name": "Saved setup", "mode": mode, "custom_layers": []string{"wireguard"}}
			var result struct {
				Profile connectionProfileRecord `json:"profile"`
			}
			for _, operation := range []string{"save", "update"} {
				response := postSetup(t, a, "/api/connection-profile/setup/"+operation, body)
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
					t.Fatalf("%s rejected the builder's CUSTOM name: %d %s", operation, response.Code, response.Body.String())
				}
				if result.Profile.Mode != mode || result.Profile.Prefs == nil {
					t.Fatalf("%s changed the selected CUSTOM name: %q", operation, result.Profile.Mode)
				}
				stored, err := loadConnectionProfileStore(a)
				if err != nil || len(stored.Profiles) != 1 || stored.Profiles[0].Mode != mode {
					t.Fatalf("%s lost the persisted CUSTOM identity: %v %#v", operation, err, stored)
				}
				body["id"] = result.Profile.ID
				body["custom_layers"] = []string{"reality", "wireguard"}
			}
			a.mu.Lock()
			a.profiles.SelectedID = "entry"
			a.state.RouterID = "entry"
			a.mu.Unlock()
			response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": result.Profile.ID})
			var loaded struct {
				Mode           string   `json:"mode"`
				CustomLayers   []string `json:"custom_layers"`
				SelectedNodeID string   `json:"selected_node_id"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &loaded) != nil {
				t.Fatalf("load: %d %s", response.Code, response.Body.String())
			}
			if loaded.Mode != mode || strings.Join(loaded.CustomLayers, ",") != "reality,wireguard" || loaded.SelectedNodeID != "home" || a.profiles.SelectedID != "home" {
				t.Fatalf("Load did not restore the exact CUSTOM name, layers and node: %#v", loaded)
			}
		})
	}
}

func TestConnectionProfileCustomNameValidation(t *testing.T) {
	for _, value := range []string{"custom:", "custom:   ", "custom:" + strings.Repeat("😀", 65), "custom:bad\nname", "custom:bad\u0085name", "custom:\xff"} {
		if _, err := normalizeConnectionProfileMode(value); err == nil {
			t.Fatalf("invalid CUSTOM name accepted: %q", value)
		}
	}
	if got, err := normalizeConnectionProfileMode(" CUSTOM:  Gaming "); err != nil || got != "custom:Gaming" {
		t.Fatalf("CUSTOM prefix normalization changed the name: %q %v", got, err)
	}
}
