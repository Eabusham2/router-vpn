package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func captureRouterSettings(t *testing.T, a *app) profileSettingsResponse {
	t.Helper()
	w := httptest.NewRecorder()
	a.profileSettings(w, httptest.NewRequest(http.MethodGet, "/api/profile/settings", nil))
	var capture profileSettingsResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &capture) != nil || len(capture.ProfileToken) != 64 {
		t.Fatalf("settings capture: %d %s", w.Code, w.Body.String())
	}
	return capture
}

func postRouterSettings(t *testing.T, a *app, fields map[string]any, mutate func()) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.profileSettings(w, httptest.NewRequest(http.MethodPost, "/api/profile/settings", &startupSettingsMutationReader{Reader: bytes.NewReader(body), mutate: mutate}))
	return w
}

func TestRouterSettingsCapturedBeforeNamedProfileLoad(t *testing.T) {
	a := setupProfileTestApp(t)
	if w := postRouterSettings(t, a, map[string]any{"home_lan_access": true}, nil); w.Code != http.StatusOK {
		t.Fatalf("set initial policy: %s", w.Body.String())
	}
	w := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Home LAN", "mode": "smart-auto"})
	var saved struct {
		Profile struct{ ID string }
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Profile.ID == "" {
		t.Fatalf("save setup: %s", w.Body.String())
	}
	if w := postRouterSettings(t, a, map[string]any{"home_lan_access": false}, nil); w.Code != http.StatusOK {
		t.Fatalf("edit policy: %s", w.Body.String())
	}
	form := captureRouterSettings(t, a)
	w = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.Profile.ID})
	if w.Code != http.StatusOK || !a.profiles.Profiles[0].HomeLANAccess || form.HomeLANAccess {
		t.Fatalf("load saved LAN preference: %s", w.Body.String())
	}
	disk, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	edit := map[string]any{"home_lan_access": false, "profile_id": form.ProfileID, "profile_token": form.ProfileToken}
	w = postRouterSettings(t, a, edit, nil)
	if w.Code != http.StatusConflict || !a.profiles.Profiles[0].HomeLANAccess {
		t.Fatalf("old editor overwrote loaded profile: %d", w.Code)
	}
	after, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil || !bytes.Equal(disk, after) {
		t.Fatalf("stale edit changed persistent node store: %v", err)
	}
	fresh := captureRouterSettings(t, a)
	edit["profile_token"] = fresh.ProfileToken
	w = postRouterSettings(t, a, edit, nil)
	if w.Code != http.StatusOK || a.profiles.Profiles[0].HomeLANAccess {
		t.Fatalf("fresh edit: %d %s", w.Code, w.Body.String())
	}
}

func TestRouterSettingsPreserveConcurrentReadbackAndSelection(t *testing.T) {
	for _, change := range []string{"readback", "source", "selection", "closing"} {
		t.Run(change, func(t *testing.T) {
			a := setupProfileTestApp(t)
			form := captureRouterSettings(t, a)
			fields := map[string]any{"profile_id": form.ProfileID, "profile_token": form.ProfileToken, "home_lan_access": true}
			w := postRouterSettings(t, a, fields, func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				switch change {
				case "readback":
					a.profiles.Profiles[0].EffectiveMTU = 1310
					a.profiles.Profiles[0].FastestDNSLatencyMs = 4.7
				case "source":
					a.profiles.Profiles[0].APIToken = "relinked-source"
				case "selection":
					a.profiles.SelectedID = "entry"
				case "closing":
					a.closing = true
				}
			})
			p := a.profiles.Profiles[0]
			if change == "readback" {
				if w.Code != http.StatusOK || !p.HomeLANAccess || p.EffectiveMTU != 1310 || p.FastestDNSLatencyMs != 4.7 || p.APIToken != "HOME-SECRET" {
					t.Fatalf("fresh preference save dropped readback or private fields: %d %s", w.Code, w.Body.String())
				}
			} else if w.Code != http.StatusConflict || p.HomeLANAccess || a.profiles.Profiles[1].HomeLANAccess {
				t.Fatalf("stale form saved after %s: %d", change, w.Code)
			}
		})
	}
}
