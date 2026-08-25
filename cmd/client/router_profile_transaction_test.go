package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestSelectRouterProfileRollsRAMBackWhenPersistenceFails(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-routers.json")
	storePath := filepath.Join(dir, "routers.json")
	if err := os.WriteFile(realPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, storePath); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: storePath},
		profiles: common.RouterProfileStore{
			SelectedID: "home",
			Profiles: []common.RouterProfile{{ID: "home", Name: "Home"}, {ID: "other", Name: "Other"}},
		},
		state: state{RouterID: "home", Phase: "off"},
	}
	req := httptest.NewRequest("POST", "/api/profile/select", strings.NewReader(`{"id":"other"}`))
	w := httptest.NewRecorder()
	a.selectProfile(w, req)
	if w.Code < 500 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if a.profiles.SelectedID != "home" || a.state.RouterID != "home" {
		t.Fatalf("failed persistence changed RAM selection: selected=%q router=%q", a.profiles.SelectedID, a.state.RouterID)
	}
	got, err := os.ReadFile(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{}\n" {
		t.Fatalf("symlink target changed: %q", string(got))
	}
}

func TestSaveRouterProfileRollsRAMBackWhenPersistenceFails(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-routers.json")
	storePath := filepath.Join(dir, "routers.json")
	if err := os.WriteFile(realPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, storePath); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: storePath},
		profiles: common.RouterProfileStore{
			SelectedID: "home",
			Profiles: []common.RouterProfile{{ID: "home", Name: "Original", Endpoint: "192.0.2.1"}},
		},
		state: state{RouterID: "home", Phase: "off"},
	}
	req := httptest.NewRequest("POST", "/api/profile/save", strings.NewReader(`{"id":"home","name":"Changed","endpoint":"203.0.113.9"}`))
	w := httptest.NewRecorder()
	a.saveProfile(w, req)
	if w.Code < 500 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(a.profiles.Profiles) != 1 || a.profiles.Profiles[0].Name != "Original" || a.profiles.Profiles[0].Endpoint != "192.0.2.1" {
		t.Fatalf("failed persistence changed RAM profile: %+v", a.profiles.Profiles)
	}
	if a.profiles.SelectedID != "home" || a.state.RouterID != "home" {
		t.Fatalf("failed persistence changed RAM selection: selected=%q router=%q", a.profiles.SelectedID, a.state.RouterID)
	}
}

func TestRouterProfileMutationGuardRejectsCompetingMutation(t *testing.T) {
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "routers.json")},
		profiles: common.RouterProfileStore{
			SelectedID: "home",
			Profiles: []common.RouterProfile{{ID: "home", Name: "Home"}, {ID: "other", Name: "Other"}},
		},
		state: state{RouterID: "home", Phase: "off"},
	}
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	req := httptest.NewRequest("POST", "/api/profile/select", strings.NewReader(`{"id":"other"}`))
	w := httptest.NewRecorder()
	a.selectProfile(w, req)
	if w.Code != 409 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if a.profiles.SelectedID != "home" || a.state.RouterID != "home" {
		t.Fatal("competing mutation changed selection")
	}
}
