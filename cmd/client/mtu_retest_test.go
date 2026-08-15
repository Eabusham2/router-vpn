package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestSafeMTUScriptPath(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "modes", "mtu-throughput-tuner.py")
	outside := filepath.Join(filepath.Dir(root), "evil.py")
	if !safeMTUScriptPath(root, inside) {
		t.Fatal("valid MTU optimizer path under HOMEVPN_ROOT rejected")
	}
	if safeMTUScriptPath(root, outside) {
		t.Fatal("MTU optimizer path traversal escaped HOMEVPN_ROOT")
	}
}

func TestMTURetestEnvironmentCarriesExactRuntimeContext(t *testing.T) {
	p := common.RouterProfile{ID: "node-1", Endpoint: "203.0.113.10"}
	st := state{RuntimeMode: "shadowsocks", LogicalMode: "privacy", Base: "wg"}
	env := strings.Join(mtuRetestEnvironment("/tmp/router-vpn", p, st, "shadowsocks"), "\n")
	for _, marker := range []string{
		"HOMEVPN_PROFILE_ID=node-1",
		"HOMEVPN_ENDPOINT=203.0.113.10",
		"HOMEVPN_MODE=shadowsocks",
		"HOMEVPN_LOGICAL_MODE=privacy",
		"HOMEVPN_BASE=wg",
		"HOMEVPN_IP_FAMILY=4",
	} {
		if !strings.Contains(env, marker) {
			t.Fatalf("missing Retest path context %q in %s", marker, env)
		}
	}
}

func TestMTURetestRejectsDisconnectedAndNonAutoBeforeLaunching(t *testing.T) {
	root := t.TempDir()
	profiles := filepath.Join(root, "routers.json")
	if err := os.WriteFile(profiles, []byte(`{"schema_version":3,"selected_id":"node","profiles":[{"id":"node","endpoint":"203.0.113.10","mtu_policy":"auto"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: profiles, ScriptsDir: filepath.Join(root, "modes")},
		profiles: common.RouterProfileStore{SelectedID: "node", Profiles: []common.RouterProfile{{ID: "node", Endpoint: "203.0.113.10", MTUPolicy: "auto"}}},
		state: state{Connected: false, Mode: "shadowsocks", RuntimeMode: "shadowsocks", RouterID: "node"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	a.retestMTU(w, req)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "connect the selected Router VPN node first") {
		t.Fatalf("disconnected Retest = %d %q", w.Code, w.Body.String())
	}

	a.state.Connected = true
	a.profiles.Profiles[0].MTUPolicy = "manual"
	w = httptest.NewRecorder()
	a.retestMTU(w, req)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "MTU policy to Auto") {
		t.Fatalf("non-Auto Retest = %d %q", w.Code, w.Body.String())
	}
}

func TestMTURetestCommandDoesNotSilentlyUseOutsideRuntime(t *testing.T) {
	root := t.TempDir()
	_, err := mtuRetestCommand(root, filepath.Join(filepath.Dir(root), "outside"))
	if runtime.GOOS == "windows" {
		// Windows command selection ignores ScriptsDir but must still require the
		// optimizer under HOMEVPN_ROOT/client.
		if err == nil {
			t.Fatal("missing Windows in-root MTU optimizer unexpectedly accepted")
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "unsafe MTU optimizer path") {
		t.Fatalf("outside optimizer path was not rejected: %v", err)
	}
}
