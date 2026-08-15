package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestSafeMTUScriptPath(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "modes", "mtu-throughput-tuner.py")
	outside := filepath.Join(filepath.Dir(root), "evil.py")
	if !safeMTUScriptPath(root, inside) { t.Fatal("valid MTU optimizer path under immutable package root rejected") }
	if safeMTUScriptPath(root, outside) { t.Fatal("MTU optimizer path traversal escaped immutable package root") }
}

func TestMTURetestPackagedScriptPaths(t *testing.T) {
	pkg := t.TempDir()
	scripts := filepath.Join(pkg, "modes")
	for goos, want := range map[string]string{
		"linux": filepath.Join(pkg, "modes", "mtu-throughput-tuner.py"),
		"darwin": filepath.Join(pkg, "modes", "mtu-throughput-tuner-platform.py"),
		"windows": filepath.Join(pkg, "client", "Optimize-RouterVPN-MTU.ps1"),
	} {
		got, _, err := mtuRetestScriptPath(scripts, goos)
		if err != nil || got != want { t.Fatalf("%s MTU Retest path = %q, %v; want %q", goos, got, err, want) }
	}
}

func TestMTURetestPortableWindowsKeepsWritableDataSeparateFromImmutableScript(t *testing.T) {
	portable := t.TempDir()
	app := filepath.Join(portable, "App", "RouterVPN")
	data := filepath.Join(portable, "Data")
	scripts := filepath.Join(app, "modes")
	if err := os.MkdirAll(filepath.Join(app, "client"), 0o700); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(data, 0o700); err != nil { t.Fatal(err) }
	got, runner, err := mtuRetestScriptPath(scripts, "windows")
	if err != nil { t.Fatal(err) }
	want := filepath.Join(app, "client", "Optimize-RouterVPN-MTU.ps1")
	if got != want || runner != "powershell" { t.Fatalf("Portable Windows runner = %q %q; want %q powershell", got, runner, want) }
	if strings.HasPrefix(got, data+string(filepath.Separator)) { t.Fatal("immutable optimizer must not be resolved from writable Portable Data") }
}

func TestMTURetestEnvironmentCarriesExactRuntimeContext(t *testing.T) {
	p := common.RouterProfile{ID: "node-1", Endpoint: "203.0.113.10"}
	st := state{RuntimeMode: "shadowsocks", LogicalMode: "privacy", Base: "wg"}
	env := strings.Join(mtuRetestEnvironment("/tmp/router-vpn", p, st, "shadowsocks"), "\n")
	for _, marker := range []string{"HOMEVPN_PROFILE_ID=node-1", "HOMEVPN_ENDPOINT=203.0.113.10", "HOMEVPN_MODE=shadowsocks", "HOMEVPN_LOGICAL_MODE=privacy", "HOMEVPN_BASE=wg", "HOMEVPN_IP_FAMILY=4"} {
		if !strings.Contains(env, marker) { t.Fatalf("missing Retest path context %q in %s", marker, env) }
	}
}

func TestMTURetestRejectsDisconnectedAndNonAutoBeforeLaunching(t *testing.T) {
	root := t.TempDir(); profiles := filepath.Join(root, "routers.json")
	if err := os.WriteFile(profiles, []byte(`{"schema_version":3,"selected_id":"node","profiles":[{"id":"node","endpoint":"203.0.113.10","mtu_policy":"auto"}]}`), 0o600); err != nil { t.Fatal(err) }
	a := &app{cfg: common.ClientConfig{ProfilesFile: profiles, ScriptsDir: filepath.Join(root, "modes")}, profiles: common.RouterProfileStore{SelectedID: "node", Profiles: []common.RouterProfile{{ID: "node", Endpoint: "203.0.113.10", MTUPolicy: "auto"}}}, state: state{Connected: false, Mode: "shadowsocks", RuntimeMode: "shadowsocks", RouterID: "node"}}
	req := httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(`{}`)); w := httptest.NewRecorder(); a.retestMTU(w, req)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "connect the selected Router VPN node first") { t.Fatalf("disconnected Retest = %d %q", w.Code, w.Body.String()) }
	a.state.Connected = true; a.profiles.Profiles[0].MTUPolicy = "manual"; w = httptest.NewRecorder(); a.retestMTU(w, req)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "MTU policy to Auto") { t.Fatalf("non-Auto Retest = %d %q", w.Code, w.Body.String()) }
}

func TestMTURetestScriptPathRejectsUnsafeRoot(t *testing.T) {
	if _, _, err := mtuRetestScriptPath(string(filepath.Separator), "linux"); err == nil { t.Fatal("filesystem root must not be accepted as the packaged MTU scripts directory") }
}
