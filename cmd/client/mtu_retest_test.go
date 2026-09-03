package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestSafeMTUScriptPath(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "modes", "mtu-throughput-tuner.py")
	outside := filepath.Join(filepath.Dir(root), "evil.py")
	if !safeMTUScriptPath(root, inside) {
		t.Fatal("valid MTU optimizer path under immutable package root rejected")
	}
	if safeMTUScriptPath(root, outside) {
		t.Fatal("MTU optimizer path traversal escaped immutable package root")
	}
}

func TestMTURetestPackagedScriptPaths(t *testing.T) {
	pkg := t.TempDir()
	scripts := filepath.Join(pkg, "modes")
	for goos, want := range map[string]string{
		"linux":   filepath.Join(pkg, "modes", "mtu-throughput-tuner.py"),
		"darwin":  filepath.Join(pkg, "modes", "mtu-throughput-tuner-platform.py"),
		"windows": filepath.Join(pkg, "client", "Optimize-RouterVPN-MTU.ps1"),
	} {
		got, _, err := mtuRetestScriptPath(scripts, goos)
		if err != nil || got != want {
			t.Fatalf("%s MTU Retest path = %q, %v; want %q", goos, got, err, want)
		}
	}
}

func TestMTURetestPortableWindowsKeepsWritableDataSeparateFromImmutableScript(t *testing.T) {
	portable := t.TempDir()
	app := filepath.Join(portable, "App", "RouterVPN")
	data := filepath.Join(portable, "Data")
	scripts := filepath.Join(app, "modes")
	if err := os.MkdirAll(filepath.Join(app, "client"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	got, runner, err := mtuRetestScriptPath(scripts, "windows")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(app, "client", "Optimize-RouterVPN-MTU.ps1")
	if got != want || runner != "powershell" {
		t.Fatalf("Portable Windows runner = %q %q; want %q powershell", got, runner, want)
	}
	if strings.HasPrefix(got, data+string(filepath.Separator)) {
		t.Fatal("immutable optimizer must not be resolved from writable Portable Data")
	}
}

func TestMTURetestEnvironmentCarriesExactRuntimeContext(t *testing.T) {
	p := common.RouterProfile{ID: "node-1", Endpoint: "203.0.113.10"}
	st := state{RuntimeMode: "shadowsocks", LogicalMode: "privacy", Base: "wg"}
	env := strings.Join(mtuRetestEnvironment("/tmp/router-vpn", p, st, "shadowsocks"), "\n")
	for _, marker := range []string{"HOMEVPN_PROFILE_ID=node-1", "HOMEVPN_ENDPOINT=203.0.113.10", "HOMEVPN_MODE=shadowsocks", "HOMEVPN_LOGICAL_MODE=privacy", "HOMEVPN_BASE=wg", "HOMEVPN_IP_FAMILY=4"} {
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
	a := &app{cfg: common.ClientConfig{ProfilesFile: profiles, ScriptsDir: filepath.Join(root, "modes")}, profiles: common.RouterProfileStore{SelectedID: "node", Profiles: []common.RouterProfile{{ID: "node", Endpoint: "203.0.113.10", MTUPolicy: "auto"}}}, state: state{Connected: false, Mode: "shadowsocks", RuntimeMode: "shadowsocks", RouterID: "node"}}
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

func TestMTURetestScriptPathRejectsUnsafeRoot(t *testing.T) {
	if _, _, err := mtuRetestScriptPath(string(filepath.Separator), "linux"); err == nil {
		t.Fatal("filesystem root must not be accepted as the packaged MTU scripts directory")
	}
}

func TestMTUProfileSnapshotTokenSeparatesIdentityFromMeasurementFields(t *testing.T) {
	base := common.RouterProfile{ID: "node", NodeKind: "router-vpn", Endpoint: "203.0.113.10", RouterAPI: "http://10.77.0.1:8787", NodeProofID: strings.Repeat("a", 64), PathProbeURL: "http://10.77.0.1:8787/health", DAITAHost: "10.77.0.1", DAITAPort: 45999, MTUPolicy: "auto", BaseTunnel: "wg", EffectiveMTU: 1320}
	token := mtuProfileSnapshotToken(base)
	measured := base
	measured.EffectiveMTU = 1380
	measured.EffectiveMTUSource = "auto-throughput"
	measured.EffectiveMTUMbps = 900
	if got := mtuProfileSnapshotToken(measured); got != token {
		t.Fatal("measurement-owned EffectiveMTU fields must not change profile identity token")
	}
	changed := base
	changed.Endpoint = "198.51.100.8"
	if got := mtuProfileSnapshotToken(changed); got == token {
		t.Fatal("endpoint/path identity change must change MTU profile token")
	}
	changed = base
	changed.MTUPolicy = "manual"
	if got := mtuProfileSnapshotToken(changed); got == token {
		t.Fatal("MTU policy change must change MTU profile token")
	}
}

func TestDecodeMTUMeasurementRequiresDeferredSafeWinner(t *testing.T) {
	good := []byte(`{"ok":true,"interface":"tun0","family":4,"original_mtu":1420,"winner":{"mtu":1380,"working":true,"success_ratio":1.0,"mbps":900.0,"median_rtt_ms":8.5},"results":[],"path_key":"0123456789abcdef01234567","network_fingerprint":"net","profile_fingerprint":"prof","adopted":false}`)
	result, _, err := decodeMTUMeasurement(good)
	if err != nil || result.Winner.MTU != 1380 {
		t.Fatalf("valid deferred measurement rejected: %+v %v", result, err)
	}
	for name, bad := range map[string]string{
		"already-adopted":  `{"ok":true,"interface":"tun0","family":4,"original_mtu":1420,"winner":{"mtu":1380,"working":true,"success_ratio":1.0},"path_key":"0123456789abcdef01234567","adopted":true}`,
		"failed-winner":    `{"ok":true,"interface":"tun0","family":4,"original_mtu":1420,"winner":{"mtu":1380,"working":false,"success_ratio":1.0},"path_key":"0123456789abcdef01234567","adopted":false}`,
		"unsafe-interface": `{"ok":true,"interface":"tun0\nboom","family":4,"original_mtu":1420,"winner":{"mtu":1380,"working":true,"success_ratio":1.0},"path_key":"0123456789abcdef01234567","adopted":false}`,
	} {
		if _, _, err := decodeMTUMeasurement([]byte(bad)); err == nil {
			t.Fatalf("%s invalid result accepted", name)
		}
	}
}

func installFakeMTURetestRuntime(t *testing.T) (*app, string) {
	t.Helper()
	root := t.TempDir()
	scripts := filepath.Join(root, "modes")
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := `#!/usr/bin/env python3
import json, os, pathlib, sys, time
root=pathlib.Path(os.environ["HOMEVPN_ROOT"])
action=sys.argv[1]
(root/("fake-"+action)).write_text("1")
if action=="measure":
    delay=float(os.environ.get("HOMEVPN_MTU_FAKE_DELAY","0"))
    if delay: time.sleep(delay)
    print(json.dumps({"ok":True,"interface":"tun0","family":4,"original_mtu":1420,"winner":{"mtu":1380,"working":True,"success_ratio":1.0,"mbps":900.0,"median_rtt_ms":8.5},"results":[],"path_key":"0123456789abcdef01234567","network_fingerprint":"network","profile_fingerprint":"generated","adopted":False}))
elif action in ("apply","restore"):
    print(json.dumps({"ok":True,"interface":"tun0","family":4,"applied_mtu":int(os.environ["HOMEVPN_MTU_APPLY_VALUE"]),"rollback":action=="restore"}))
else:
    raise SystemExit(2)
`
	for _, name := range []string{"mtu-throughput-tuner.py", "mtu-throughput-tuner-platform.py"} {
		if err := os.WriteFile(filepath.Join(scripts, name), []byte(fake), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	profile := common.RouterProfile{ID: "node", NodeKind: "router-vpn", Endpoint: "203.0.113.10", MTUPolicy: "auto", EffectiveMTU: 1420}
	store := common.RouterProfileStore{SchemaVersion: 4, SelectedID: "node", Profiles: []common.RouterProfile{profile}}
	payload, _ := json.Marshal(store)
	profiles := filepath.Join(root, "routers.json")
	if err := os.WriteFile(profiles, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: profiles, ScriptsDir: scripts}, profiles: store, state: state{Connected: true, Phase: "connected", Mode: "shadowsocks", LogicalMode: "privacy", RuntimeMode: "shadowsocks", Base: "wg", RouterID: "node"}}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "session-start", RouterID: "node", ActualMode: "shadowsocks", ActualBase: "wg", Phase: "connected", Connected: true, PathProof: "passed", DNSProof: dnsProofState{Status: "passed"}}}
	sessionTrackers.Store(a, tracker)
	t.Cleanup(func() { sessionTrackers.Delete(a); mtuRetestLocks.Delete(a) })
	return a, root
}

func TestMTURetestTwoPhaseTransactionPersistsOnlyAfterFreshApply(t *testing.T) {
	a, root := installFakeMTURetestRuntime(t)
	t.Setenv("HOMEVPN_ROOT", root)
	req := httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	a.retestMTU(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Retest = %d %q", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "fake-measure")); err != nil {
		t.Fatal("measure phase did not run")
	}
	if _, err := os.Stat(filepath.Join(root, "fake-apply")); err != nil {
		t.Fatal("apply phase did not run")
	}
	if _, err := os.Stat(filepath.Join(root, "fake-restore")); !os.IsNotExist(err) {
		t.Fatal("successful transaction unexpectedly rolled back")
	}
	a.mu.Lock()
	got := a.profiles.Profiles[0]
	a.mu.Unlock()
	if got.EffectiveMTU != 1380 || got.EffectiveMTUSource != "auto-throughput" || got.EffectiveMTUPathKey == "" {
		t.Fatalf("fresh MTU result not persisted: %+v", got)
	}
}

func TestMTURetestRejectsStaleSessionBeforeApplyOrPersistence(t *testing.T) {
	a, root := installFakeMTURetestRuntime(t)
	t.Setenv("HOMEVPN_ROOT", root)
	t.Setenv("HOMEVPN_MTU_FAKE_DELAY", "0.25")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		a.retestMTU(w, req)
		done <- w
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "fake-measure")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("measure phase did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	tracker.session.ID = "session-new"
	tracker.mu.Unlock()
	w := <-done
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "VPN session changed") {
		t.Fatalf("stale Retest = %d %q", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "fake-apply")); !os.IsNotExist(err) {
		t.Fatal("stale measurement reached apply phase")
	}
	a.mu.Lock()
	got := a.profiles.Profiles[0].EffectiveMTU
	a.mu.Unlock()
	if got != 1420 {
		t.Fatalf("stale measurement persisted MTU %d", got)
	}
}

func TestMTURetestPackagedOptimizersKeepMeasurementAndAdoptionSeparate(t *testing.T) {
	unixPath := filepath.Join("..", "..", "modes", "mtu-throughput-tuner.py")
	unixData, err := os.ReadFile(unixPath)
	if err != nil {
		t.Fatal(err)
	}
	unix := string(unixData)
	for _, marker := range []string{
		"def optimize(*, defer_adopt: bool = False)",
		"if defer_adopt:",
		"set_interface_mtu(alias, family, original)",
		"def apply_measured_result(*, rollback: bool = False)",
		`sys.argv[1] not in {"optimize", "measure", "apply", "restore"}`,
		`current["path_key"] != expected`,
	} {
		if !strings.Contains(unix, marker) {
			t.Fatalf("Unix MTU transaction contract missing %q", marker)
		}
	}
	windowsPath := filepath.Join("..", "..", "client", "Optimize-RouterVPN-MTU.ps1")
	windowsData, err := os.ReadFile(windowsPath)
	if err != nil {
		t.Fatal(err)
	}
	windows := string(windowsData)
	for _, marker := range []string{
		"[ValidateSet('optimize','measure','apply','restore','self-test')]",
		"function Invoke-ApplyMeasured([bool]$Rollback)",
		"if($Action-eq'measure'){Set-Mtu $alias $family $original;$adopted=$false}",
		"HOMEVPN_MTU_EXPECTED_PATH_KEY",
		"Active MTU path fingerprint changed before adoption.",
	} {
		if !strings.Contains(windows, marker) {
			t.Fatalf("Windows MTU transaction contract missing %q", marker)
		}
	}
}

func TestMTURetestPersistenceFailureRollsBackLiveAndInMemoryResult(t *testing.T) {
	a, root := installFakeMTURetestRuntime(t)
	t.Setenv("HOMEVPN_ROOT", root)
	blocker := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.cfg.ProfilesFile = filepath.Join(blocker, "routers.json")

	req := httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	a.retestMTU(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("persistence failure status=%d body=%q", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "fake-restore")); err != nil {
		t.Fatal("MTU persistence failure did not roll back the live interface")
	}
	a.mu.Lock()
	got := a.profiles.Profiles[0]
	a.mu.Unlock()
	if got.EffectiveMTU != 1420 || got.EffectiveMTUSource != "" || got.EffectiveMTUPathKey != "" {
		t.Fatalf("MTU persistence failure left measured state in RAM: %+v", got)
	}
}
