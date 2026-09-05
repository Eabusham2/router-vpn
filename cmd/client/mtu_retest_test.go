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
	appRoot := filepath.Join(portable, "App", "RouterVPN")
	data := filepath.Join(portable, "Data")
	scripts := filepath.Join(appRoot, "modes")
	if err := os.MkdirAll(filepath.Join(appRoot, "client"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	got, runner, err := mtuRetestScriptPath(scripts, "windows")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(appRoot, "client", "Optimize-RouterVPN-MTU.ps1")
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
	if err := os.WriteFile(profiles, []byte(`{"schema_version":4,"selected_id":"node","profiles":[{"id":"node","endpoint":"203.0.113.10","mtu_policy":"auto"}]}`), 0o600); err != nil {
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

func newMTUTransactionFixture(t *testing.T) (*app, mtuRetestSnapshot) {
	t.Helper()
	root := t.TempDir()
	profile := common.RouterProfile{ID: "node", NodeKind: "router-vpn", Endpoint: "203.0.113.10", MTUPolicy: "auto", EffectiveMTU: 1420}
	store := common.RouterProfileStore{SchemaVersion: 4, SelectedID: "node", Profiles: []common.RouterProfile{profile}}
	profiles := filepath.Join(root, "routers.json")
	payload, _ := json.Marshal(store)
	if err := os.WriteFile(profiles, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: profiles}, profiles: store, state: state{Connected: true, Phase: "connected", Mode: "shadowsocks", LogicalMode: "privacy", RuntimeMode: "shadowsocks", Base: "wg", RouterID: "node"}}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "session-start", RouterID: "node", ActualMode: "shadowsocks", ActualBase: "wg", Phase: "connected", Connected: true, PathProof: "passed", DNSProof: dnsProofState{Status: "passed"}}}
	sessionTrackers.Store(a, tracker)
	t.Cleanup(func() { sessionTrackers.Delete(a); mtuRetestLocks.Delete(a) })
	snapshot, err := captureMTURetestSnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	return a, snapshot
}

func testMTUMeasurement() mtuMeasurementResult {
	return mtuMeasurementResult{
		OK: true, Interface: "tun0", Family: 4, OriginalMTU: 1420,
		Winner: mtuWinner{MTU: 1380, Working: true, SuccessRatio: 1, Mbps: 900, MedianRTTMs: 8.5},
		PathKey: "0123456789abcdef01234567", NetworkFingerprint: "network", ProfileFingerprint: "generated",
	}
}

func readMTURetestSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("mtu_retest.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestMTURetestTwoPhaseTransactionPersistsOnlyAfterFreshApply(t *testing.T) {
	a, snapshot := newMTUTransactionFixture(t)
	measurement := testMTUMeasurement()
	updated, err := persistMTUMeasurement(a, snapshot, measurement)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EffectiveMTU != 1380 || updated.EffectiveMTUSource != "auto-throughput" || updated.EffectiveMTUPathKey == "" {
		t.Fatalf("fresh MTU result not persisted: %+v", updated)
	}
	source := readMTURetestSource(t)
	apply := strings.Index(source, `runMTURetestAction(ctx, a.cfg.ScriptsDir, "apply", applyEnv)`)
	fresh := strings.Index(source[apply:], `validateMTURetestSnapshot(a, snapshot)`)
	persist := strings.Index(source, `persistMTUMeasurement(a, snapshot, measurement)`)
	if apply < 0 || fresh < 0 || persist < 0 || apply >= persist || apply+fresh >= persist {
		t.Fatal("MTU controller no longer requires live apply plus fresh-session proof before durable adoption")
	}
}

func TestMTURetestRejectsStaleSessionBeforeApplyOrPersistence(t *testing.T) {
	a, snapshot := newMTUTransactionFixture(t)
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	tracker.session.ID = "session-new"
	tracker.mu.Unlock()
	if err := validateMTURetestSnapshot(a, snapshot); err == nil || !strings.Contains(err.Error(), "VPN session changed") {
		t.Fatalf("stale MTU session was accepted: %v", err)
	}
	source := readMTURetestSource(t)
	measurement := strings.Index(source, `measurement, rawResult, err := decodeMTUMeasurement(out)`)
	apply := strings.Index(source, `runMTURetestAction(ctx, a.cfg.ScriptsDir, "apply", applyEnv)`)
	between := ""
	if measurement >= 0 && apply > measurement {
		between = source[measurement:apply]
	}
	if measurement < 0 || apply < 0 || !strings.Contains(between, `validateMTURetestSnapshot(a, snapshot)`) || !strings.Contains(between, `failMTURetestWithLiveRollback`) {
		t.Fatal("MTU controller no longer rejects a stale session with live rollback before apply")
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
	a, snapshot := newMTUTransactionFixture(t)
	root := filepath.Dir(a.cfg.ProfilesFile)
	blocker := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.cfg.ProfilesFile = filepath.Join(blocker, "routers.json")
	if _, err := persistMTUMeasurement(a, snapshot, testMTUMeasurement()); err == nil {
		t.Fatal("MTU persistence failure was accepted")
	}
	a.mu.Lock()
	got := a.profiles.Profiles[0]
	a.mu.Unlock()
	if got.EffectiveMTU != 1420 || got.EffectiveMTUSource != "" || got.EffectiveMTUPathKey != "" {
		t.Fatalf("MTU persistence failure left measured state in RAM: %+v", got)
	}
	source := readMTURetestSource(t)
	persistBranch := `if persistErr != nil {`
	idx := strings.Index(source, persistBranch)
	if idx < 0 || !strings.Contains(source[idx:], `failMTURetestWithLiveRollback`) {
		t.Fatal("MTU persistence failure is no longer wired to exact live-MTU rollback")
	}
}
