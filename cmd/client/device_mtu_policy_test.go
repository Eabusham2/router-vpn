package main

import (
	"bytes"
	"context"
	"encoding/json"
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

func deviceMTUTestApp(t *testing.T) *app {
	t.Helper()
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "profiles.json")},
		profiles: common.RouterProfileStore{SelectedID: "first", Profiles: []common.RouterProfile{
			{ID: "first", MTUPolicy: "auto", EffectiveMTU: 1300},
			{ID: "second", MTUPolicy: "manual", ManualMTU: 1380},
		}}}
	raw, err := json.Marshal(a.profiles)
	if err != nil || os.WriteFile(a.cfg.ProfilesFile, raw, 0600) != nil {
		t.Fatal("could not create original private node store", err)
	}
	return a
}

func deviceMTUTestPost(t *testing.T, a *app, token string, value int) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"token": token, "fixed_mtu": value})
	w := httptest.NewRecorder()
	a.deviceMTUSettings(w, httptest.NewRequest(http.MethodPost, "/api/device/mtu", bytes.NewReader(body)))
	return w
}

func TestDeviceMTUPreferenceIsSeparateAndDetectsAwayBack(t *testing.T) {
	a := deviceMTUTestApp(t)
	before := cloneRouterProfileStore(a.profiles)
	beforeBytes, _ := os.ReadFile(a.cfg.ProfilesFile)
	initial, err := captureDeviceMTUPolicy(a)
	if err != nil || initial.policy.FixedMTU != 0 || initial.policy.Revision != "" {
		t.Fatal("default must preserve each configuration", err)
	}
	startup, cancel := context.WithCancel(context.Background())
	defer cancel()
	startupPolicyCancels.Store(a, context.CancelFunc(cancel))
	for _, value := range []int{1320, 0, 1320} {
		capture, err := captureDeviceMTUPolicy(a)
		if err != nil {
			t.Fatal(err)
		}
		reply := deviceMTUTestPost(t, a, capture.token, value)
		if reply.Code != 200 {
			t.Fatal(reply.Code, reply.Body.String())
		}
		after, err := captureDeviceMTUPolicy(a)
		if err != nil || after.policy.FixedMTU != value || after.token == capture.token ||
			!deviceMTURevisionPattern.MatchString(after.policy.Revision) || capture.current() == nil {
			t.Fatal("write lost the exact new policy revision", value, err)
		}
	}
	afterBytes, _ := os.ReadFile(a.cfg.ProfilesFile)
	if !reflect.DeepEqual(before, a.profiles) || !bytes.Equal(beforeBytes, afterBytes) || a.profileCatalogEpoch != 3 || startup.Err() != context.Canceled {
		t.Fatal("device setting changed a node, lost catalog invalidation, or retained old startup")
	}
	if reply := deviceMTUTestPost(t, a, initial.token, 1400); reply.Code != http.StatusConflict {
		t.Fatal("stale Settings form was accepted", reply.Code)
	}
	info, err := os.Stat(deviceMTUPolicyPath(a))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("device policy is not private", err)
	}
}

func TestDeviceMTURejectsBusyCancelledAndMalformedEdits(t *testing.T) {
	a := deviceMTUTestApp(t)
	capture, _ := captureDeviceMTUPolicy(a)
	for _, phase := range []string{"connected", "requested", "candidate:running", "stopping"} {
		a.state.Phase = phase
		if w := deviceMTUTestPost(t, a, capture.token, 1320); w.Code != 409 {
			t.Fatal(phase, w.Code)
		}
	}
	a.state.Phase = "off"
	for _, body := range []string{
		`null`, `{}`, `{"token":"x","fixed_mtu":null}`, `{"token":"x","fixed_mtu":1279}`,
		`{"token":"x","fixed_mtu":9001}`, `{"token":"x","fixed_mtu":1320.5}`,
		`{"token":"x","fixed_mtu":1320,"fixed_mtu":0}`, `{"token":"x","fixed_mtu":1320,"profile_id":"first"}`,
		`{"token":"x","fixed_mtu":1320} {}`, strings.Repeat(" ", 4097),
	} {
		w := httptest.NewRecorder()
		a.deviceMTUSettings(w, httptest.NewRequest(http.MethodPost, "/api/device/mtu", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal("malformed edit was not rejected", body, w.Code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	a.deviceMTUSettings(w, httptest.NewRequest(http.MethodPost, "/api/device/mtu", strings.NewReader(`{"token":"`+capture.token+`","fixed_mtu":1320}`)).WithContext(ctx))
	if w.Code < 400 {
		t.Fatal("canceled edit was accepted")
	}
	if _, err := os.Lstat(deviceMTUPolicyPath(a)); !os.IsNotExist(err) {
		t.Fatal("rejected edit wrote a preference", err)
	}
}

func TestDeviceMTULoadRejectsChangedPrivateSource(t *testing.T) {
	a := deviceMTUTestApp(t)
	capture, _ := captureDeviceMTUPolicy(a)
	if w := deviceMTUTestPost(t, a, capture.token, 1320); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	valid, _ := os.ReadFile(deviceMTUPolicyPath(a))
	for _, body := range []string{
		`{"schema":1,"revision":"` + strings.Repeat("a", 32) + `"}`,
		`{"schema":1,"revision":"` + strings.Repeat("a", 32) + `","fixed_mtu":null}`,
		`{"schema":2,"revision":"` + strings.Repeat("a", 32) + `","fixed_mtu":1320}`,
		`{"schema":1,"revision":"bad","fixed_mtu":1320}`,
		`{"schema":1,"revision":"` + strings.Repeat("a", 32) + `","fixed_mtu":1320,"fixed_mtu":0}`,
	} {
		if err := os.WriteFile(deviceMTUPolicyPath(a), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := captureDeviceMTUPolicy(a); err == nil {
			t.Fatal("invalid saved source accepted", body)
		}
	}
	if err := os.WriteFile(deviceMTUPolicyPath(a), valid, 0600); err != nil {
		t.Fatal(err)
	}
	current, err := captureDeviceMTUPolicy(a)
	if err != nil {
		t.Fatal(err)
	}
	changed := current.policy
	changed.FixedMTU = 1340
	raw, _ := json.Marshal(changed)
	if err := os.WriteFile(deviceMTUPolicyPath(a), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if current.current() == nil {
		t.Fatal("captured connection accepted changed device setting")
	}
}

func TestDeviceMTUConnectCapturesRevisionAndCannotOptimizeFixedPolicy(t *testing.T) {
	privateOperationRoot(t)
	a := deviceMTUTestApp(t)
	original, _ := captureDeviceMTUPolicy(a)
	if w := deviceMTUTestPost(t, a, original.token, 1320); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	ctx, finish, err := a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	captured := deviceMTUForContext(ctx)
	if captured == nil || captured != a.deviceMTU || captured.policy.FixedMTU != 1320 || captured.current() != nil || a.checkCapturedConnectionOperation(ctx) != nil {
		t.Fatal("Connect lost the original device preference")
	}
	if a.deviceMTUAllowsOptimization() {
		t.Fatal("fixed device policy allowed Auto")
	}
	w := httptest.NewRecorder()
	a.retestMTU(w, httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(`{}`)))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "Fixed MTU for all") {
		t.Fatal(w.Code, w.Body.String())
	}
	changed := captured.policy
	changed.Revision = strings.Repeat("b", 32)
	raw, _ := json.Marshal(changed)
	if err := os.WriteFile(deviceMTUPolicyPath(a), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if a.checkCapturedConnectionOperation(ctx) == nil || a.deviceMTUAllowsOptimization() {
		t.Fatal("changed device revision was adopted by an older connection")
	}
}

func TestDeviceMTUProjectionKeepsOriginalGraphAndPeerEnvelope(t *testing.T) {
	a := deviceMTUTestApp(t)
	initial, _ := captureDeviceMTUPolicy(a)
	if reply := deviceMTUTestPost(t, a, initial.token, 1320); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	capture, _ := captureDeviceMTUPolicy(a)
	ctx := context.WithValue(context.Background(), deviceMTUContextKey{}, capture)
	graph := map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "device", "auto_route": true, "strict_route": true, "mtu": 1380}},
		"endpoints": []any{map[string]any{"type": "wireguard", "tag": "packet", "mtu": 1408, "private_key": "original-private", "peers": []any{map[string]any{"public_key": "original-peer", "address": "203.0.113.17"}}}},
		"route":     map[string]any{"final": "packet"},
	}
	before, _ := json.Marshal(graph)
	projected, err := projectCapturedDeviceMTU(ctx, graph, common.RouterProfile{})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(graph)
	raw, _ := json.Marshal(projected)
	if !bytes.Equal(before, after) || capture.requireConfig(raw) != nil {
		t.Fatal("original graph changed or fixed projection was not retained")
	}
	if capture.requireConfig(before) == nil {
		t.Fatal("unmodified TUN was accepted as the requested device MTU")
	}
	projected["inbounds"].([]any)[0].(map[string]any)["mtu"] = 1380
	restored, _ := json.Marshal(projected)
	if !bytes.Equal(before, restored) {
		t.Fatal("device choice changed independent peer, route, or credentials")
	}
	for _, profile := range []common.RouterProfile{{SocksEnabled: true}, {JumboTUN: true}} {
		if _, err := projectCapturedDeviceMTU(ctx, graph, profile); err == nil {
			t.Fatal("conflicting interface policy was accepted")
		}
	}
	if reply := deviceMTUTestPost(t, a, capture.token, 1409); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	if _, err := projectCapturedDeviceMTU(ctx, graph, common.RouterProfile{}); err == nil {
		t.Fatal("obsolete policy revision was adopted")
	}
	current, _ := captureDeviceMTUPolicy(a)
	ctx = context.WithValue(context.Background(), deviceMTUContextKey{}, current)
	if _, err := projectCapturedDeviceMTU(ctx, graph, common.RouterProfile{}); err == nil {
		t.Fatal("fixed device MTU crossed an independent packet peer ceiling")
	}
}

func TestDeviceMTULegacyEnvironmentRequiresOriginalCapture(t *testing.T) {
	a := deviceMTUTestApp(t)
	initial, _ := captureDeviceMTUPolicy(a)
	if reply := deviceMTUTestPost(t, a, initial.token, 1320); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	capture, _ := captureDeviceMTUPolicy(a)
	ctx := context.WithValue(context.Background(), deviceMTUContextKey{}, capture)
	input := []string{"HOMEVPN_MTU=1380", "HOMEVPN_MTU=1440", "HOMEVPN_DEVICE_MTU=9000", "HOMEVPN_DEVICE_MTU_REVISION=ambient", "HOMEVPN_DEVICE_MTU_FAKE=1", "HOMEVPN_ENDPOINT=203.0.113.10"}
	env, err := a.deviceMTULaunchEnvironment(ctx, input, false, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"HOMEVPN_ENDPOINT=203.0.113.10", "HOMEVPN_DEVICE_MTU=1320", "HOMEVPN_DEVICE_MTU_REVISION=" + capture.policy.Revision, "HOMEVPN_MTU=1320"}
	if !reflect.DeepEqual(env, want) || input[0] != "HOMEVPN_MTU=1380" {
		t.Fatal("launch inherited ambient or rewritten policy", env)
	}
	for _, flags := range [][2]bool{{true, false}, {false, true}} {
		if _, err := a.deviceMTULaunchEnvironment(ctx, input, flags[0], flags[1]); err == nil {
			t.Fatal("conflicting mode reached launch")
		}
	}
	if _, err := a.deviceMTULaunchEnvironment(context.Background(), input, false, false); err == nil {
		t.Fatal("fixed launch invented a new uncaptured preference")
	}
}

func TestDeviceMTURequiresNativeOwnerBeforeStop(t *testing.T) {
	privateOperationRoot(t)
	a := deviceMTUTestApp(t)
	a.profiles.Profiles[0].Endpoint = "198.51.100.7"
	initial, _ := captureDeviceMTUPolicy(a)
	if err := a.requireDeviceMTUNativeOwner(context.Background(), false); err != nil {
		t.Fatal("per-configuration mode lost its existing adapter", err)
	}
	if reply := deviceMTUTestPost(t, a, initial.token, 1320); reply.Code != 200 {
		t.Fatal(reply.Body.String())
	}
	ctx, finish, err := a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	if err := a.requireDeviceMTUNativeOwner(ctx, true); err != nil {
		t.Fatal("captured fixed policy refused its native owner", err)
	}
	if err := a.requireDeviceMTUNativeOwner(context.Background(), true); err == nil {
		t.Fatal("native launch invented a replacement preference capture")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if a.requireDeviceMTUNativeOwner(canceled, true) == nil || a.requireDeviceMTUNativeOwner(nil, true) == nil {
		t.Fatal("native admission accepted a missing or expired connection")
	}
	foreign := deviceMTUTestApp(t)
	if foreign.requireDeviceMTUNativeOwner(ctx, true) == nil {
		t.Fatal("native admission borrowed another application's preference")
	}
	// Model the prior command boundary; this test must never execute Stop or a
	// replacement command. The real startModeAttempt performs admission.
	original := &exec.Cmd{Path: "captured-existing-runtime"}
	a.cmd = original
	a.state = state{Connected: true, Phase: "connected", Mode: "original", RuntimeMode: "original", RouterID: "first"}
	a.modes = []common.Mode{{ID: "legacy-fixed-fixture", Command: []string{"must-not-launch"}}}
	before := a.state
	transition := &modeAttemptTransition{}
	err = a.startModeAttempt("legacy-fixed-fixture", true, transition)
	if err == nil || !strings.Contains(err.Error(), "cannot verify the fixed device MTU") ||
		transition.StopBegun || a.cmd != original || a.state != before || ctx.Err() != nil {
		t.Fatal("unowned fixed-MTU adapter disturbed the original connection", err, transition.StopBegun)
	}
	current := deviceMTUForContext(ctx)
	changed := current.policy
	changed.Revision = strings.Repeat("b", 32)
	raw, _ := json.Marshal(changed)
	if err := os.WriteFile(deviceMTUPolicyPath(a), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if a.requireDeviceMTUNativeOwner(ctx, true) == nil {
		t.Fatal("native admission accepted a changed preference source")
	}
}
