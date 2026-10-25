package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func getStartupSettingsForTest(t *testing.T, a *app) profileStartupSettings {
	t.Helper()
	mux := http.NewServeMux()
	registerProfileSettingsRoute(mux, a)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/profile/startup", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("startup GET: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("cache-control") != "no-store" {
		t.Fatal("startup snapshot must not be cached")
	}
	for _, secret := range []string{"private_key", "password", "ss-secret", "hy-secret", "proxy-secret", "private-ovpn", "bridges", "api_token"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("startup response exposes private field %q", secret)
		}
	}
	var p profileStartupSettings
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func startupSettingsBodyForTest(t *testing.T, p profileStartupSettings, mode string, automatic bool) []byte {
	t.Helper()
	raw, err := json.Marshal(profileStartupRequest{ProfileID: p.ProfileID, ProfileToken: p.ProfileToken, StartupMode: mode, AutoConnect: &automatic})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func postStartupSettingsForTest(a *app, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.profileStartupSettings(w, httptest.NewRequest(http.MethodPost, "/api/profile/startup", body))
	return w
}

func TestProfileStartupSettingsExternalSavePreservesPrivateNodeAndOnlyChangesStartup(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn", "tor-bridge"} {
		t.Run(protocol, func(t *testing.T) {
			a := externalConnectionTestApp(t, protocol, true)
			before := cloneRouterProfileStore(a.profiles)
			snapshot := getStartupSettingsForTest(t, a)
			if snapshot.NodeKind != "external" || snapshot.ProfileID != before.SelectedID || len(snapshot.ProfileToken) != 64 {
				t.Fatalf("wrong selected-node snapshot: %+v", snapshot)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			startupPolicyCancels.Store(a, context.CancelFunc(cancel))
			t.Cleanup(func() { cancelPendingStartupPolicy(a) })
			w := postStartupSettingsForTest(a, bytes.NewReader(startupSettingsBodyForTest(t, snapshot, "last", true)))
			if w.Code != http.StatusOK {
				t.Fatalf("startup save: %d %s", w.Code, w.Body.String())
			}
			if ctx.Err() != context.Canceled {
				t.Fatal("settings save retained a delayed startup intent")
			}
			want := cloneRouterProfileStore(before)
			want.Profiles[3].StartupMode, want.Profiles[3].AutoConnect = "last", true
			if !reflect.DeepEqual(a.profiles, want) {
				t.Fatal("startup save changed another policy, private node, or node selection")
			}
			raw, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			var disk common.RouterProfileStore
			if err := json.Unmarshal(raw, &disk); err != nil {
				t.Fatal(err)
			}
			if disk.SelectedID != want.SelectedID || disk.Profiles[3].StartupMode != "last" || !disk.Profiles[3].AutoConnect || !reflect.DeepEqual(disk.Profiles[3].External, want.Profiles[3].External) {
				t.Fatal("startup/private data was not durably preserved")
			}
		})
	}
}

func TestProfileStartupSettingsRejectsStaleSelectionPolicyCredentialsAndAutoconnect(t *testing.T) {
	cases := map[string]func(*app){
		"selection":     func(a *app) { a.profiles.SelectedID = "entry" },
		"credentials":   func(a *app) { a.profiles.Profiles[3].External.Shadowsocks.Password = "replacement-secret" },
		"DNS":           func(a *app) { a.profiles.Profiles[3].DNSHost = "1.1.1.1" },
		"startup":       func(a *app) { a.profiles.Profiles[3].StartupMode = "auto" },
		"autoconnect":   func(a *app) { a.profiles.Profiles[3].AutoConnect = true },
		"requested MTU": func(a *app) { a.profiles.Profiles[3].ManualMTU = 1320 },
		"hop":           func(a *app) { a.profiles.Profiles[3].MultihopEntryID = "replacement" },
		"execution":     func(a *app) { a.profiles.Profiles[3].MultihopExecution = "server" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", true)
			snapshot := getStartupSettingsForTest(t, a)
			mutate(a)
			before := cloneRouterProfileStore(a.profiles)
			w := postStartupSettingsForTest(a, bytes.NewReader(startupSettingsBodyForTest(t, snapshot, "last", true)))
			if w.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) {
				t.Fatalf("stale editor adopted/replaced state: status %d", w.Code)
			}
		})
	}
}

type startupSettingsMutationReader struct {
	io.Reader
	mutate func()
}

func (r *startupSettingsMutationReader) Read(p []byte) (int, error) {
	if r.mutate != nil {
		r.mutate()
		r.mutate = nil
	}
	return r.Reader.Read(p)
}

func TestProfileStartupSettingsRechecksCapturedNodeBeforePersistence(t *testing.T) {
	for _, change := range []string{"selection", "source", "connected", "closing"} {
		t.Run(change, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", false)
			snapshot := getStartupSettingsForTest(t, a)
			body := startupSettingsBodyForTest(t, snapshot, "auto", true)
			reader := &startupSettingsMutationReader{Reader: bytes.NewReader(body), mutate: func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				switch change {
				case "selection":
					a.profiles.SelectedID = "entry"
				case "source":
					a.profiles.Profiles[3].DNSPort++
				case "connected":
					a.state.Connected = true
				case "closing":
					a.closing = true
				}
			}}
			w := postStartupSettingsForTest(a, reader)
			if w.Code != http.StatusConflict || a.profiles.Profiles[3].AutoConnect {
				t.Fatalf("late %s change adopted stale edit: %d", change, w.Code)
			}
		})
	}
}

func TestProfileStartupSettingsRejectsMalformedUnsafeAndUnownedEdits(t *testing.T) {
	for _, change := range []string{"foreign field", "empty identity", "bad mode", "manual automatic", "missing automatic", "trailing JSON"} {
		t.Run(change, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", false)
			snapshot := getStartupSettingsForTest(t, a)
			var body map[string]any
			_ = json.Unmarshal(startupSettingsBodyForTest(t, snapshot, "auto", true), &body)
			switch change {
			case "foreign field":
				body["dns_host"] = "1.1.1.1"
			case "empty identity":
				body["profile_id"] = ""
			case "bad mode":
				body["startup_mode"] = "random"
			case "manual automatic":
				body["startup_mode"] = "manual"
			case "missing automatic":
				delete(body, "auto_connect")
			}
			raw, _ := json.Marshal(body)
			if change == "trailing JSON" {
				raw = append(raw, []byte(" {}")...)
			}
			before := cloneRouterProfileStore(a.profiles)
			w := postStartupSettingsForTest(a, bytes.NewReader(raw))
			if w.Code < 400 || !reflect.DeepEqual(a.profiles, before) {
				t.Fatalf("unsafe input changed saved node: %d", w.Code)
			}
		})
	}
}

func TestProfileStartupSettingsPersistenceFailureAndBusyStateLeaveSourceUntouched(t *testing.T) {
	for _, condition := range []string{"persistence", "connected", "unknown phase", "operation"} {
		t.Run(condition, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", false)
			snapshot := getStartupSettingsForTest(t, a)
			before := cloneRouterProfileStore(a.profiles)
			switch condition {
			case "persistence":
				a.cfg.ProfilesFile = t.TempDir()
			case "connected":
				a.state.Connected = true
			case "unknown phase":
				a.state.Phase = "future-transition"
			case "operation":
				a.operationMu.Lock()
				defer a.operationMu.Unlock()
			}
			w := postStartupSettingsForTest(a, bytes.NewReader(startupSettingsBodyForTest(t, snapshot, "auto", true)))
			if w.Code < 400 || !reflect.DeepEqual(a.profiles, before) {
				t.Fatalf("failed/busy save changed selected private node: %d", w.Code)
			}
		})
	}
}
