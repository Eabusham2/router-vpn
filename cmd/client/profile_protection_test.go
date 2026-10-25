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
)

func getProtectionForTest(t *testing.T, a *app) profileProtectionSettings {
	t.Helper()
	mux := http.NewServeMux()
	registerProfileSettingsRoute(mux, a)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/profile/protection", nil))
	if w.Code != http.StatusOK || w.Header().Get("cache-control") != "no-store" {
		t.Fatalf("protection GET: %d %s", w.Code, w.Body.String())
	}
	var value profileProtectionSettings
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &fields)
	if len(fields) != 3 || value.ProfileID != a.profiles.SelectedID || len(value.ProfileToken) != 64 {
		t.Fatal("protection GET leaked fields or lost exact selected identity")
	}
	return value
}

func protectionBodyForTest(t *testing.T, capture profileProtectionSettings, policy string) []byte {
	t.Helper()
	capture.KillSwitchPolicy = policy
	body, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func postProtectionForTest(a *app, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.profileProtectionSettings(w, httptest.NewRequest(http.MethodPost, "/api/profile/protection", body))
	return w
}

func TestProfileProtectionPreservesExternalPrivateGraphAndPolicies(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn", "tor-bridge"} {
		for _, viaEntry := range []bool{false, true} {
			name := protocol + "/direct"
			if viaEntry {
				name = protocol + "/via-entry"
			}
			t.Run(name, func(t *testing.T) {
				a := externalConnectionTestApp(t, protocol, viaEntry)
				for _, policy := range []string{"off", "on-connect", "always"} {
					capture := getProtectionForTest(t, a)
					before := cloneRouterProfileStore(a.profiles)
					ctx, cancel := context.WithCancel(context.Background())
					startupPolicyCancels.Store(a, context.CancelFunc(cancel))
					w := postProtectionForTest(a, bytes.NewReader(protectionBodyForTest(t, capture, policy)))
					if w.Code != http.StatusOK {
						cancel()
						t.Fatalf("protection save: %d %s", w.Code, w.Body.String())
					}
					if ctx.Err() != context.Canceled {
						cancel()
						t.Fatal("policy edit retained an older startup intent")
					}
					cancel()
					before.Profiles[3].KillSwitchPolicy, before.Profiles[3].KillSwitch = policy, policy != "off"
					if !reflect.DeepEqual(before, a.profiles) {
						t.Fatal("protection edit changed another node, credentials, DNS, graph, MTU, or startup")
					}
					file, err := os.ReadFile(a.cfg.ProfilesFile)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Contains(file, []byte(`"kill_switch_policy": "`+policy+`"`)) {
						t.Fatal("protection policy was not persisted")
					}
				}
			})
		}
	}
}

func TestProfileProtectionRejectsStaleSourceAndBusyOrMissingOwner(t *testing.T) {
	cases := map[string]func(*app){
		"selection":   func(a *app) { a.profiles.SelectedID = "entry" },
		"credential":  func(a *app) { a.profiles.Profiles[3].External.Shadowsocks.Password = "new-secret" },
		"DNS":         func(a *app) { a.profiles.Profiles[3].DNSHost = "1.1.1.1" },
		"graph":       func(a *app) { a.profiles.Profiles[3].MultihopExecution = "server" },
		"kill policy": func(a *app) { a.profiles.Profiles[3].KillSwitchPolicy = "off" },
		"connected":   func(a *app) { a.state.Connected = true },
		"transition":  func(a *app) { a.state.Phase = "future-transition" },
		"closing":     func(a *app) { a.closing = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", true)
			capture := getProtectionForTest(t, a)
			mutate(a)
			before := cloneRouterProfileStore(a.profiles)
			w := postProtectionForTest(a, bytes.NewReader(protectionBodyForTest(t, capture, "on-connect")))
			if w.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) {
				t.Fatalf("stale/busy protection edit adopted: %d", w.Code)
			}
		})
	}
}

func TestProfileProtectionRechecksAtCommitAndPreservesConcurrentMeasurements(t *testing.T) {
	for _, change := range []string{"selection", "credential", "connected", "closing", "measurement"} {
		t.Run(change, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", false)
			capture := getProtectionForTest(t, a)
			reader := &startupSettingsMutationReader{Reader: bytes.NewReader(protectionBodyForTest(t, capture, "off")), mutate: func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				switch change {
				case "selection":
					a.profiles.SelectedID = "entry"
				case "credential":
					a.profiles.Profiles[3].External.Shadowsocks.Password = "replacement"
				case "connected":
					a.state.Connected = true
				case "closing":
					a.closing = true
				case "measurement":
					a.profiles.Profiles[3].LatencyMedianMs = 37.5
					a.profiles.Profiles[3].UseCount = 11
				}
			}}
			w := postProtectionForTest(a, reader)
			if change == "measurement" {
				if w.Code != http.StatusOK || a.profiles.Profiles[3].KillSwitch || a.profiles.Profiles[3].LatencyMedianMs != 37.5 || a.profiles.Profiles[3].UseCount != 11 {
					t.Fatalf("current metadata lost during protection edit: %d", w.Code)
				}
			} else if w.Code != http.StatusConflict || a.profiles.Profiles[3].KillSwitchPolicy != "always" {
				t.Fatalf("late source/owner change escaped final check: %d", w.Code)
			}
		})
	}
}

func TestProfileProtectionRejectsMalformedInputAndRollsBackPersistenceFailure(t *testing.T) {
	for _, change := range []string{"bad policy", "empty policy", "foreign ID", "missing revision", "mixed settings", "extra object", "persistence"} {
		t.Run(change, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", false)
			capture := getProtectionForTest(t, a)
			var request map[string]any
			_ = json.Unmarshal(protectionBodyForTest(t, capture, "off"), &request)
			switch change {
			case "bad policy":
				request["kill_switch_policy"] = "strict-ish"
			case "empty policy":
				request["kill_switch_policy"] = ""
			case "foreign ID":
				request["profile_id"] = "entry"
			case "missing revision":
				delete(request, "profile_token")
			case "mixed settings":
				request["dns_host"] = "1.1.1.1"
			case "persistence":
				a.cfg.ProfilesFile = t.TempDir()
			}
			body, _ := json.Marshal(request)
			if change == "extra object" {
				body = append(body, []byte(" {}")...)
			}
			before := cloneRouterProfileStore(a.profiles)
			w := postProtectionForTest(a, bytes.NewReader(body))
			if w.Code < 400 || !reflect.DeepEqual(before, a.profiles) {
				t.Fatalf("unsafe/failed protection edit changed source: %d", w.Code)
			}
			if strings.Contains(w.Body.String(), "ss-secret") {
				t.Fatal("error leaked private credential")
			}
		})
	}
}

func TestProfileProtectionRouterNodeUsesSameCapturedTransaction(t *testing.T) {
	a := externalConnectionTestApp(t, "shadowsocks", false)
	a.profiles.SelectedID = "home"
	capture := getProtectionForTest(t, a)
	w := postProtectionForTest(a, bytes.NewReader(protectionBodyForTest(t, capture, "always")))
	profile, exists := a.profileByIDLocked("home")
	if w.Code != http.StatusOK || !exists || !profile.KillSwitch || profile.KillSwitchPolicy != "always" {
		t.Fatalf("Router protection transaction failed: %d %s", w.Code, w.Body.String())
	}
}
