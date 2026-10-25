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

func deviceSettingsTestApp(t *testing.T, protocol string, viaEntry bool) *app {
	t.Helper()
	a := externalConnectionTestApp(t, protocol, viaEntry)
	if protocol == "tor-bridge" {
		return a
	}
	var native common.RouterProfile
	if protocol == "openvpn" {
		var err error
		native, err = externalProfileFromCreateRequest(desktopOpenVPNCreateFixture(t, "off"))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		native, _ = desktopExternalNativeFixture(t, protocol)
	}
	a.profiles.Profiles[3].External = native.External
	a.profiles.Profiles[3].Endpoint = native.Endpoint
	a.profiles.Profiles[3].StartLayer = native.StartLayer
	return a
}

func getDeviceSettingsForTest(t *testing.T, a *app) profileDeviceSettings {
	t.Helper()
	mux := http.NewServeMux()
	registerProfileSettingsRoute(mux, a)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/profile/device", nil))
	if w.Code != http.StatusOK || w.Header().Get("cache-control") != "no-store" {
		t.Fatalf("device GET: %d %s", w.Code, w.Body.String())
	}
	var value profileDeviceSettings
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &fields)
	if len(fields) != 16 || value.ProfileID != a.profiles.SelectedID || len(value.ProfileToken) != 64 {
		t.Fatal("device GET leaked fields or lost selected identity")
	}
	for _, forbidden := range []string{"password", "private_key", "peer_public_key", "bridges", "api_token", "router_api"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("device GET exposed private field %s", forbidden)
		}
	}
	return value
}

func deviceSettingsRequestForTest(t *testing.T, capture profileDeviceSettings, policy string) map[string]any {
	t.Helper()
	fixed := 0
	if policy == "manual" {
		fixed = 1320
	}
	return map[string]any{
		"profile_id": capture.ProfileID, "profile_token": capture.ProfileToken,
		"home_lan_access": true, "kill_switch_policy": "on-connect", "ipv6_mode": "on",
		"mtu_policy": policy, "manual_mtu": fixed,
	}
}

func deviceSettingsBodyForTest(t *testing.T, request map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func postDeviceSettingsForTest(a *app, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.profileDeviceSettings(w, httptest.NewRequest(http.MethodPost, "/api/profile/device", body))
	return w
}

func TestProfileDevicePreservesExternalGraphCredentialsEntryAndMeasurements(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn", "tor-bridge"} {
		for _, viaEntry := range []bool{false, true} {
			if protocol == "tor-bridge" && viaEntry {
				continue // The separate Tor rejection test retains this required graph.
			}
			for _, policy := range []string{"auto", "default", "manual"} {
				t.Run(protocol+"/"+policy+map[bool]string{false: "/direct", true: "/entry"}[viaEntry], func(t *testing.T) {
					a := deviceSettingsTestApp(t, protocol, viaEntry)
					capture := getDeviceSettingsForTest(t, a)
					if !capture.DevicePolicySupported || capture.DevicePolicyReason != "" {
						t.Fatal("native path does not advertise its actual common settings")
					}
					before := cloneRouterProfileStore(a.profiles)
					request := deviceSettingsRequestForTest(t, capture, policy)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					startupPolicyCancels.Store(a, context.CancelFunc(cancel))
					w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, request)))
					if w.Code != http.StatusOK {
						t.Fatalf("device save: %d %s", w.Code, w.Body.String())
					}
					if ctx.Err() != context.Canceled || a.state.Connected || a.cmd != nil {
						t.Fatal("device edit retained delayed startup or launched a runtime")
					}
					p := &before.Profiles[3]
					p.HomeLANAccess, p.KillSwitchPolicy, p.KillSwitch, p.IPv6Mode = true, "on-connect", true, "on"
					p.MTUPolicy, p.ManualMTU = policy, request["manual_mtu"].(int)
					if !reflect.DeepEqual(before, a.profiles) {
						t.Fatal("device edit changed credentials, independent entry, DNS, graph, startup or measurements")
					}
					raw, err := os.ReadFile(a.cfg.ProfilesFile)
					if err != nil || !bytes.Contains(raw, []byte(`"mtu_policy": "`+policy+`"`)) {
						t.Fatalf("device policy was not persisted: %v", err)
					}
					var response profileDeviceSettings
					if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.ProfileToken == capture.ProfileToken ||
						response.ProfileID != capture.ProfileID || response.ManualMTU != p.ManualMTU {
						t.Fatal("save did not return the exact new captured policy")
					}
				})
			}
		}
	}
}

func TestProfileDeviceStartupPairIsOptionalAndAtomic(t *testing.T) {
	for _, mode := range []string{"manual", "auto", "smart-auto", "last"} {
		t.Run(mode, func(t *testing.T) {
			a := deviceSettingsTestApp(t, "shadowsocks", true)
			before := cloneRouterProfileStore(a.profiles)
			q := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "manual")
			q["startup_mode"], q["auto_connect"] = mode, mode != "manual"
			w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
			if w.Code != http.StatusOK {
				t.Fatalf("atomic settings: %d %s", w.Code, w.Body.String())
			}
			p := &before.Profiles[3]
			p.HomeLANAccess, p.KillSwitchPolicy, p.KillSwitch, p.IPv6Mode = true, "on-connect", true, "on"
			p.MTUPolicy, p.ManualMTU, p.StartupMode, p.AutoConnect = "manual", 1320, mode, mode != "manual"
			if !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("atomic full Settings changed an unedited field")
			}
		})
	}
}

func TestProfileDeviceRejectsChangedSelectedAndIndependentEntrySource(t *testing.T) {
	cases := map[string]func(*app){
		"selection":       func(a *app) { a.profiles.SelectedID = "entry" },
		"exit credential": func(a *app) { a.profiles.Profiles[3].External.Shadowsocks.Password = "replacement" },
		"exit DNS":        func(a *app) { a.profiles.Profiles[3].DNSHost = "1.1.1.1" },
		"exit graph":      func(a *app) { a.profiles.Profiles[3].MultihopExecution = "server" },
		"exit startup":    func(a *app) { a.profiles.Profiles[3].AutoConnect = true },
		"entry policy":    func(a *app) { a.profiles.Profiles[1].IPv6Mode = "off" },
		"entry key":       func(a *app) { a.profiles.Profiles[1].APIToken = "replacement" },
		"entry removed":   func(a *app) { a.profiles.Profiles[1].ID = "replacement" },
		"connected":       func(a *app) { a.state.Connected = true },
		"future phase":    func(a *app) { a.state.Phase = "future-transition" },
		"closing":         func(a *app) { a.closing = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := deviceSettingsTestApp(t, "shadowsocks", true)
			q := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "auto")
			mutate(a)
			before := cloneRouterProfileStore(a.profiles)
			w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
			if w.Code < 400 || !reflect.DeepEqual(before, a.profiles) {
				t.Fatalf("stale captured source changed policy: %d", w.Code)
			}
		})
	}
}

func TestProfileDeviceRevalidatesAtCommitAndPreservesFreshHistoricalMeasurements(t *testing.T) {
	for _, change := range []string{"selection", "entry key", "exit key", "busy", "closing", "cancelled", "measurements"} {
		t.Run(change, func(t *testing.T) {
			a := deviceSettingsTestApp(t, "shadowsocks", true)
			capture := getDeviceSettingsForTest(t, a)
			q := deviceSettingsRequestForTest(t, capture, "auto")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var changed common.RouterProfileStore
			reader := &startupSettingsMutationReader{Reader: bytes.NewReader(deviceSettingsBodyForTest(t, q)), mutate: func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				switch change {
				case "selection":
					a.profiles.SelectedID = "entry"
				case "entry key":
					a.profiles.Profiles[1].APIToken = "replacement"
				case "exit key":
					a.profiles.Profiles[3].External.Shadowsocks.Password = "replacement"
				case "busy":
					a.state.Phase = "disconnecting"
				case "closing":
					a.closing = true
				case "cancelled":
					cancel()
				case "measurements":
					a.profiles.Profiles[3].LatencyMedianMs = 38.5
					a.profiles.Profiles[3].UseCount = 17
					a.profiles.Profiles[3].EffectiveMTU = 1420
					a.profiles.Profiles[3].EffectiveMTUSource = "new-observed-owner"
					a.profiles.Profiles[1].EffectiveMTU = 1460
				}
				changed = cloneRouterProfileStore(a.profiles)
			}}
			w := httptest.NewRecorder()
			a.profileDeviceSettings(w, httptest.NewRequest(http.MethodPost, "/api/profile/device", reader).WithContext(ctx))
			if change == "measurements" {
				p := &changed.Profiles[3]
				p.HomeLANAccess, p.KillSwitchPolicy, p.KillSwitch, p.IPv6Mode = true, "on-connect", true, "on"
				p.MTUPolicy, p.ManualMTU = "auto", 0
				if w.Code != http.StatusOK || !reflect.DeepEqual(changed, a.profiles) {
					t.Fatalf("policy edit lost a fresh measurement or entry history: %d %s", w.Code, w.Body.String())
				}
			} else if w.Code != http.StatusConflict || !reflect.DeepEqual(changed, a.profiles) {
				t.Fatalf("post-validation owner change adopted: %d", w.Code)
			}
		})
	}
}

func TestProfileDeviceRejectsMalformedDraftAndRollsBackFailedPersist(t *testing.T) {
	cases := map[string]func(map[string]any){
		"missing LAN":   func(q map[string]any) { delete(q, "home_lan_access") },
		"null LAN":      func(q map[string]any) { q["home_lan_access"] = nil },
		"string LAN":    func(q map[string]any) { q["home_lan_access"] = "true" },
		"missing kill":  func(q map[string]any) { delete(q, "kill_switch_policy") },
		"unknown kill":  func(q map[string]any) { q["kill_switch_policy"] = "strict-ish" },
		"missing IPv6":  func(q map[string]any) { delete(q, "ipv6_mode") },
		"unknown IPv6":  func(q map[string]any) { q["ipv6_mode"] = "maybe" },
		"missing MTU":   func(q map[string]any) { delete(q, "mtu_policy") },
		"unknown MTU":   func(q map[string]any) { q["mtu_policy"] = "jumbo" },
		"missing fixed": func(q map[string]any) { delete(q, "manual_mtu") },
		"low fixed":     func(q map[string]any) { q["manual_mtu"] = 1279 },
		"large fixed":   func(q map[string]any) { q["manual_mtu"] = 9001 },
		"fraction":      func(q map[string]any) { q["manual_mtu"] = 1320.5 },
		"string fixed":  func(q map[string]any) { q["manual_mtu"] = "1320" },
		"stale fixed":   func(q map[string]any) { q["mtu_policy"] = "auto" },
		"half startup":  func(q map[string]any) { q["startup_mode"] = "last" },
		"half enabled":  func(q map[string]any) { q["auto_connect"] = true },
		"manual start":  func(q map[string]any) { q["startup_mode"], q["auto_connect"] = "manual", true },
		"bad start":     func(q map[string]any) { q["startup_mode"], q["auto_connect"] = "boot", false },
		"foreign ID":    func(q map[string]any) { q["profile_id"] = "entry" },
		"no revision":   func(q map[string]any) { delete(q, "profile_token") },
		"mixed DNS":     func(q map[string]any) { q["dns_host"] = "1.1.1.1" },
		"mixed graph":   func(q map[string]any) { q["multihop_entry_id"] = "home" },
		"mixed padding": func(q map[string]any) { q["daita_enabled"] = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := deviceSettingsTestApp(t, "shadowsocks", true)
			q := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "manual")
			mutate(q)
			before := cloneRouterProfileStore(a.profiles)
			w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
			if w.Code < 400 || !reflect.DeepEqual(before, a.profiles) {
				t.Fatalf("invalid draft changed source: %d", w.Code)
			}
		})
	}
	for _, failure := range []string{"extra object", "oversize", "persist"} {
		t.Run(failure, func(t *testing.T) {
			a := deviceSettingsTestApp(t, "shadowsocks", true)
			q := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "manual")
			body := deviceSettingsBodyForTest(t, q)
			switch failure {
			case "extra object":
				body = append(body, []byte(" {}")...)
			case "oversize":
				body = append(body, []byte(strings.Repeat(" ", 4096))...)
			case "persist":
				a.cfg.ProfilesFile = t.TempDir()
			}
			before := cloneRouterProfileStore(a.profiles)
			w := postDeviceSettingsForTest(a, bytes.NewReader(body))
			if w.Code < 400 || !reflect.DeepEqual(before, a.profiles) {
				t.Fatalf("failed transaction changed source: %d", w.Code)
			}
		})
	}
}

func TestProfileDeviceNativeValidationAndHomeDraftDoNotInventReadiness(t *testing.T) {
	for _, fault := range []string{"none", "LAN network", "OpenVPN MTU"} {
		t.Run(fault, func(t *testing.T) {
			protocol := "shadowsocks"
			if fault == "OpenVPN MTU" {
				protocol = "openvpn"
			}
			a := deviceSettingsTestApp(t, protocol, false)
			p := &a.profiles.Profiles[3]
			p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "home", "udp", "", 53
			if fault == "LAN network" {
				p.HomeLANCIDRs = []string{"0.0.0.0/0"}
			} else if fault == "OpenVPN MTU" {
				p.MultihopExecution = "server"
			}
			capture := getDeviceSettingsForTest(t, a)
			q := deviceSettingsRequestForTest(t, capture, "manual")
			q["home_lan_access"] = false
			if fault == "OpenVPN MTU" {
				q["manual_mtu"] = 9000
			}
			before := cloneRouterProfileStore(a.profiles)
			w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
			if fault != "none" {
				if w.Code < 400 || !reflect.DeepEqual(before, a.profiles) {
					t.Fatalf("native invalid device policy accepted: %d", w.Code)
				}
				return
			}
			if w.Code != http.StatusOK || p.DNSMode != "home" || p.DNSHost != "" || a.cmd != nil || a.state.Connected {
				t.Fatalf("idle Home draft did not preserve unresolved policy: %d %s", w.Code, w.Body.String())
			}
			selected := a.profiles.Profiles[3]
			exit, err := standardExitFromExternalProfile(selected)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = compileDesktopExternalCaptured(context.Background(), selected, common.RouterProfile{}, exit, true, "", nil, nil, nil); err == nil {
				t.Fatal("idle saved Home draft bypassed actual path DNS proof")
			}
		})
	}
}

func TestProfileDeviceSavedPolicyReachesActualNativeCompiler(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			a := deviceSettingsTestApp(t, protocol, false)
			q := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "manual")
			q["home_lan_access"], q["ipv6_mode"], q["kill_switch_policy"] = false, "off", "always"
			w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
			if w.Code != http.StatusOK {
				t.Fatalf("device save: %d %s", w.Code, w.Body.String())
			}
			profile := a.profiles.Profiles[3]
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if json.Unmarshal(launch.config, &config) != nil {
				t.Fatal("invalid actual native compiler result")
			}
			ins, _ := config["inbounds"].([]any)
			if len(ins) != 1 || ins[0].(map[string]any)["mtu"] != float64(1320) {
				t.Fatal("saved Fixed policy did not reach the sole native TUN")
			}
			dns := config["dns"].(map[string]any)
			if dns["strategy"] != "ipv4_only" || !bytes.Contains(launch.config, []byte(profile.DNSHost)) {
				t.Fatal("saved IPv6/DNS policy was substituted")
			}
			route := config["route"].(map[string]any)
			ipv6, lan := false, false
			for _, raw := range route["rules"].([]any) {
				rule := raw.(map[string]any)
				if rule["ip_version"] == float64(6) && rule["action"] == "reject" {
					ipv6 = true
				}
				if prefixes, ok := rule["ip_cidr"].([]any); ok && rule["action"] == "reject" {
					for _, prefix := range prefixes {
						lan = lan || prefix == "192.168.50.0/24"
					}
				}
			}
			if !ipv6 || !lan || launch.external.profile.KillSwitchPolicy != "always" ||
				launch.external.profile.ManualMTU != 1320 || a.cmd != nil || a.state.Connected {
				t.Fatal("saved device protection did not reach the captured runtime, or compilation claimed Connected")
			}
		})
	}
}

func TestProfileDeviceReadNormalizesLegacyBlankEnumsWithoutMutatingSource(t *testing.T) {
	a := deviceSettingsTestApp(t, "shadowsocks", false)
	p := &a.profiles.Profiles[3]
	p.KillSwitchPolicy, p.IPv6Mode, p.MTUPolicy, p.StartupMode = "", "", "", ""
	p.KillSwitch, p.ManualMTU = true, 0
	before := cloneRouterProfileStore(a.profiles)
	capture := getDeviceSettingsForTest(t, a)
	if capture.KillSwitchPolicy != "on-connect" || capture.IPv6Mode != "on" ||
		capture.MTUPolicy != "auto" || capture.StartupMode != "smart-auto" ||
		!reflect.DeepEqual(before, a.profiles) {
		t.Fatal("read did not normalize known blank defaults without replacing source")
	}
	p.MTUPolicy, p.ManualMTU = "fixed", 1350
	before = cloneRouterProfileStore(a.profiles)
	capture = getDeviceSettingsForTest(t, a)
	if capture.MTUPolicy != "manual" || capture.ManualMTU != 1350 || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("legacy Fixed alias changed its requested MTU or saved source")
	}
	p.MTUPolicy, p.ManualMTU = "auto", 1400
	before = cloneRouterProfileStore(a.profiles)
	capture = getDeviceSettingsForTest(t, a)
	if capture.MTUPolicy != "auto" || capture.ManualMTU != 0 || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("Auto displayed an unused fixed value as policy or mutated source")
	}
}

func TestProfileDeviceUnsupportedRuntimeAndRouterStayExplicit(t *testing.T) {
	a := externalConnectionTestApp(t, "tor-bridge", false)
	a.profiles.Profiles[3].External.Protocol = "future-protocol"
	capture := getDeviceSettingsForTest(t, a)
	if capture.DevicePolicySupported || capture.DevicePolicyReason == "" {
		t.Fatal("unwired protocol claimed common device support")
	}
	before := cloneRouterProfileStore(a.profiles)
	q := deviceSettingsRequestForTest(t, capture, "auto")
	if w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q))); w.Code != http.StatusUnprocessableEntity || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("unsupported runtime silently accepted common settings")
	}
	a.profiles.SelectedID = "home"
	w := httptest.NewRecorder()
	a.profileDeviceSettings(w, httptest.NewRequest(http.MethodGet, "/api/profile/device", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatal("external editor replaced Router settings")
	}
	w = httptest.NewRecorder()
	a.profileDeviceSettings(w, httptest.NewRequest(http.MethodDelete, "/api/profile/device", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("unsupported method accepted")
	}
}
