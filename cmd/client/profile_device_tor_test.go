package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestProfileDeviceTorSavedPolicyReachesActualDesktopPreparation(t *testing.T) {
	for _, mtu := range []string{"auto", "default", "manual"} {
		for _, transport := range []string{"tcp", "dot", "doh"} {
			t.Run(mtu+"/"+transport, func(t *testing.T) {
				a := deviceSettingsTestApp(t, "tor-bridge", false)
				profile := &a.profiles.Profiles[3]
				profile.DNSProtocol = transport
				profile.DNSPort = 5353
				if transport != "tcp" {
					profile.DNSServerName = "dns.example.test"
				}
				if transport == "doh" {
					profile.DNSPath = "/captured-query"
				}
				capture := getDeviceSettingsForTest(t, a)
				if !capture.DevicePolicySupported || capture.DevicePolicyReason != "" ||
					!strings.Contains(capture.Note, "1280-byte virtual interface") ||
					!strings.Contains(capture.Note, "Retest repeats those measurements with fresh Tor and DNS proof") ||
					!strings.Contains(capture.Note, "not a UDP path-MTU measurement") {
					t.Fatal("Tor device capability or interface/measurement boundary is inaccurate")
				}
				q := deviceSettingsRequestForTest(t, capture, mtu)
				q["home_lan_access"], q["ipv6_mode"], q["kill_switch_policy"] = false, "off", "always"
				w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
				if w.Code != http.StatusOK {
					t.Fatalf("Tor device save: %d %s", w.Code, w.Body.String())
				}
				saved := cloneRouterProfile(a.profiles.Profiles[3])
				prepared, err := stageDesktopTorInputs(t.TempDir(), saved, saved,
					installFakeExecutable(t, t.TempDir(), "tor"), installFakeExecutable(t, t.TempDir(), "native"))
				if err != nil {
					t.Fatal("saved device policy did not reach shipping Tor preparation", err)
				}
				defer func() {
					if err := cleanupDesktopTorLaunch(prepared.Launch); err != nil {
						t.Error("prepared owner did not clean its private inputs", err)
					}
					_ = prepared.Launch.directoryRoot.Close()
				}()
				expectedMTU := 1280
				if mtu == "manual" {
					expectedMTU = 1320
				}
				metadata := prepared.Launch.tor.expected
				if metadata.MTUPolicy != mtu || metadata.ConfiguredMTU != expectedMTU || metadata.IPv6Mode != "off" ||
					metadata.HomeLANAccess || metadata.KillSwitchPolicy != "always" || metadata.DNS.Address != saved.DNSHost ||
					metadata.DNS.Port != saved.DNSPort || metadata.DNS.ServerName != saved.DNSServerName || metadata.DNS.Path != saved.DNSPath {
					t.Fatal("saved Tor policy was substituted before actual native staging")
				}
				if metadata.DNS.Transport != map[string]string{"tcp": "tcp", "dot": "tls", "doh": "https"}[transport] {
					t.Fatal("saved DNS transport was reinterpreted")
				}
				raw, err := readDesktopRuntimeFile(prepared.Launch, "tor-profile.json", 4<<20)
				var staged common.RouterProfile
				if err != nil || json.Unmarshal(raw, &staged) != nil || !reflect.DeepEqual(staged, saved) {
					t.Fatal("shipping preparation lost exact credentials, policy, source or history", err)
				}
				config, err := readDesktopRuntimeFile(prepared.Launch, "sing-box.json", 4<<20)
				var graph map[string]any
				if err != nil || json.Unmarshal(config, &graph) != nil {
					t.Fatal("shipping Tor configuration unavailable", err)
				}
				inbounds := graph["inbounds"].([]any)
				if len(inbounds) != 1 || inbounds[0].(map[string]any)["mtu"] != float64(expectedMTU) || graph["dns"].(map[string]any)["strategy"] != "ipv4_only" {
					t.Fatal("saved device values did not reach the native TUN and resolver")
				}
				ipv6, lan := false, false
				for _, rawRule := range graph["route"].(map[string]any)["rules"].([]any) {
					rule := rawRule.(map[string]any)
					if rule["action"] == "reject" && rule["ip_version"] == float64(6) {
						ipv6 = true
					}
					prefixes, _ := rule["ip_cidr"].([]any)
					for _, prefix := range prefixes {
						lan = lan || rule["action"] == "reject" && prefix == "192.168.50.0/24"
					}
				}
				if !ipv6 || !lan || a.cmd != nil || a.state.Connected || prepared.Launch.command != nil {
					t.Fatal("device settings dropped network policy or invented runtime readiness")
				}
			})
		}
	}
}

func TestProfileDeviceTorUnresolvedHomeDoesNotAcquireResolverOrRuntime(t *testing.T) {
	a := deviceSettingsTestApp(t, "tor-bridge", false)
	profile := &a.profiles.Profiles[3]
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "home", "udp", "", 53
	q := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "manual")
	w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
	if w.Code != http.StatusOK {
		t.Fatalf("idle Home preference was not preserved: %d %s", w.Code, w.Body.String())
	}
	saved := a.profiles.Profiles[3]
	if saved.DNSMode != "home" || saved.DNSProtocol != "udp" || saved.DNSHost != "" || saved.DNSPort != 53 || a.cmd != nil || a.state.Connected {
		t.Fatal("idle device edit replaced Home DNS or claimed a connection")
	}
	root := t.TempDir()
	if _, err := stageDesktopTorInputs(root, saved, saved, installFakeExecutable(t, t.TempDir(), "tor"), installFakeExecutable(t, t.TempDir(), "native")); err == nil {
		t.Fatal("saved unresolved Home acquired a runnable Tor resolver")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("unresolved Home staged private runtime work", err)
	}
}

func TestProfileDeviceTorStrictPolicyUsesActualCapturedBridgePlan(t *testing.T) {
	plans := map[string][]string{
		"obfs4":     {clientTorBridge},
		"snowflake": {clientSnowflakeBridge},
		"webtunnel": {clientWebTunnelBridge},
		"multiple":  {clientTorBridge, strings.Replace(clientTorBridge, "203.0.113.44", "203.0.113.45", 1)},
	}
	for plan, bridges := range plans {
		for _, policy := range []string{"off", "on-connect", "always"} {
			t.Run(plan+"/"+policy, func(t *testing.T) {
				a := deviceSettingsTestApp(t, "tor-bridge", false)
				a.profiles.Profiles[3].External.TorBridge.Transport = "custom"
				a.profiles.Profiles[3].External.TorBridge.Bridges = append([]string(nil), bridges...)
				q := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "auto")
				q["kill_switch_policy"] = policy
				before := cloneRouterProfileStore(a.profiles)
				w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
				if plan != "obfs4" && policy != "off" {
					if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "one fixed obfs4 bridge") || !reflect.DeepEqual(before, a.profiles) {
						t.Fatalf("uncontrolled PT egress bypassed strict Tor policy: %d %s", w.Code, w.Body.String())
					}
				} else if w.Code != http.StatusOK || !reflect.DeepEqual(before.Profiles[3].External, a.profiles.Profiles[3].External) {
					t.Fatalf("supported captured plan or credentials were replaced: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestProfileDeviceTorUnsupportedGraphRemainsExplicit(t *testing.T) {
	for _, option := range []string{"Server Router-entry", "missing Router-entry", "external Router-entry", "padding"} {
		t.Run(option, func(t *testing.T) {
			a := deviceSettingsTestApp(t, "tor-bridge", option != "padding")
			a.profiles.Profiles[3].DAITAEnabled = option == "padding"
			switch option {
			case "Server Router-entry":
				a.profiles.Profiles[3].MultihopExecution = "server"
			case "missing Router-entry":
				a.profiles.Profiles[3].MultihopEntryID = "missing-router"
			case "external Router-entry":
				a.profiles.Profiles[1].NodeKind = "external"
				a.profiles.Profiles[1].External = &common.ExternalNodeConfig{Protocol: "socks5"}
			}
			before := cloneRouterProfileStore(a.profiles)
			capture := getDeviceSettingsForTest(t, a)
			label := "Router-entry"
			if option == "padding" {
				label = option
			}
			if capture.DevicePolicySupported || !strings.Contains(capture.DevicePolicyReason, label) {
				t.Fatal("unsupported saved Tor graph acquired common device capability")
			}
			q := deviceSettingsRequestForTest(t, capture, "auto")
			w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
			if w.Code != http.StatusUnprocessableEntity || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("common editor discarded an unsupported saved graph")
			}
		})
	}
}

func TestProfileDeviceTorNativeValidationCannotDiscardForeignPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*common.RouterProfile){
		"router owner":  func(p *common.RouterProfile) { p.APIToken = "another-router-secret" },
		"proof owner":   func(p *common.RouterProfile) { p.NodeProofID = "another-node" },
		"start layer":   func(p *common.RouterProfile) { p.StartLayer = "aes-256-gcm" },
		"bad bridge":    func(p *common.RouterProfile) { p.External.TorBridge.Bridges = []string{"not a bridge"} },
		"reserved port": func(p *common.RouterProfile) { p.External.TorBridge.SocksPort = 8788 },
		"fixed exit":    func(p *common.RouterProfile) { p.External.ExpectedPublicIP = "203.0.113.9" },
		"public UDP":    func(p *common.RouterProfile) { p.DNSProtocol = "udp" },
		"DNS hostname":  func(p *common.RouterProfile) { p.DNSHost = "dns.example.test" },
		"wrong LAN":     func(p *common.RouterProfile) { p.HomeLANCIDRs = []string{"10.0.0.0/7"} },
	} {
		t.Run(name, func(t *testing.T) {
			a := deviceSettingsTestApp(t, "tor-bridge", false)
			mutate(&a.profiles.Profiles[3])
			q := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "manual")
			q["home_lan_access"] = false
			before := cloneRouterProfileStore(a.profiles)
			w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, q)))
			if w.Code != http.StatusBadRequest || !reflect.DeepEqual(before, a.profiles) {
				t.Fatalf("native Tor policy was silently ignored: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestProfileDeviceTorCommitCapturesSourceAndRollsBack(t *testing.T) {
	for _, change := range []string{"bridge", "DNS", "selection", "connected", "cancelled", "persist", "measurement"} {
		t.Run(change, func(t *testing.T) {
			a := deviceSettingsTestApp(t, "tor-bridge", false)
			q := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "manual")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var changed common.RouterProfileStore
			reader := &startupSettingsMutationReader{Reader: bytes.NewReader(deviceSettingsBodyForTest(t, q)), mutate: func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				switch change {
				case "bridge":
					a.profiles.Profiles[3].External.TorBridge.Bridges[0] = clientSnowflakeBridge
				case "DNS":
					a.profiles.Profiles[3].DNSPort = 5443
				case "selection":
					a.profiles.SelectedID = "home"
				case "connected":
					a.state.Connected, a.state.Phase = true, "connected"
				case "cancelled":
					cancel()
				case "persist":
					a.cfg.ProfilesFile = t.TempDir()
				case "measurement":
					a.profiles.Profiles[3].EffectiveMTU, a.profiles.Profiles[3].EffectiveMTUSource = 1420, "new-owner-readback"
				}
				changed = cloneRouterProfileStore(a.profiles)
			}}
			w := httptest.NewRecorder()
			a.profileDeviceSettings(w, httptest.NewRequest(http.MethodPost, "/api/profile/device", reader).WithContext(ctx))
			if change == "measurement" {
				p := &changed.Profiles[3]
				p.HomeLANAccess, p.KillSwitchPolicy, p.KillSwitch, p.IPv6Mode = true, "on-connect", true, "on"
				p.MTUPolicy, p.ManualMTU = "manual", 1320
				if w.Code != http.StatusOK || !reflect.DeepEqual(changed, a.profiles) {
					t.Fatalf("saved Tor policy overwrote newer readback: %d %s", w.Code, w.Body.String())
				}
			} else if w.Code < 400 || !reflect.DeepEqual(changed, a.profiles) {
				t.Fatalf("failed or retired Tor policy edit changed source: %d", w.Code)
			}
		})
	}
}
