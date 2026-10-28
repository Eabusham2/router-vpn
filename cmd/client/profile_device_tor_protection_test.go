package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestTorBridgeCapabilitySeparatesDirectAndRouterProtection(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	for _, row := range torBridgeTransportCapabilities() {
		if !row.StrictRouterEntryKillSwitch || !row.StrictExternalEntryKillSwitch || row.StrictKillSwitch != (row.ID == "obfs4" || row.ID == "custom") {
			t.Fatal("capability conflated protected predecessors and dynamic Direct paths", row)
		}
	}
	w := httptest.NewRecorder()
	a := &app{}
	a.torBridgeCapabilities(w, httptest.NewRequest(http.MethodGet, "/api/tor-bridge/capabilities", nil))
	var response map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil ||
		response["router_entry_strict_kill_switch"] != false || response["external_entry_strict_kill_switch"] != false || response["supported"] != false {
		t.Fatal("unverified runtime advertised executable Router protection", w.Code, w.Body.String())
	}
}

func TestProfileDeviceTorRouterStrictPolicyReachesCapturedNativeGraph(t *testing.T) {
	plans := map[string][]string{
		"obfs4":     {clientTorBridge},
		"meek":      {"meek_lite 192.0.2.2:2 url=https://bridge.example/ front=front.example"},
		"snowflake": {clientSnowflakeBridge},
		"webtunnel": {clientWebTunnelBridge},
		"mixed":     {clientTorBridge, clientSnowflakeBridge, clientWebTunnelBridge},
	}
	for name, bridges := range plans {
		for _, kill := range []string{"on-connect", "always"} {
			t.Run(name+"/"+kill, func(t *testing.T) {
				a, profile, _ := desktopTorEntryFixture(t, "198.51.100.8")
				profile.External.TorBridge.Transport, profile.External.TorBridge.Bridges = "custom", append([]string(nil), bridges...)
				a.profiles.Profiles[0] = profile
				beforeEntry := cloneRouterProfile(a.profiles.Profiles[1])
				capture := getDeviceSettingsForTest(t, a)
				if !capture.DevicePolicySupported || capture.DevicePolicyReason != "" {
					t.Fatal("actual device API rejected the owned Router-entry policy", capture)
				}
				request := deviceSettingsRequestForTest(t, capture, "manual")
				request["kill_switch_policy"], request["manual_mtu"] = kill, 1280
				request["home_lan_access"], request["ipv6_mode"] = false, "off"
				w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, request)))
				if w.Code != http.StatusOK {
					t.Fatalf("actual protected Router device edit: %d %s", w.Code, w.Body.String())
				}
				saved := a.profiles.Profiles[0]
				if !reflect.DeepEqual(beforeEntry, a.profiles.Profiles[1]) || !reflect.DeepEqual(profile.External, saved.External) ||
					saved.MultihopEntryID != profile.MultihopEntryID || saved.MultihopEntryMode != profile.MultihopEntryMode || saved.MultihopExecution != "local" {
					t.Fatal("device edit copied credentials or substituted the selected path")
				}
				selection, err := captureDesktopTorSelection(a, saved, externalProfileConnectRequest{ProfileID: saved.ID}, nil)
				if err != nil {
					t.Fatal("saved protection did not reach shipping selection", err)
				}
				prepared, err := stageDesktopTorInputsWithPredecessor(t.TempDir(), selection.policy, selection.profile,
					installFakeExecutable(t, t.TempDir(), "tor"), installFakeExecutable(t, t.TempDir(), "native"), selection.predecessor)
				if err != nil {
					t.Fatal("saved protection did not reach actual native staging", err)
				}
				defer func() { _ = cleanupDesktopTorLaunch(prepared.Launch); _ = prepared.Launch.directoryRoot.Close() }()
				meta := prepared.Launch.tor.expected
				if meta.KillSwitchPolicy != kill || meta.EntryID != beforeEntry.ID || meta.EntrySHA256 == "" || meta.HomeLANAccess || meta.IPv6Mode != "off" {
					t.Fatal("native staged protection or source identity changed", meta)
				}
				env, err := desktopTorLaunchEnvironment(nil, clientRoot(a), prepared)
				if err != nil {
					t.Fatal(err)
				}
				values := map[string]string{}
				for _, item := range env {
					key, value, _ := strings.Cut(item, "=")
					values[key] = value
				}
				want, err := mobilemultihop.NodePhysicalEgress(selection.predecessor.mode, selection.predecessor.native.Profile(), selection.predecessor.native.Config())
				var got []mobilemultihop.PhysicalEgress
				if err != nil || json.Unmarshal([]byte(values["HOMEVPN_NATIVE_EGRESS_JSON"]), &got) != nil || !reflect.DeepEqual(got, want) ||
					values["HOMEVPN_PROFILE_ID"] != beforeEntry.ID || values["HOMEVPN_POLICY_PROFILE_ID"] != saved.ID {
					t.Fatal("dynamic bridge widened or replaced the exact physical firewall tuples", err)
				}
				if a.cmd != nil || a.state.Connected || prepared.Launch.command != nil {
					t.Fatal("settings or staging invented connection proof")
				}
			})
		}
	}
}

func TestProfileDeviceTorRouterStrictEditRejectsRelinkedEntry(t *testing.T) {
	for _, change := range []string{"credentials", "missing", "replaced-kind"} {
		t.Run(change, func(t *testing.T) {
			a, profile, _ := desktopTorEntryFixture(t, "198.51.100.8")
			profile.External.TorBridge.Transport, profile.External.TorBridge.Bridges = "snowflake", []string{clientSnowflakeBridge}
			a.profiles.Profiles[0] = profile
			request := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, a), "auto")
			request["kill_switch_policy"] = "always"
			switch change {
			case "credentials":
				a.profiles.Profiles[1].APIToken = "relinked-entry-credential"
			case "missing":
				a.profiles.Profiles = a.profiles.Profiles[:1]
			case "replaced-kind":
				a.profiles.Profiles[1].NodeKind = "external"
				a.profiles.Profiles[1].External = &common.ExternalNodeConfig{Protocol: "socks5"}
			}
			before := cloneRouterProfileStore(a.profiles)
			w := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, request)))
			if w.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("stale Router-entry editor installed policy after relink", w.Code, w.Body.String())
			}
		})
	}
}
