package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

func profileDeviceTorCoverApp(t *testing.T, protocol string) *app {
	t.Helper()
	a, _, _ := desktopTorEntryFixture(t, "198.51.100.8")
	p := &a.profiles.Profiles[0]
	p.MultihopExecution = "server"
	if protocol == "tor" {
		p.External = &common.ExternalNodeConfig{Protocol: "tor"}
	}
	return a
}

func profileDeviceTorCoverRequest(t *testing.T, capture profileDeviceSettings) map[string]any {
	t.Helper()
	return map[string]any{
		"profile_id": capture.ProfileID, "profile_token": capture.ProfileToken,
		"home_lan_access": capture.HomeLANAccess, "kill_switch_policy": capture.KillSwitchPolicy,
		"ipv6_mode": capture.IPv6Mode, "mtu_policy": capture.MTUPolicy, "manual_mtu": capture.ManualMTU,
	}
}

func TestProfileDeviceTorCoverSavedPairReachesServerCompiler(t *testing.T) {
	for _, protocol := range []string{"tor", "tor-bridge"} {
		for _, enabled := range []bool{false, true} {
			for _, rate := range []int{0, 32, 64, 192} {
				t.Run(protocol+"/"+strconv.FormatBool(enabled)+"/"+strconv.Itoa(rate), func(t *testing.T) {
					a := profileDeviceTorCoverApp(t, protocol)
					capture := getDeviceSettingsForTest(t, a)
					if !capture.DevicePolicySupported || !capture.TorCoverSupported || !strings.Contains(capture.TorCoverNote, "not bidirectional DAITA") || !strings.Contains(capture.TorCoverNote, "fresh cover receipt") {
						t.Fatal("cover settings did not disclose the actual Server preference boundary")
					}
					request := profileDeviceTorCoverRequest(t, capture)
					request["daita_enabled"], request["daita_rate_kbps"] = enabled, rate
					before := cloneRouterProfileStore(a.profiles)
					response := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, request)))
					if response.Code != http.StatusOK {
						t.Fatal("saved cover pair rejected", response.Code, response.Body.String())
					}
					expected := &before.Profiles[0]
					expected.DAITAEnabled, expected.DAITARateKbps = enabled, rate
					expected.KillSwitchPolicy, expected.KillSwitch = capture.KillSwitchPolicy, capture.KillSwitchPolicy != "off"
					expected.IPv6Mode, expected.MTUPolicy, expected.ManualMTU = capture.IPv6Mode, capture.MTUPolicy, capture.ManualMTU
					if !reflect.DeepEqual(before, a.profiles) {
						t.Fatal("cover edit changed the entry, credentials, DNS, graph, MTU or history")
					}
					var confirmed profileDeviceSettings
					if json.Unmarshal(response.Body.Bytes(), &confirmed) != nil || confirmed.DAITAEnabled != enabled || confirmed.DAITARateKbps != rate || !confirmed.TorCoverSupported {
						t.Fatal("cover edit response did not confirm the exact pair")
					}
					raw, err := os.ReadFile(a.cfg.ProfilesFile)
					var disk common.RouterProfileStore
					if err != nil || json.Unmarshal(raw, &disk) != nil || disk.Profiles[0].DAITAEnabled != enabled || disk.Profiles[0].DAITARateKbps != rate {
						t.Fatal("cover response preceded durable exact preference", err)
					}
					profile := a.profiles.Profiles[0]
					entry, err := captureDesktopTorPredecessor(a, profile, nil)
					if err != nil {
						t.Fatal(err)
					}
					prepared, err := stageDesktopTorInputsWithPredecessor(clientRoot(a), profile, profile, "", installFakeExecutable(t, t.TempDir(), "native"), entry)
					if err != nil {
						t.Fatal("saved cover did not reach actual Server compilation", err)
					}
					t.Cleanup(func() { _ = cleanupDesktopTorLaunch(prepared.Launch); _ = prepared.Launch.directoryRoot.Close() })
					source, err := readDesktopRuntimeFile(prepared.Launch, "tor-profile.json", 4<<20)
					if err != nil {
						t.Fatal(err)
					}
					captured, err := readDesktopRuntimeFile(prepared.Launch, "tor-capture.json", 4<<20)
					if err != nil {
						t.Fatal(err)
					}
					input, err := mobiletor.DecodeDesktopBridgeCapture(string(source), string(captured), prepared.Launch.directory)
					wantRate := rate
					if enabled && wantRate == 0 {
						wantRate = mobiletor.PaddingDefaultRateKbps
					}
					if err != nil || input.Policy().ServerPolicy().Padding() != (mobiletor.TorPaddingPolicy{Enabled: enabled, RateKbps: wantRate}) || a.cmd != nil || a.state.Connected || prepared.Launch.command != nil {
						t.Fatal("Server compiler substituted requested cover or fabricated runtime proof", err)
					}
					// Older/narrow editors omit both fields and retain the saved pair.
					omitted := profileDeviceTorCoverRequest(t, confirmed)
					response = postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, omitted)))
					if response.Code != http.StatusOK || a.profiles.Profiles[0].DAITAEnabled != enabled || a.profiles.Profiles[0].DAITARateKbps != rate {
						t.Fatal("unrelated device edit discarded saved cover", response.Code, response.Body.String())
					}
					// Off retains the exact dormant budget, including explicit zero.
					omitted["daita_enabled"], omitted["daita_rate_kbps"] = false, rate
					response = postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, omitted)))
					if response.Code != http.StatusOK || a.profiles.Profiles[0].DAITAEnabled || a.profiles.Profiles[0].DAITARateKbps != rate {
						t.Fatal("turning cover Off reset the saved budget", response.Code, response.Body.String())
					}
				})
			}
		}
	}
}

func TestProfileDeviceTorCoverRejectsInvalidPairAndChangedOwner(t *testing.T) {
	for _, fault := range []string{"flag-null", "flag-string", "rate-null", "rate-string", "rate-bool", "rate-fraction", "rate-low", "rate-high", "rate-negative", "missing-flag", "missing-rate", "duplicate", "local", "direct", "ordinary-entry", "missing-entry", "stale-entry", "stale-rate", "selected", "busy", "failed-write"} {
		t.Run(fault, func(t *testing.T) {
			a := profileDeviceTorCoverApp(t, "tor")
			capture := getDeviceSettingsForTest(t, a)
			request := profileDeviceTorCoverRequest(t, capture)
			request["daita_enabled"], request["daita_rate_kbps"] = true, 64
			switch fault {
			case "flag-null":
				request["daita_enabled"] = nil
			case "flag-string":
				request["daita_enabled"] = "true"
			case "rate-null":
				request["daita_rate_kbps"] = nil
			case "rate-string":
				request["daita_rate_kbps"] = "64"
			case "rate-bool":
				request["daita_rate_kbps"] = true
			case "rate-fraction":
				request["daita_rate_kbps"] = 64.5
			case "rate-low":
				request["daita_rate_kbps"] = 31
			case "rate-high":
				request["daita_rate_kbps"] = 193
			case "rate-negative":
				request["daita_rate_kbps"] = -1
			case "missing-flag":
				delete(request, "daita_enabled")
			case "missing-rate":
				delete(request, "daita_rate_kbps")
			case "local":
				a.profiles.Profiles[0].MultihopExecution = "local"
			case "direct":
				a.profiles.Profiles[0].MultihopEnabled = false
			case "ordinary-entry":
				a.profiles.Profiles[1].NodeKind = "external"
				a.profiles.Profiles[1].External = &common.ExternalNodeConfig{Protocol: "socks5"}
			case "missing-entry":
				a.profiles.Profiles[0].MultihopEntryID = "missing"
			case "stale-entry":
				a.profiles.Profiles[1].APIToken = "relinked-private-owner"
			case "stale-rate":
				a.profiles.Profiles[0].DAITARateKbps = 192
			case "selected":
				a.profiles.SelectedID = a.profiles.Profiles[1].ID
			case "busy":
				a.state.Phase = "connecting"
			case "failed-write":
				a.cfg.ProfilesFile = t.TempDir()
			}
			if fault == "local" || fault == "direct" || fault == "ordinary-entry" || fault == "missing-entry" {
				current := getDeviceSettingsForTest(t, a)
				if current.TorCoverSupported {
					t.Fatal("unsupported cover path acquired editor capability")
				}
				request["profile_token"] = current.ProfileToken
			}
			before := cloneRouterProfileStore(a.profiles)
			raw := deviceSettingsBodyForTest(t, request)
			if fault == "duplicate" {
				raw = append([]byte(`{"daita_enabled":false,`), raw[1:]...)
			}
			response := postDeviceSettingsForTest(a, bytes.NewReader(raw))
			if response.Code < 400 || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("invalid cover edit changed captured state", response.Code, response.Body.String())
			}
		})
	}
}

func TestProfileDeviceTorCoverDormantLocalPreferenceRemainsCaptured(t *testing.T) {
	a := profileDeviceTorCoverApp(t, "tor")
	p := &a.profiles.Profiles[0]
	p.MultihopExecution, p.DAITAEnabled, p.DAITARateKbps = "local", false, 64
	capture := getDeviceSettingsForTest(t, a)
	if !capture.DevicePolicySupported || capture.TorCoverSupported || capture.DAITAEnabled || capture.DAITARateKbps != 64 {
		t.Fatal("dormant Local cover preference was lost or advertised as supported")
	}
	response := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, profileDeviceTorCoverRequest(t, capture))))
	if response.Code != http.StatusOK || a.profiles.Profiles[0].DAITAEnabled || a.profiles.Profiles[0].DAITARateKbps != 64 {
		t.Fatal("Local device edit reset dormant cover", response.Code, response.Body.String())
	}
	request := profileDeviceTorCoverRequest(t, getDeviceSettingsForTest(t, a))
	request["daita_enabled"], request["daita_rate_kbps"] = false, 64
	response = postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, request)))
	if response.Code != http.StatusOK || a.profiles.Profiles[0].DAITARateKbps != 64 {
		t.Fatal("unchanged unsupported cover pair was not preserved", response.Code, response.Body.String())
	}
	before := cloneRouterProfileStore(a.profiles)
	request["daita_rate_kbps"] = 32
	response = postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, request)))
	if response.Code < 400 || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("unsupported Local path changed the dormant cover budget", response.Code, response.Body.String())
	}
}
