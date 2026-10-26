package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func assertSavedTorJumboPreparation(t *testing.T, profile common.RouterProfile, jumbo bool) {
	t.Helper()
	prepared, err := stageDesktopTorInputs(t.TempDir(), profile, profile,
		installFakeExecutable(t, t.TempDir(), "tor"), installFakeExecutable(t, t.TempDir(), "native"))
	if err != nil {
		t.Fatal("saved Jumbo policy failed actual Tor staging", err)
	}
	defer func() {
		if err := cleanupDesktopTorLaunch(prepared.Launch); err != nil {
			t.Error("Jumbo staging cleanup", err)
		}
		_ = prepared.Launch.directoryRoot.Close()
	}()
	wantMTU := 1280
	if jumbo || profile.MTUPolicy == "manual" {
		wantMTU = 9000
	}
	meta := prepared.Launch.tor.expected
	if meta.JumboTUN != jumbo || meta.ConfiguredMTU != wantMTU || meta.MTUPolicy != profile.MTUPolicy ||
		meta.KillSwitchPolicy != profile.KillSwitchPolicy || meta.DNS.Address != profile.DNSHost || meta.DNS.Port != profile.DNSPort {
		t.Fatal("saved Jumbo setting changed selected policy or was not captured", meta)
	}
	raw, err := readDesktopRuntimeFile(prepared.Launch, "sing-box.json", 4<<20)
	var config struct {
		Inbounds []struct {
			MTU int `json:"mtu"`
		} `json:"inbounds"`
	}
	if err != nil || json.Unmarshal(raw, &config) != nil || len(config.Inbounds) != 1 || config.Inbounds[0].MTU != wantMTU {
		t.Fatal("Jumbo setting did not reach the one captured TUN", err)
	}
	raw, err = readDesktopRuntimeFile(prepared.Launch, "tor-profile.json", 4<<20)
	var captured common.RouterProfile
	if err != nil || json.Unmarshal(raw, &captured) != nil || !reflect.DeepEqual(captured, profile) {
		t.Fatal("Jumbo staging substituted private node data", err)
	}
}

func TestProfileDeviceTorJumboSavedSelectionReachesActualNativePreparation(t *testing.T) {
	for _, policy := range []string{"auto", "default", "manual"} {
		t.Run(policy, func(t *testing.T) {
			a := deviceSettingsTestApp(t, "tor-bridge", false)
			before := cloneRouterProfileStore(a.profiles)
			capture := getDeviceSettingsForTest(t, a)
			if !capture.JumboTUNSupported || capture.JumboTUN {
				t.Fatal("Tor Jumbo capability does not match the saved selection")
			}
			request := deviceSettingsRequestForTest(t, capture, policy)
			request["jumbo_tun"] = true
			if policy == "manual" {
				request["manual_mtu"] = 9000
			}
			response := postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, request)))
			if response.Code != http.StatusOK {
				t.Fatal("Jumbo save failed", response.Code, response.Body.String())
			}
			expected := &before.Profiles[3]
			expected.HomeLANAccess, expected.KillSwitchPolicy, expected.KillSwitch, expected.IPv6Mode = true, "on-connect", true, "on"
			expected.MTUPolicy, expected.ManualMTU, expected.JumboTUN = policy, request["manual_mtu"].(int), true
			if !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("Jumbo changed credentials, history, startup, entry or DNS")
			}
			var confirmed profileDeviceSettings
			if json.Unmarshal(response.Body.Bytes(), &confirmed) != nil || !confirmed.JumboTUN || !confirmed.JumboTUNSupported ||
				confirmed.ProfileToken == capture.ProfileToken || !strings.Contains(confirmed.Note, "does not force 9000-byte packets") {
				t.Fatal("Jumbo response did not confirm captured interface capacity")
			}
			raw, err := os.ReadFile(a.cfg.ProfilesFile)
			var disk common.RouterProfileStore
			if err != nil || json.Unmarshal(raw, &disk) != nil || !disk.Profiles[3].JumboTUN || disk.Profiles[3].MTUPolicy != policy {
				t.Fatal("Jumbo save returned before durable policy", err)
			}
			assertSavedTorJumboPreparation(t, a.profiles.Profiles[3], true)

			// A narrower existing editor omits the optional field; it cannot
			// silently undo the saved interface choice while changing policy.
			retained := deviceSettingsRequestForTest(t, confirmed, policy)
			if policy == "manual" {
				retained["manual_mtu"] = 9000
			}
			response = postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, retained)))
			if response.Code != http.StatusOK || !a.profiles.Profiles[3].JumboTUN {
				t.Fatal("omitted Jumbo field discarded the captured value", response.Body.String())
			}
			retained["jumbo_tun"] = false
			response = postDeviceSettingsForTest(a, bytes.NewReader(deviceSettingsBodyForTest(t, retained)))
			if response.Code != http.StatusOK || a.profiles.Profiles[3].JumboTUN || a.profiles.Profiles[3].MTUPolicy != policy {
				t.Fatal("turning off Jumbo changed the saved MTU preference", response.Body.String())
			}
			assertSavedTorJumboPreparation(t, a.profiles.Profiles[3], false)
		})
	}
}

func TestProfileDeviceTorJumboRejectsConflictInvalidCapabilityAndStaleTransactions(t *testing.T) {
	for _, fault := range []string{"fixed-conflict", "null", "string", "number", "duplicate", "ordinary", "stale-jumbo", "new-credentials", "busy", "failed-write"} {
		t.Run(fault, func(t *testing.T) {
			protocol := "tor-bridge"
			if fault == "ordinary" {
				protocol = "shadowsocks"
			}
			a := deviceSettingsTestApp(t, protocol, false)
			capture := getDeviceSettingsForTest(t, a)
			request := deviceSettingsRequestForTest(t, capture, "auto")
			request["jumbo_tun"] = true
			switch fault {
			case "fixed-conflict":
				request["mtu_policy"], request["manual_mtu"] = "manual", 1400
			case "null":
				request["jumbo_tun"] = nil
			case "string":
				request["jumbo_tun"] = "true"
			case "number":
				request["jumbo_tun"] = 1
			case "stale-jumbo":
				a.profiles.Profiles[3].JumboTUN = true
			case "new-credentials":
				a.profiles.Profiles[3].External.TorBridge.Bridges = []string{strings.Replace(clientTorBridge, "203.0.113.44", "203.0.113.45", 1)}
			case "busy":
				a.state.Phase = "connecting"
			case "failed-write":
				a.cfg.ProfilesFile = t.TempDir()
			}
			before := cloneRouterProfileStore(a.profiles)
			body := deviceSettingsBodyForTest(t, request)
			if fault == "duplicate" {
				body = append([]byte(`{"jumbo_tun":false,`), body[1:]...)
			}
			response := postDeviceSettingsForTest(a, bytes.NewReader(body))
			if response.Code < 400 || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("Jumbo invalid/stale transaction rewrote captured state", response.Code, response.Body.String())
			}
			if fault == "ordinary" && capture.JumboTUNSupported {
				t.Fatal("Tor-only editor capability was granted to another native path")
			}
		})
	}
}

func TestDesktopTorJumboControllerRetainsConfiguredReaderWithoutMTURequests(t *testing.T) {
	a, launch, _ := desktopTorRunningFixture(t, "healthy", func(p *common.RouterProfile) {
		p.JumboTUN, p.MTUPolicy, p.ManualMTU = true, "auto", 0
		p.EffectiveMTU, p.EffectiveMTUSource = 1350, "historical-fixture"
	})
	a.cfg.ProfilesFile = filepath.Join(t.TempDir(), "profiles.json")
	a.state.Connected, a.state.Phase = true, "connected"
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	proof, err := a.waitDesktopTorProof(ctx, launch)
	if err != nil || !proof.Policy.JumboTUN || proof.EffectiveMTU != 9000 || proof.MTUReadback != nil {
		t.Fatal("Jumbo did not retain its configured initial reader", err)
	}
	a.mu.Lock()
	captureDesktopMTUBaselineLocked(a, launch)
	a.mu.Unlock()
	t.Cleanup(func() { mtuRetestLocks.Delete(a); mtuViewSlots.Delete(a); mtuSuspensions.Delete(a) })
	if _, err := a.runDesktopExternalMTU(ctx, launch, true); err == nil {
		t.Fatal("Jumbo admitted a measured Retest")
	}
	if _, err := captureDesktopMTUSnapshot(a, launch); err == nil {
		t.Fatal("Jumbo admitted automatic optimizer capture")
	}
	for _, name := range []string{"mtu-request.json", "mtu-commit.json", "mtu-cancel.json"} {
		if _, err := readDesktopRuntimeFile(launch, name, 8192); !os.IsNotExist(err) {
			t.Fatal("Jumbo created an unrequested MTU transaction", name, err)
		}
	}
	if after, err := a.readDesktopTorProof(launch); err != nil || after.EffectiveMTU != 9000 || desktopTorSavedMTU(t, a).EffectiveMTU != 1350 {
		t.Fatal("Jumbo readback rewrote historical measurements", err)
	}
}
