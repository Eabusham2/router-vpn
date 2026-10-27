package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobiletor"
)

var desktopTorOrdinaryTestProtocols = []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"}

func TestDesktopTorOrdinaryStartupLastAndCompleteSetupRetainExactEntry(t *testing.T) {
	for _, protocol := range desktopTorOrdinaryTestProtocols {
		t.Run(protocol, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			entry := desktopTorOrdinaryFixture(t, f, protocol)
			f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "last.json")
			f.a.mu.Lock()
			p := &f.a.profiles.Profiles[0]
			p.AutoConnect, p.StartupMode = true, "last"
			p.MultihopEnabled = false
			p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = "", "", ""
			profileID := p.ID
			f.a.mu.Unlock()
			response := f.request(t, externalProfileConnectRequest{ProfileID: profileID, EntryID: entry.ID, EntryMode: protocol, Base: "auto"})
			if response.Code != http.StatusOK {
				t.Fatal("explicit ordinary path could not be saved", response.Code, response.Body.String())
			}
			first := f.launch
			last, err := f.a.loadStartupSelection()
			if err != nil || last.External == nil || last.External.Direct || last.External.EntryID != entry.ID || last.External.EntryMode != protocol || last.External.EntryToken != startupExternalProfileToken(entry) {
				t.Fatal("Startup Last lost the ordinary source identity", err)
			}
			lastBytes, err := os.ReadFile(f.a.cfg.StateFile)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"bridges", "private_key", "api_token", "password", "certificate"} {
				if bytes.Contains(lastBytes, []byte(secret)) {
					t.Fatal("Startup Last copied credentials", secret)
				}
			}
			if err := f.a.stopModeWithIntent(true); err != nil {
				t.Fatal(err)
			}
			capture, err := f.a.captureStartupPolicy()
			if err != nil || capture == nil || capture.entryMode != protocol || capture.entryToken != startupProfileToken(entry) {
				t.Fatal("Startup Last did not capture the exact imported entry", err)
			}
			f.a.applyCapturedStartupPolicy(context.Background(), capture, externalConnectRuntime{tor: f.driver})
			f.a.mu.Lock()
			connected := f.a.state.Connected
			f.a.mu.Unlock()
			if !connected || f.launch == first || f.launch.tor.expected.SessionID == first.tor.expected.SessionID || f.launch.tor.expected.EntryMode != protocol || f.launch.tor.expected.EntryProofKind != mobiletor.ExternalPredecessorProofKind || f.launch.tor.expected.EntrySHA256 != first.tor.expected.EntrySHA256 {
				t.Fatal("Startup Last failed to freshly prove the exact ordinary path")
			}
			if err := f.a.stopModeWithIntent(true); err != nil {
				t.Fatal(err)
			}
			// Use the same setup route and disabled Router-only controls as all
			// three native complete-profile forms. The selected Tor node supplies
			// its actual saved graph, including the raw imported entry protocol.
			body := map[string]any{"name": "Ordinary entry to Tor", "mode": "external", "multihop_enabled": false}
			response = postSetup(t, f.a, "/api/connection-profile/setup/save", body)
			var saved struct {
				Profile   connectionProfileRecord `json:"profile"`
				EntryMode string                  `json:"multihop_entry_mode"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &saved) != nil || saved.Profile.External == nil || len(saved.Profile.Hops) != 1 || saved.Profile.Hops[0].External == nil || saved.EntryMode != protocol {
				t.Fatal("complete setup could not capture the ordinary Tor path", response.Code, response.Body.String())
			}
			meta, err := loadConnectionProfileSetupMeta(f.a)
			if err != nil || meta.Entries[saved.Profile.ID].MultihopEntryMode != protocol {
				t.Fatal("complete setup lost its exact raw entry metadata", err)
			}
			for _, path := range []string{connectionProfileStorePath(f.a), connectionProfileSetupMetaPath(f.a)} {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{"private_key", "api_token", "password", "bridges", "certificate", "effective_mtu"} {
					if bytes.Contains(raw, []byte(secret)) {
						t.Fatal("complete profile copied a private source or runtime measurement", secret)
					}
				}
			}
			f.a.mu.Lock()
			f.a.profiles.Profiles[0].DNSHost, f.a.profiles.Profiles[0].DNSPort = "1.0.0.1", 5354
			f.a.mu.Unlock()
			body["id"], body["name"] = saved.Profile.ID, "Updated ordinary Tor path"
			response = postSetup(t, f.a, "/api/connection-profile/setup/update", body)
			if response.Code != http.StatusOK {
				t.Fatal("complete setup Update failed", response.Code, response.Body.String())
			}
			f.a.mu.Lock()
			p = &f.a.profiles.Profiles[0]
			p.MultihopEnabled = false
			p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = "", "", ""
			p.DNSHost, p.DNSPort = "9.9.9.10", 53
			f.a.mu.Unlock()
			response = postSetup(t, f.a, "/api/connection-profile/setup/load", map[string]any{"id": saved.Profile.ID})
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"multihop_entry_mode":"`+protocol+`"`) {
				t.Fatal("complete setup Load lost its ordinary entry", response.Code, response.Body.String())
			}
			f.a.mu.Lock()
			loaded, loadedEntry := cloneRouterProfile(f.a.profiles.Profiles[0]), cloneRouterProfile(f.a.profiles.Profiles[1])
			connected = f.a.state.Connected
			f.a.mu.Unlock()
			if connected || !loaded.MultihopEnabled || loaded.MultihopEntryID != entry.ID || loaded.MultihopEntryMode != protocol || loaded.DNSHost != "1.0.0.1" || loaded.DNSPort != 5354 || !reflect.DeepEqual(loadedEntry.External, entry.External) || loadedEntry.DNSMode != entry.DNSMode {
				t.Fatal("complete Load changed private credentials or failed to restore exact policy")
			}
			response = f.request(t, externalProfileConnectRequest{ProfileID: profileID, Base: "auto"})
			if response.Code != http.StatusOK || f.launch.tor.expected.DNS.Address != "1.0.0.1" || f.launch.tor.expected.DNS.Port != 5354 || f.launch.tor.expected.EntryMode != protocol {
				t.Fatal("loaded complete profile did not reach the shipping native capture", response.Code, response.Body.String())
			}
			if err := f.a.stopModeWithIntent(true); err != nil {
				t.Fatal(err)
			}
			response = postSetup(t, f.a, "/api/connection-profile/setup/delete", map[string]any{"id": saved.Profile.ID})
			if response.Code != http.StatusOK {
				t.Fatal("complete setup Delete failed", response.Code, response.Body.String())
			}
		})
	}
}

func TestDesktopTorOrdinarySpeedLabRetainsCompiledSourceAndRestoresAfterCancel(t *testing.T) {
	for _, protocol := range desktopTorOrdinaryTestProtocols {
		t.Run(protocol, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			entry := desktopTorOrdinaryFixture(t, f, protocol)
			lookups := 0
			if protocol == "shadowsocks" {
				f.a.mu.Lock()
				entry.Endpoint, entry.External.Shadowsocks.Server = "entry.example.test", "entry.example.test"
				f.a.profiles.Profiles[1] = cloneRouterProfile(entry)
				f.a.mu.Unlock()
				f.driver.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
					lookups++
					if ctx.Err() != nil || host != entry.Endpoint || lookups != 1 {
						t.Fatal("retained restoration repeated or replaced its captured bootstrap")
					}
					return []netip.Addr{netip.MustParseAddr("198.51.100.40")}, nil
				}
			}
			previous := connectSpeedLabTorPrior(t, f, false)
			beforeDisk := desktopTorStoredProfile(t, f)
			oldDNS, _ := activeDNSRuntimeIdentities.Load(f.a)
			q := speedLabRequest{Scope: "temporary", Topology: "external", NodeID: previous.profileID, Base: "auto", Execution: "local"}
			_, snapshot, finish, err := f.a.beginSpeedLabTemporaryOperationExpected(&q)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			if snapshot.Plan.tor == nil || snapshot.Plan.request.EntryID != entry.ID || snapshot.Plan.request.EntryMode != protocol || snapshot.Plan.tor.selection.predecessor != previous.tor.predecessor {
				t.Fatal("temporary test lost its exact compiled ordinary restore path")
			}
			prepared, err := f.a.prepareSpeedLabExternalPathWithRuntime(q, nil, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.releaseUnused()
			q.preparedExternal = prepared
			if f.a.cmd != previous.command || desktopNodeProcessExited(previous) || prepared.tor.command.Process != nil {
				t.Fatal("temporary preparation stopped the prior ordinary path")
			}
			if current, _ := activeDNSRuntimeIdentities.Load(f.a); current != oldDNS {
				t.Fatal("temporary preparation replaced the prior DNS owner")
			}
			if err := f.a.speedLabSuspendPrevious(snapshot, false); err != nil {
				t.Fatal(err)
			}
			path, err := f.a.startSpeedLabTemporaryPath(q)
			if err != nil || path.EntryID != "" || path.EntryMode != "" || path.Execution != "local" {
				t.Fatal("Speed Lab did not honor explicit Direct over the saved ordinary entry", path, err)
			}
			trial := f.launch
			identity, _, err := captureSpeedLabIdentity(f.a)
			if err != nil || identity.TorEntry != nil {
				t.Fatal("temporary measurement borrowed the prior ordinary entry", err)
			}
			if err := verifySpeedLabPath(context.Background(), f.a, identity); err != nil {
				t.Fatal(err)
			}
			snapshot.Owner.cancelTest()
			err = f.a.speedLabRestoreWith(snapshot, speedLabRestoreActions{stop: f.a.speedLabStopRuntime, persist: f.a.speedLabWriteStore, network: physicalNetworkIdentity,
				restart: func(plan speedLabRestorePlan) error { return f.a.speedLabRestartPlanWithTorRuntime(plan, f.driver) },
			})
			if err != nil {
				t.Fatal("cancelled temporary test failed to restore the exact ordinary path", err)
			}
			restored := f.launch
			if restored == previous || restored == trial || restored.tor.predecessor != previous.tor.predecessor || restored.tor.expected.EntryMode != protocol || restored.tor.expected.EntryProofKind != mobiletor.ExternalPredecessorProofKind || restored.tor.expected.EntrySHA256 != previous.tor.expected.EntrySHA256 || restored.tor.expected.DNS != previous.tor.expected.DNS || restored.tor.expected.SessionID == previous.tor.expected.SessionID || !desktopNodeProcessExited(previous) || !desktopNodeProcessExited(trial) {
				t.Fatal("restore substituted source, DNS, proof kind or native lifetime")
			}
			f.a.mu.Lock()
			store, connected := cloneRouterProfileStore(f.a.profiles), f.a.state.Connected
			f.a.mu.Unlock()
			if !connected || !reflect.DeepEqual(store, snapshot.Profiles) || !snapshot.Owner.restored || !bytes.Equal(beforeDisk, desktopTorStoredProfile(t, f)) {
				t.Fatal("temporary Speed Lab changed the saved ordinary path or credentials")
			}
		})
	}
}

func TestDesktopTorOrdinarySavedMetadataCannotGrantRouterModeOrReplaceCapture(t *testing.T) {
	f := newDesktopTorConnectFixture(t)
	desktopTorOrdinaryFixture(t, f, "socks5")
	response := postSetup(t, f.a, "/api/connection-profile/setup/save", map[string]any{"name": "Exact ordinary entry", "mode": "external"})
	var saved struct {
		Profile connectionProfileRecord `json:"profile"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &saved) != nil {
		t.Fatal(response.Code, response.Body.String())
	}
	meta, err := loadConnectionProfileSetupMeta(f.a)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(f.a.cfg.ProfilesFile)
	if err != nil {
		// Save captures the existing store without changing selected policy.
		if err := f.a.persistProfiles(); err != nil {
			t.Fatal(err)
		}
		before = desktopTorStoredProfile(t, f)
	}
	for _, mode := range []string{"http-connect", "wg", "SOCKS5", " socks5", "unknown"} {
		meta.Entries[saved.Profile.ID] = connectionProfileSetupMeta{MultihopEntryMode: mode, MultihopExecution: "local"}
		if err := persistConnectionProfileSetupMeta(f.a, meta); err != nil {
			t.Fatal(err)
		}
		response := postSetup(t, f.a, "/api/connection-profile/setup/load", map[string]any{"id": saved.Profile.ID})
		if response.Code == http.StatusOK || !bytes.Equal(before, desktopTorStoredProfile(t, f)) {
			t.Fatal("foreign/invalid mirror changed complete profile authority", mode)
		}
	}
	for _, mode := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "openvpn"} {
		if _, err := normalizeConnectionProfileEntryMode(mode); err == nil {
			t.Fatal("ordinary Tor metadata broadened Router entry selection", mode)
		}
		captured := *saved.Profile.External
		captured.Protocol = "shadowsocks"
		captured.ExpectedPublicIP = "203.0.113.5"
		captured.MultihopEntryMode = mode
		if err := captured.validate(); err == nil {
			t.Fatal("non-Tor external profile borrowed ordinary Tor-only entry mode", mode)
		}
	}
}

func TestDesktopTorOrdinaryDeviceAndBridgeEditsReachTheCapturedNativePath(t *testing.T) {
	for _, protocol := range desktopTorOrdinaryTestProtocols {
		t.Run(protocol, func(t *testing.T) {
			f := newDesktopTorConnectFixture(t)
			entry := desktopTorOrdinaryFixture(t, f, protocol)
			capture := getDeviceSettingsForTest(t, f.a)
			if !capture.DevicePolicySupported {
				t.Fatal("ordinary Tor path lost common device settings", capture.DevicePolicyReason)
			}
			request := deviceSettingsRequestForTest(t, capture, "manual")
			request["kill_switch_policy"], request["manual_mtu"] = "off", 1280
			request["home_lan_access"], request["ipv6_mode"] = false, "off"
			response := postDeviceSettingsForTest(f.a, bytes.NewReader(deviceSettingsBodyForTest(t, request)))
			if response.Code != http.StatusOK || !reflect.DeepEqual(entry, f.a.profiles.Profiles[1]) {
				t.Fatal("ordinary device edit changed its independent predecessor", response.Code, response.Body.String())
			}
			saved := cloneRouterProfile(f.a.profiles.Profiles[0])
			bridge := strings.Replace(saved.External.TorBridge.Bridges[0], "203.0.113.44", "203.0.113.45", 1)
			if bridge == saved.External.TorBridge.Bridges[0] {
				t.Fatal("bridge update fixture did not change its relay")
			}
			update := map[string]any{
				"id": saved.ID, "transport": "obfs4", "bridges": []string{bridge},
				"expected_selected_node_id": saved.ID,
				"expected_profile_tokens":   map[string]string{saved.ID: publicProfileToken(saved), entry.ID: publicProfileToken(entry)},
			}
			response = postTorBridgeUpdate(f.a, torBridgeUpdateBody(t, update))
			if response.Code != http.StatusOK || !reflect.DeepEqual(entry, f.a.profiles.Profiles[1]) {
				t.Fatal("ordinary bridge update lost its captured entry", response.Code, response.Body.String())
			}
			updated := f.a.profiles.Profiles[0]
			if updated.MultihopEntryID != entry.ID || updated.MultihopEntryMode != protocol || !updated.MultihopEnabled ||
				updated.MultihopExitID != saved.ID || updated.MultihopExecution != "local" || updated.KillSwitchPolicy != "off" ||
				updated.DNSHost != saved.DNSHost || updated.DNSPort != saved.DNSPort || updated.IPv6Mode != "off" ||
				updated.HomeLANAccess || updated.MTUPolicy != "manual" || updated.ManualMTU != 1280 ||
				updated.External.TorBridge.Bridges[0] != bridge || f.a.cmd != nil || f.a.state.Connected {
				t.Fatal("idle ordinary edits substituted the saved path or invented runtime readiness")
			}
			response = f.request(t, externalProfileConnectRequest{ProfileID: saved.ID, Base: "auto"})
			if response.Code != http.StatusOK || f.launch.tor.expected.EntryMode != protocol ||
				f.launch.tor.expected.EntryProofKind != mobiletor.ExternalPredecessorProofKind ||
				f.launch.tor.expected.HomeLANAccess || f.launch.tor.expected.IPv6Mode != "off" {
				t.Fatal("idle ordinary edits did not reach native capture and proof", response.Code, response.Body.String())
			}
			if err := f.a.stopModeWithIntent(true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopTorOrdinaryIdleEditsRejectBorrowedProtectionAndRetiredSources(t *testing.T) {
	for _, route := range []string{"device", "bridge"} {
		for _, fault := range []string{"strict", "relinked"} {
			t.Run(route+"/"+fault, func(t *testing.T) {
				f := newDesktopTorConnectFixture(t)
				entry := desktopTorOrdinaryFixture(t, f, "shadowsocks")
				profile := cloneRouterProfile(f.a.profiles.Profiles[0])
				device := deviceSettingsRequestForTest(t, getDeviceSettingsForTest(t, f.a), "manual")
				device["kill_switch_policy"], device["manual_mtu"] = "off", 1280
				bridge := map[string]any{
					"id": profile.ID, "transport": "obfs4", "bridges": profile.External.TorBridge.Bridges,
					"expected_selected_node_id": profile.ID,
					"expected_profile_tokens":   map[string]string{profile.ID: publicProfileToken(profile), entry.ID: publicProfileToken(entry)},
				}
				if fault == "strict" {
					device["kill_switch_policy"], bridge["kill_switch_policy"] = "always", "always"
				} else {
					f.a.profiles.Profiles[1].External.Shadowsocks.Password = testWGKey('z')
				}
				before := cloneRouterProfileStore(f.a.profiles)
				var response *httptest.ResponseRecorder
				if route == "device" {
					response = postDeviceSettingsForTest(f.a, bytes.NewReader(deviceSettingsBodyForTest(t, device)))
				} else {
					response = postTorBridgeUpdate(f.a, torBridgeUpdateBody(t, bridge))
				}
				if response.Code == http.StatusOK || !reflect.DeepEqual(before, f.a.profiles) || f.a.cmd != nil || f.a.state.Connected {
					t.Fatal("ordinary edit borrowed Router authority or a replacement source", response.Code, response.Body.String())
				}
			})
		}
	}
}
