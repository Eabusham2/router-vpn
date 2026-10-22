package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func externalConnectionTestNode(t *testing.T, protocol string) common.RouterProfile {
	t.Helper()
	var p common.RouterProfile
	var err error
	switch protocol {
	case "amneziawg":
		p = desktopAWGProfile(t)
	case "tor-bridge":
		p = common.RouterProfile{NodeKind: "external", External: &common.ExternalNodeConfig{Protocol: "tor-bridge", TorBridge: &common.ExternalTorBridgeConfig{Bridges: []string{externalTestTorBridge}}}}
	case "openvpn":
		p = common.RouterProfile{NodeKind: "external", External: &common.ExternalNodeConfig{Protocol: "openvpn", ExpectedPublicIP: "203.0.113.90", OpenVPN: &common.ExternalOpenVPNConfig{Config: "client\ndev tun\nproto tcp-client\nremote vpn.example.test 443\nremote-cert-tls server\n", Username: "private-ovpn-user", Password: "private-ovpn-password"}}}
	default:
		p, err = externalProfileFromCreateRequest(createRequestFor(protocol))
		if err != nil {
			t.Fatal(err)
		}
	}
	p.ID, p.Name = "external", "Saved external"
	p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "custom", "tcp", "9.9.9.9", 5353
	p.DNSServerName, p.DNSPath = "", ""
	p.HomeLANAccess = false
	p.HomeLANCIDRs = []string{"192.168.50.0/24"}
	p.KillSwitchPolicy, p.IPv6Mode, p.StartupMode = "always", "off", "manual"
	p.MTUPolicy, p.ManualMTU = "manual", 1380
	p.EffectiveMTU, p.EffectiveMTUSource = 1280, "historical-other-path"
	if err := common.NormalizeRouterProfile(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func externalConnectionTestApp(t *testing.T, protocol string, multihop bool) *app {
	t.Helper()
	a := setupProfileTestApp(t)
	p := externalConnectionTestNode(t, protocol)
	if multihop {
		p.MultihopEnabled = true
		p.MultihopEntryID = "entry"
		p.MultihopExitID = p.ID
	}
	a.profiles.Profiles[3] = p
	a.profiles.SelectedID = p.ID
	a.state.RouterID = p.ID
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	return a
}

func savedExternalConnectionID(t *testing.T, a *app) string {
	t.Helper()
	response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Complete external", "mode": "smart-auto", "multihop_enabled": false})
	if response.Code != http.StatusOK {
		t.Fatalf("save status=%d: %s", response.Code, response.Body.String())
	}
	var result struct {
		Profile connectionProfileRecord `json:"profile"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.Profile.ID
}

func TestExternalConnectionProfileCRUDRestoresActualPolicyWithoutCopyingCredentials(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn", "tor-bridge"} {
		t.Run(protocol, func(t *testing.T) {
			a := externalConnectionTestApp(t, protocol, false)
			original := cloneRouterProfile(a.profiles.Profiles[3])
			id := savedExternalConnectionID(t, a)
			store, err := loadConnectionProfileStore(a)
			if err != nil {
				t.Fatal(err)
			}
			if len(store.Profiles) != 1 || store.Profiles[0].External == nil || store.Profiles[0].Prefs != nil || store.Profiles[0].Mode != "external" {
				t.Fatalf("missing complete external policy: %+v", store)
			}
			raw, err := os.ReadFile(connectionProfileStorePath(a))
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"private_key", "api_token", "password", "ss-secret", "hy-secret", "proxy-secret", "private-ovpn", "bridges", "effective_mtu", "historical-other-path"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("profile copied private/runtime field %q", secret)
				}
			}
			// Changing the linked node's policy does not change which credentials
			// the saved profile references or restore an old runtime measurement.
			a.profiles.Profiles[3].DNSMode = "rescue"
			a.profiles.Profiles[3].DNSHost = "1.1.1.1"
			a.profiles.Profiles[3].MTUPolicy = "auto"
			a.profiles.Profiles[3].ManualMTU = 0
			a.profiles.Profiles[3].HomeLANAccess = true
			a.profiles.Profiles[3].HomeLANCIDRs = nil
			a.profiles.Profiles[3].KillSwitchPolicy = "off"
			a.profiles.Profiles[3].IPv6Mode = "on"
			a.profiles.SelectedID = "home"
			a.state.RouterID = "home"
			loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if loaded.Code != http.StatusOK {
				t.Fatalf("load status=%d: %s", loaded.Code, loaded.Body.String())
			}
			got := a.profiles.Profiles[3]
			capture, err := snapshotExternalConnectionPolicy(got)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(capture, store.Profiles[0].External) {
				t.Fatalf("policy changed on load: got=%+v want=%+v", capture, store.Profiles[0].External)
			}
			if !reflect.DeepEqual(got.External, original.External) || got.EffectiveMTU != 1280 || a.state.Connected || a.profiles.SelectedID != original.ID {
				t.Fatal("load changed credentials/runtime evidence or connected instead of selecting")
			}
			a.profiles.Profiles[3].DNSPort = 5354
			updated := postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": id, "name": "Updated external", "mode": "external", "multihop_enabled": false})
			if updated.Code != 200 {
				t.Fatal(updated.Body.String())
			}
			store, err = loadConnectionProfileStore(a)
			if err != nil || store.Profiles[0].External.DNSPort != 5354 {
				t.Fatalf("update lost policy: %v", err)
			}
			deleted := postSetup(t, a, "/api/connection-profile/setup/delete", map[string]any{"id": id})
			if deleted.Code != 200 {
				t.Fatal(deleted.Body.String())
			}
			store, err = loadConnectionProfileStore(a)
			if err != nil || len(store.Profiles) != 0 || !reflect.DeepEqual(a.profiles.Profiles[3].External, original.External) {
				t.Fatal("delete affected linked credentials")
			}
		})
	}
}

func TestExternalConnectionProfileRestoresCapturedEntryAndRejectsChangedIdentity(t *testing.T) {
	a := externalConnectionTestApp(t, "socks5", true)
	a.profiles.Profiles[1].HomeLANAccess = true
	a.profiles.Profiles[1].IPv6Mode = "off"
	a.profiles.Profiles[1].KillSwitchPolicy = "always"
	id := savedExternalConnectionID(t, a)
	a.profiles.Profiles[1].IPv6Mode = "on"
	a.profiles.Profiles[1].KillSwitchPolicy = "off"
	a.profiles.Profiles[3].MultihopEnabled = false
	a.profiles.Profiles[3].MultihopEntryID = ""
	a.profiles.Profiles[3].MultihopExitID = ""
	loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if loaded.Code != 200 {
		t.Fatal(loaded.Body.String())
	}
	if a.profiles.Profiles[1].IPv6Mode != "off" || a.profiles.Profiles[1].KillSwitchPolicy != "always" || !a.profiles.Profiles[3].MultihopEnabled || a.profiles.Profiles[3].MultihopEntryID != "entry" {
		t.Fatal("whole path policy was not restored")
	}
	var response map[string]any
	_ = json.Unmarshal(loaded.Body.Bytes(), &response)
	if response["multihop_execution"] != "local" || response["multihop_exit_mode"] != "socks5" || response["multihop_entry_id"] != "entry" {
		t.Fatal("native loaded path response lost the external capture")
	}
	a.profiles.Profiles[1].NodeProofID = strings.Repeat("e", 64)
	before := cloneRouterProfileStore(a.profiles)
	rejected := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if rejected.Code != 409 || !reflect.DeepEqual(a.profiles, before) {
		t.Fatal("changed Router entry identity mutated a saved path")
	}
}

func TestExternalConnectionProfileIdentityAndFailedWritePreservePriorState(t *testing.T) {
	for _, fault := range []string{"protocol", "public-ip", "node-kind", "missing-entry", "write"} {
		t.Run(fault, func(t *testing.T) {
			a := externalConnectionTestApp(t, "socks5", true)
			id := savedExternalConnectionID(t, a)
			switch fault {
			case "protocol":
				a.profiles.Profiles[3].External.Protocol = "shadowsocks"
			case "public-ip":
				a.profiles.Profiles[3].External.ExpectedPublicIP = "203.0.113.18"
			case "node-kind":
				a.profiles.Profiles[3].NodeKind = "router-vpn"
				a.profiles.Profiles[3].External = nil
			case "missing-entry":
				a.profiles.Profiles[1].ID = "replacement"
			case "write":
				if err := os.Remove(a.cfg.ProfilesFile); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(a.cfg.ProfilesFile, 0700); err != nil {
					t.Fatal(err)
				}
			}
			a.profiles.Profiles[1].IPv6Mode = "on"
			a.profiles.Profiles[3].DNSMode = "rescue"
			a.profiles.SelectedID = "home"
			a.state.RouterID = "home"
			before := cloneRouterProfileStore(a.profiles)
			beforeState := a.state
			result := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if result.Code < 400 || !reflect.DeepEqual(a.profiles, before) || !reflect.DeepEqual(a.state, beforeState) {
				t.Fatalf("failed %s load changed prior state: %d %s", fault, result.Code, result.Body.String())
			}
		})
	}
}

func TestExternalConnectionProfileRejectsPartialAndSecretPolicy(t *testing.T) {
	a := externalConnectionTestApp(t, "socks5", false)
	_ = savedExternalConnectionID(t, a)
	store, err := loadConnectionProfileStore(a)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(store.Profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing", "null", "secret", "wrong-type", "invalid-dns", "wrong-mode"} {
		t.Run(fault, func(t *testing.T) {
			var value map[string]any
			_ = json.Unmarshal(raw, &value)
			policy := value["external_policy"].(map[string]any)
			switch fault {
			case "missing":
				delete(policy, "ipv6_mode")
			case "null":
				value["external_policy"] = nil
			case "secret":
				policy["api_token"] = "must-not-be-copied"
			case "wrong-type":
				policy["home_lan_access"] = "false"
			case "invalid-dns":
				policy["dns_host"] = "bad resolver host"
			case "wrong-mode":
				value["mode"] = "smart-auto"
			}
			data, _ := json.Marshal(value)
			var decoded connectionProfileRecord
			if json.Unmarshal(data, &decoded) == nil {
				t.Fatalf("accepted %s policy", fault)
			}
		})
	}
}

func TestLegacyExternalConnectionProfileRemainsSelectionOnly(t *testing.T) {
	a := externalConnectionTestApp(t, "socks5", false)
	legacy := recordForModeTest("legacy", "external", "external", nil)
	if err := persistConnectionProfileStore(a, connectionProfileStore{Version: 4, Profiles: []connectionProfileRecord{legacy}}); err != nil {
		t.Fatal(err)
	}
	before := cloneRouterProfile(a.profiles.Profiles[3])
	a.profiles.SelectedID = "home"
	result := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": "legacy"})
	if result.Code != 200 || !reflect.DeepEqual(a.profiles.Profiles[3], before) || a.profiles.SelectedID != "external" || a.state.Connected {
		t.Fatalf("legacy selection failed: %d %s", result.Code, result.Body.String())
	}
}

func TestExternalPrimaryConnectUsesSavedEntryInsteadOfSilentlyGoingDirect(t *testing.T) {
	a := externalConnectionTestApp(t, "socks5", true)
	a.profiles.Profiles[1].ID = "removed-entry"
	r := httptest.NewRequest(http.MethodPost, "/api/external-profile/connect", strings.NewReader(`{"profile_id":"external"}`))
	w := httptest.NewRecorder()
	a.externalProfileConnect(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "entry node is not linked") || a.state.Connected {
		t.Fatalf("primary Connect lost the saved hop: %d %s", w.Code, w.Body.String())
	}
}

func TestExternalConnectionProfileKeepsRotatedLinkedCredentials(t *testing.T) {
	a := externalConnectionTestApp(t, "socks5", true)
	id := savedExternalConnectionID(t, a)
	a.profiles.Profiles[3].External.SOCKS5.Password = "rotated-current-node-password"
	a.profiles.Profiles[1].APIToken = "rotated-entry-token"
	a.profiles.Profiles[3].DNSMode = "rescue"
	loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if loaded.Code != http.StatusOK || a.profiles.Profiles[3].External.SOCKS5.Password != "rotated-current-node-password" || a.profiles.Profiles[1].APIToken != "rotated-entry-token" || a.profiles.Profiles[3].DNSMode != "custom" {
		t.Fatalf("load replaced linked credentials or lost saved policy: %d %s", loaded.Code, loaded.Body.String())
	}
}

func TestConnectionProfileRestoresEveryRouterHopPolicyAndBindsNodeIdentity(t *testing.T) {
	a := setupProfileTestApp(t)
	for i := 0; i < 3; i++ {
		node := &a.profiles.Profiles[i]
		node.NodeProofID = strings.Repeat(string(rune('a'+i)), 64)
		node.HomeLANCIDRs = []string{"192.168.50.0/24", "fd42:50::/64"}
		node.StartupMode, node.AutoConnect = "last", true
		node.KillSwitchPolicy, node.IPv6Mode = "always", "off"
		node.CustomLayers = []string{"reality", "wireguard"}
	}
	result := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{
		"name": "Captured complete Router graph", "mode": "custom", "custom_layers": []string{"wireguard", "reality"},
		"multihop_enabled": true, "multihop_entry_id": "entry", "multihop_exit_id": "exit", "multihop_exit_mode": "shadowsocks", "multihop_execution": "auto",
	})
	if result.Code != 200 {
		t.Fatal(result.Body.String())
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil {
		t.Fatal(err)
	}
	id := store.Profiles[0].ID
	if len(store.Profiles[0].Hops) != 2 || store.Profiles[0].NodeProofID != strings.Repeat("a", 64) {
		t.Fatal("whole Router path was not captured")
	}
	for i := 0; i < 3; i++ {
		node := &a.profiles.Profiles[i]
		node.HomeLANCIDRs = []string{"10.1.0.0/16"}
		node.StartupMode, node.AutoConnect = "manual", false
		node.KillSwitchPolicy, node.IPv6Mode = "off", "on"
		node.CustomLayers = nil
		node.APIToken = "rotated-" + node.ID
	}
	loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if loaded.Code != 200 {
		t.Fatal(loaded.Body.String())
	}
	for i := 0; i < 3; i++ {
		node := a.profiles.Profiles[i]
		if node.StartupMode != "last" || !node.AutoConnect || node.KillSwitchPolicy != "always" || node.IPv6Mode != "off" || strings.Join(node.HomeLANCIDRs, ",") != "192.168.50.0/24,fd42:50::/64" || strings.Join(node.CustomLayers, ",") != "reality,wireguard" || node.APIToken != "rotated-"+node.ID {
			t.Fatalf("node %s lost captured policy or current credentials", node.ID)
		}
	}
	var payload map[string]any
	_ = json.Unmarshal(loaded.Body.Bytes(), &payload)
	if payload["multihop_execution"] != "auto" || payload["multihop_exit_mode"] != "shadowsocks" || a.state.Connected {
		t.Fatal("load lost Compare choice or connected without user action")
	}
	a.profiles.Profiles[0].NodeProofID = strings.Repeat("d", 64)
	before := cloneRouterProfileStore(a.profiles)
	rejected := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if rejected.Code != 409 || !reflect.DeepEqual(a.profiles, before) {
		t.Fatal("changed main Router identity was accepted or altered the previous state")
	}
}

func TestConnectionProfileLegacySnapshotPreservesUncapturedStartupAndLAN(t *testing.T) {
	a := setupProfileTestApp(t)
	p := &a.profiles.Profiles[0]
	p.StartupMode, p.AutoConnect = "last", true
	p.HomeLANCIDRs = []string{"10.55.0.0/16"}
	prefs, err := snapshotConnectionPreferences(*p, nil)
	if err != nil {
		t.Fatal(err)
	}
	prefs.StartupMode, prefs.AutoConnect, prefs.HomeLANCIDRs = nil, nil, nil
	legacy := recordForModeTest("legacy-router", "home", "smart-auto", prefs)
	if err := persistConnectionProfileStore(a, connectionProfileStore{Version: 4, Profiles: []connectionProfileRecord{legacy}}); err != nil {
		t.Fatal(err)
	}
	loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": legacy.ID})
	got := a.profiles.Profiles[0]
	if loaded.Code != 200 || got.StartupMode != "last" || !got.AutoConnect || strings.Join(got.HomeLANCIDRs, ",") != "10.55.0.0/16" {
		t.Fatalf("legacy load invented uncaptured settings: %d %s", loaded.Code, loaded.Body.String())
	}
}
