package main

import (
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

func TestSpeedLabOptionsBindCurrentExternalHopToRuntimeOwner(t *testing.T) {
	for _, variant := range []string{"hopped", "direct", "different-command", "different-node", "disconnected", "router-mode"} {
		t.Run(variant, func(t *testing.T) {
			a := setupProfileTestApp(t)
			a.cmd = &exec.Cmd{}
			a.state = state{Connected: true, Phase: "connected", Mode: "external-node", RouterID: "external"}
			entry, _ := a.profileByIDLocked("entry")
			launch := &desktopNodeLaunch{command: a.cmd, profileID: "external", external: &desktopExternalRuntime{entry: entry}}
			switch variant {
			case "direct":
				launch.external.direct = true
			case "different-command":
				launch.command = &exec.Cmd{}
			case "different-node":
				launch.profileID = "exit"
			case "disconnected":
				a.state.Connected = false
			case "router-mode":
				a.state.Mode = "wg"
			}
			desktopNodeOwners.Store(a, launch)
			t.Cleanup(func() { desktopNodeOwners.Delete(a) })
			response := httptest.NewRecorder()
			a.speedLabOptions(response, httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil))
			var options struct {
				Current map[string]any `json:"current"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &options) != nil {
				t.Fatal("current-path options failed", response.Code)
			}
			if variant == "hopped" {
				if options.Current["entry_id"] != "entry" || options.Current["exit_id"] != "external" {
					t.Fatal("current native path omitted its exact hop identities", options.Current)
				}
			} else if variant == "direct" {
				if options.Current["entry_id"] != nil || options.Current["exit_id"] != "external" {
					t.Fatal("current direct path acquired a hop", options.Current)
				}
			} else if options.Current["entry_id"] != nil || options.Current["exit_id"] != nil {
				t.Fatal("stale native owner supplied current path identity", options.Current)
			}
		})
	}
}

func TestSpeedLabOptionsKeepPrivatePairedPathDefaultsAndNativeEntryCatalog(t *testing.T) {
	request := desktopOpenVPNCreateFixture(t, common.StartLayerAES256GCMXOR)
	profile, err := externalProfileFromCreateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	profile.MultihopEnabled, profile.MultihopEntryID, profile.MultihopExitID = true, "saved-entry", profile.ID
	profile.MultihopEntryMode, profile.MultihopExecution = "max-quic-awg", "auto"
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var modes []common.Mode
	if err := json.Unmarshal(data, &modes); err != nil {
		t.Fatal(err)
	}
	a := &app{modes: modes, profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}, state: state{Mode: "off", Phase: "off"}}
	response := httptest.NewRecorder()
	a.speedLabOptions(response, httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil))
	var options struct {
		Nodes      []map[string]any    `json:"nodes"`
		EntryModes []map[string]string `json:"router_vpn_entry_modes"`
		Executions []map[string]string `json:"execution_choices"`
		ExitModes  []string            `json:"supported_exit_modes"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &options) != nil || len(options.Nodes) != 1 {
		t.Fatal("Speed Lab options lost the captured node")
	}
	node := options.Nodes[0]
	if node["profile_token"] != publicProfileFor(profile).ProfileToken {
		t.Fatal("Speed Lab options cannot validate the captured public node revision")
	}
	for key, expected := range map[string]any{"multihop_enabled": true, "multihop_entry_id": "saved-entry", "multihop_exit_id": profile.ID, "multihop_entry_mode": "max-quic-awg", "multihop_execution": "auto", "has_response_probe": true, "has_openvpn_pairing": true, "selected": true} {
		if node[key] != expected {
			t.Fatalf("Speed Lab lost saved %s: %v", key, node[key])
		}
	}
	capability := httptest.NewRecorder()
	a.externalProfileCapabilities(capability, httptest.NewRequest(http.MethodGet, "/api/external-profile/capabilities", nil))
	var external struct {
		EntryModes []map[string]string `json:"router_vpn_entry_modes"`
	}
	if json.Unmarshal(capability.Body.Bytes(), &external) != nil || len(options.EntryModes) != 19 || !reflect.DeepEqual(external.EntryModes, options.EntryModes) {
		t.Fatal("Speed Lab substituted its Router entry catalog")
	}
	if len(options.Executions) != 3 || options.Executions[0]["id"] != "local" || options.Executions[1]["id"] != "server" || options.Executions[2]["id"] != "auto" || options.Executions[2]["name"] != "Compare both" {
		t.Fatal("Speed Lab execution choices changed")
	}
	if !reflect.DeepEqual(options.ExitModes, desktopMultihopExitModes()) {
		t.Fatal("Speed Lab changed the complete native Router exit catalog")
	}
	for _, secret := range []string{profile.External.OpenVPN.Username, profile.External.OpenVPN.Password, profile.External.OpenVPNPairing.PrivateKey, `"config":`, `"openvpn_pairing":`, `"provider_identity":`, `"private_key":`, `"response_probe":`} {
		if secret != "" && strings.Contains(response.Body.String(), secret) {
			t.Fatal("Speed Lab options exposed private pairing material")
		}
	}
}

func TestSpeedLabExternalEntryRejectsUnownedModeAndRetainsExactRouter(t *testing.T) {
	profile, _ := desktopExternalNativeFixture(t, "hysteria2")
	entry := common.RouterProfile{ID: "router-entry", NodeKind: "router-vpn", Endpoint: "203.0.113.8", BaseTunnel: "awg"}
	external, _ := desktopExternalNativeFixture(t, "socks5")
	external.ID = "external-entry"
	profiles := []common.RouterProfile{entry, external}
	for _, mode := range []string{"wg", "awg2-strong", "wg-pq", "reality-vision", "max-quic-awg"} {
		q := speedLabRequest{EntryID: entry.ID, EntryMode: mode, Base: "wg"}
		got, kind, direct, err := speedLabExternalEntry(profiles, profile, q)
		if err != nil || direct || kind != "router-vpn" || !reflect.DeepEqual(got, entry) {
			t.Fatalf("Speed Lab changed its captured Router entry: %v", err)
		}
		resolved, err := desktopExternalEntryMode(profile, got, q.EntryMode, q.Base)
		if err != nil || resolved != mode {
			t.Fatal("Speed Lab substituted the requested native entry mode")
		}
	}
	for _, q := range []speedLabRequest{{EntryMode: "wg"}, {EntryID: external.ID, EntryMode: "wg"}, {EntryID: entry.ID, EntryMode: "smart-auto"}, {EntryID: entry.ID, EntryMode: " wg"}, {EntryID: "missing", EntryMode: "wg"}} {
		if _, _, _, err := speedLabExternalEntry(profiles, profile, q); err == nil {
			t.Fatal("Speed Lab accepted an unowned Router entry mode")
		}
	}
}

func TestSpeedLabOptionsHideTorBridgeRelay(t *testing.T) {
	a := &app{
		profiles: common.RouterProfileStore{
			SchemaVersion: common.RouterProfileSchemaVersion,
			SelectedID:    "tor-private",
			Profiles: []common.RouterProfile{{
				SchemaVersion: common.RouterProfileSchemaVersion,
				ID:            "tor-private",
				Name:          "Tor Snowflake",
				NodeKind:      "external",
				Endpoint:      "203.0.113.77:443",
				External: &common.ExternalNodeConfig{
					Protocol: "tor-bridge",
					TorBridge: &common.ExternalTorBridgeConfig{
						Transport: "snowflake",
						Bridges:   []string{"Bridge snowflake 203.0.113.77:443 fingerprint=ABC url=https://broker.example/ front=front.example"},
					},
				},
			}},
		},
		state: state{Mode: "off", Phase: "off"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil)
	a.speedLabOptions(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Speed Lab options status=%d body=%q", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "203.0.113.77:443") || strings.Contains(body, "Bridge snowflake") {
		t.Fatalf("Speed Lab options leaked Tor relay metadata: %s", body)
	}
	if !strings.Contains(body, `"external_protocol":"tor-bridge"`) || !strings.Contains(body, `"id":"tor-private"`) {
		t.Fatalf("Speed Lab options lost safe Tor node identity: %s", body)
	}
}
