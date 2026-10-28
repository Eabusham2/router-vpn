package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func torBridgeFormSelections() []string {
	values := []string{"local", "server"}
	for _, protocol := range desktopTorOrdinaryTestProtocols {
		values = append(values, "ordinary-"+protocol)
	}
	for _, selection := range append([]string(nil), values...) {
		values = append(values, "plain-"+selection)
	}
	return values
}

func torBridgeFormNeedsTCPOnly(selection string) bool {
	selection = strings.TrimPrefix(selection, "plain-")
	return selection == "ordinary-socks5" || selection == "ordinary-http-connect" || selection == "ordinary-https-connect"
}

func torBridgeFormPreservedTransport(selection string) string {
	if strings.HasPrefix(selection, "plain-") {
		return "tor"
	}
	if strings.HasPrefix(selection, "ordinary-") {
		return "meek_lite"
	}
	return "snowflake"
}

func torBridgeFormInputLines() map[string][]string {
	lines := torBridgeUpdateInputLines()
	lines["tor"] = []string{}
	return lines
}

func TestDesktopTorBridgeUpdateFormCatalog(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_TOR_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("native Tor editor supplies its callback payload directory")
	}
	for _, execution := range torBridgeFormSelections() {
		a, _, _ := torBridgeFormSourceFixture(t, execution)
		response := httptest.NewRecorder()
		a.listPublicNodes(response, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
		if response.Code != http.StatusOK || response.Header().Get("cache-control") != "no-store" {
			t.Fatal("Tor editor catalog did not use the actual private-source projection")
		}
		for _, secret := range []string{"cert=", "private-token", "api_token", "private_key"} {
			if strings.Contains(response.Body.String(), secret) {
				t.Fatal("Tor form catalog exposed source credentials", secret)
			}
		}
		if err := os.WriteFile(filepath.Join(directory, torBridgeFormFile(execution, "source-catalog.json")), response.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		// Separate actual projections include the execution-bound revision and
		// the saved Always policy. Native editors must not fabricate either.
		a.profiles.Profiles[0].KillSwitchPolicy = "always"
		a.profiles.Profiles[0].KillSwitch = true
		response = httptest.NewRecorder()
		a.listPublicNodes(response, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
		if response.Code != http.StatusOK {
			t.Fatal("saved Always source projection failed")
		}
		if err := os.WriteFile(filepath.Join(directory, torBridgeFormFile(execution, "always-source-catalog.json")), response.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	a, _, _ := torBridgeFormSourceFixture(t, "local")
	response := httptest.NewRecorder()
	a.torBridgeCapabilities(response, httptest.NewRequest(http.MethodGet, "/api/tor-bridge/capabilities", nil))
	var capability map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &capability) != nil || capability["profile_update_source_preconditions"] != true {
		t.Fatal("Tor update capability omitted its unconditional source contract")
	}
	// The native editor intentionally prevents choosing unavailable transports.
	// This fixture exercises its idle import callbacks with simulated installed
	// availability; it does not claim this test app owns a runtime or a tunnel.
	capability["test_fixture_runtime_availability"] = "simulated: idle bridge form/import only"
	capability["supported"] = true
	rows, ok := capability["transports"].([]any)
	if !ok {
		t.Fatal("Tor capability transport catalog is missing")
	}
	for _, row := range rows {
		transport, ok := row.(map[string]any)
		if !ok {
			t.Fatal("Tor capability transport is not an object")
		}
		if _, tested := torBridgeFormInputLines()[transport["id"].(string)]; tested || transport["id"] == "custom" {
			transport["supported"] = true
			transport["helper"] = "test-only simulated runtime availability"
			delete(transport, "reason")
		}
	}
	capabilityBytes, err := json.MarshalIndent(capability, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tor-update-capabilities.json"), capabilityBytes, 0600); err != nil {
		t.Fatal(err)
	}
	lines, err := json.MarshalIndent(torBridgeFormInputLines(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "tor-update-input-lines.json"), lines, 0600); err != nil {
		t.Fatal(err)
	}
	fixed := map[string][]string{}
	for _, count := range []int{1, 2, 8} {
		fixed[fmt.Sprint(count)] = desktopDirectBridgeLines(count)
	}
	lines, err = json.MarshalIndent(fixed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "tor-fixed-input-sets.json"), lines, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopTorBridgeUpdateFormPayload(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_TOR_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("native Tor editor supplies its callback payload directory")
	}
	t.Run("new-plain-direct", func(t *testing.T) {
		a, old, entry := torBridgeFormSourceFixture(t, "local")
		raw, err := os.ReadFile(filepath.Join(directory, "tor-create-plain.json"))
		if err != nil {
			t.Fatal(err)
		}
		var request torBridgeImportRequest
		if json.Unmarshal(raw, &request) != nil || request.Transport != "tor" || len(request.Bridges) != 0 || request.KillSwitchPolicy != "off" || request.ID != "" || request.ExpectedSelectedNodeID != nil || len(request.ExpectedProfileTokens) != 0 {
			t.Fatal("actual Plain Tor Add borrowed update identity or bridge material")
		}
		response := postTorBridgeUpdate(a, raw)
		if response.Code != http.StatusOK || len(a.profiles.Profiles) != 3 {
			t.Fatal("actual Plain Tor Add failed", response.Code, response.Body.String())
		}
		added := a.profiles.Profiles[2]
		if added.External == nil || added.External.Protocol != "tor" || added.External.TorBridge != nil || added.MultihopEnabled || added.KillSwitch || added.KillSwitchPolicy != "off" || a.cmd != nil || a.state.Connected {
			t.Fatal("Plain Tor Add changed its direct/bridge-free policy or invented runtime proof")
		}
		before, _ := json.Marshal([]common.RouterProfile{old, entry})
		after, _ := json.Marshal(a.profiles.Profiles[:2])
		if !bytes.Equal(before, after) {
			t.Fatal("Plain Tor Add changed an existing private node")
		}
	})
	for _, transport := range []string{"obfs4", "custom"} {
		for _, count := range []int{1, 2, 8} {
			for _, kill := range []string{"on-connect", "always"} {
				t.Run(fmt.Sprintf("new-fixed/%s/%d/%s", transport, count, kill), func(t *testing.T) {
					a, old, entry := torBridgeFormSourceFixture(t, "local")
					raw, err := os.ReadFile(filepath.Join(directory, fmt.Sprintf("tor-create-fixed-%s-%d-%s.json", transport, count, kill)))
					if err != nil {
						t.Fatal(err)
					}
					var request torBridgeImportRequest
					if json.Unmarshal(raw, &request) != nil || request.Transport != transport || request.KillSwitchPolicy != kill || request.ID != "" || request.ExpectedSelectedNodeID != nil || len(request.ExpectedProfileTokens) != 0 || len(request.Bridges) != count {
						t.Fatal("actual fixed Direct Add borrowed an update identity or changed its complete bridge selection")
					}
					lines := desktopDirectBridgeLines(count)
					for i := range lines {
						if request.Bridges[i] != lines[i] {
							t.Fatal("actual fixed Direct Add substituted bridge credentials or source order")
						}
					}
					response := postTorBridgeUpdate(a, raw)
					if response.Code != http.StatusOK || len(a.profiles.Profiles) != 3 {
						t.Fatal("actual fixed Direct Add failed", response.Code, response.Body.String())
					}
					added := a.profiles.Profiles[2]
					if added.External == nil || added.External.Protocol != "tor-bridge" || added.External.TorBridge == nil || added.External.TorBridge.Transport != transport || len(added.External.TorBridge.Bridges) != count || added.MultihopEnabled || !added.KillSwitch || added.KillSwitchPolicy != kill || a.cmd != nil || a.state.Connected {
						t.Fatal("fixed Direct Add changed its complete policy or invented a running connection")
					}
					for i := range lines {
						if added.External.TorBridge.Bridges[i] != lines[i] {
							t.Fatal("fixed Direct import did not preserve every captured bridge credential")
						}
					}
					before, _ := json.Marshal([]common.RouterProfile{old, entry})
					after, _ := json.Marshal(a.profiles.Profiles[:2])
					if !bytes.Equal(before, after) {
						t.Fatal("fixed Direct Add changed an existing private node")
					}
				})
			}
		}
	}
	for _, execution := range torBridgeFormSelections() {
		t.Run(execution+"/unchanged-saved-protection", func(t *testing.T) {
			a, old, entry := torBridgeFormSourceFixture(t, execution)
			old.KillSwitchPolicy, old.KillSwitch = "always", true
			a.profiles.Profiles[0] = old
			raw, err := os.ReadFile(filepath.Join(directory, torBridgeFormFile(execution, "preserved-protection.json")))
			if err != nil {
				t.Fatal(err)
			}
			var request torBridgeImportRequest
			if json.Unmarshal(raw, &request) != nil || request.KillSwitchPolicy != "always" || request.Name != old.Name || len(request.ExpectedProfileTokens) != 2 {
				t.Fatal("actual checkbox and Save did not preserve the saved protection/name/source")
			}
			checkTorBridgePreservedUpdate(t, a, old, entry, postTorBridgeUpdate(a, raw), torBridgeFormPreservedTransport(execution), "always")
			checkTorFormPersistedPath(t, a, old, entry)
		})
		for transport := range torBridgeFormInputLines() {
			for _, kill := range []string{"off", "on-connect", "always"} {
				t.Run(execution+"/"+transport+"/"+kill, func(t *testing.T) {
					a, old, entry := torBridgeFormSourceFixture(t, execution)
					path := filepath.Join(directory, torBridgeFormFile(execution, transport+"-"+kill+".json"))
					if transport == "snowflake" && kill != "off" && torBridgeFormNeedsTCPOnly(execution) {
						if _, err := os.Stat(path); !os.IsNotExist(err) {
							t.Fatal("native editor emitted a strict request without bounded UDP", err)
						}
						return
					}
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					var q torBridgeImportRequest
					if err = json.Unmarshal(raw, &q); err != nil {
						t.Fatal("actual native bridge form is not the shipping API contract", err)
					}
					if q.ID != old.ID || q.Transport != transport || q.KillSwitchPolicy != kill || q.ExpectedSelectedNodeID == nil || *q.ExpectedSelectedNodeID != old.ID || len(q.ExpectedProfileTokens) != 2 {
						t.Fatal("native editor omitted or changed its captured target, protection or source revisions")
					}
					if err = a.validateExternalProfileExpectedProfiles(q.expectedProfiles(), old); err != nil {
						t.Fatal("native editor body cannot pass the actual source guard", err)
					}
					checkTorBridgePreservedUpdate(t, a, old, entry, postTorBridgeUpdate(a, raw), transport, kill)
					checkTorFormPersistedPath(t, a, old, entry)
					for _, relinked := range []string{"tor-edit", "entry", "execution"} {
						replaced, _, _ := torBridgeFormSourceFixture(t, execution)
						if relinked == "entry" {
							if replaced.profiles.Profiles[1].External != nil {
								replaced.profiles.Profiles[1].External.ExpectedPublicIP = "203.0.113.155"
							} else {
								replaced.profiles.Profiles[1].APIToken = "replacement-private-entry-token"
							}
						} else if relinked == "execution" {
							replaced.profiles.Profiles[0].MultihopExecution = "server"
							if strings.TrimPrefix(execution, "plain-") == "server" {
								replaced.profiles.Profiles[0].MultihopExecution = "local"
							}
						} else if replaced.profiles.Profiles[0].External.TorBridge == nil {
							replaced.profiles.Profiles[0].DNSHost = "149.112.112.112"
						} else {
							replaced.profiles.Profiles[0].External.TorBridge.Bridges = []string{strings.Replace(torImportObfs4Bridge, "203.0.113.44", "203.0.113.45", 1)}
						}
						if response := postTorBridgeUpdate(replaced, raw); response.Code != http.StatusConflict {
							t.Fatal("native editor adopted a relinked source", relinked, response.Code, response.Body.String())
						}
					}
				})
			}
		}
	}
}

func torBridgeFormSourceFixture(t *testing.T, execution string) (*app, common.RouterProfile, common.RouterProfile) {
	t.Helper()
	a, old, entry := torBridgeUpdateSourceFixture(t)
	if strings.HasPrefix(execution, "plain-") {
		execution = strings.TrimPrefix(execution, "plain-")
		old.External.Protocol, old.External.TorBridge = "tor", nil
	}
	if protocol, ordinary := strings.CutPrefix(execution, "ordinary-"); ordinary {
		if protocol == "openvpn" {
			var err error
			entry, err = externalProfileFromCreateRequest(desktopOpenVPNCreateFixture(t, common.StartLayerOff))
			if err != nil {
				t.Fatal(err)
			}
		} else {
			entry, _ = desktopExternalNativeFixture(t, protocol)
		}
		entry.ID, entry.Name = "entry", "Captured ordinary entry"
		entry.KillSwitchPolicy, entry.KillSwitch = "off", false
		old.MultihopEntryMode, old.MultihopExecution = protocol, "local"
		old.DNSMode, old.DNSProtocol, old.DNSHost, old.DNSPort = "custom", "tcp", "9.9.9.9", 5353
		old.DNSServerName, old.DNSPath = "", ""
		a.profiles.Profiles = []common.RouterProfile{cloneRouterProfile(old), cloneRouterProfile(entry)}
		return a, old, entry
	}
	if execution != "local" && execution != "server" {
		t.Fatal("form fixture requires an explicit supported execution")
	}
	old.MultihopExecution = execution
	a.profiles.Profiles[0] = cloneRouterProfile(old)
	return a, old, entry
}

func torBridgeFormFile(execution, suffix string) string {
	prefix := "tor-update-"
	if execution != "local" {
		prefix += execution + "-"
	}
	return prefix + suffix
}

func checkTorFormPersistedPath(t *testing.T, a *app, old, entry common.RouterProfile) {
	t.Helper()
	raw, err := os.ReadFile(a.cfg.ProfilesFile)
	var stored common.RouterProfileStore
	if err != nil || json.Unmarshal(raw, &stored) != nil || len(stored.Profiles) != 2 {
		t.Fatal("native form did not commit its complete private profile store")
	}
	selected := stored.Profiles[0]
	if selected.MultihopExecution != old.MultihopExecution || selected.MultihopEntryID != old.MultihopEntryID ||
		selected.DNSMode != old.DNSMode || selected.DNSProtocol != old.DNSProtocol || selected.DNSHost != old.DNSHost ||
		selected.DNSPort != old.DNSPort || selected.DNSServerName != old.DNSServerName || selected.DNSPath != old.DNSPath {
		t.Fatal("native bridge Save changed the persisted execution, entry or selected DNS")
	}
	actual, _ := json.Marshal(stored.Profiles[1])
	expected, _ := json.Marshal(entry)
	if !bytes.Equal(actual, expected) {
		t.Fatal("native bridge Save changed the persisted independent entry or credentials")
	}
}
