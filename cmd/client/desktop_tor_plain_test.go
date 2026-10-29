package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

func TestDesktopTorPlainImportAndExplicitProtocolUpdate(t *testing.T) {
	a := torImportTestApp(t, filepath.Join(t.TempDir(), "profiles.json"))
	response := httptest.NewRecorder()
	a.torBridgeImport(response, httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(`{"transport":"tor","bridges":[]}`)))
	if response.Code != http.StatusOK || len(a.profiles.Profiles) != 1 {
		t.Fatal("plain import failed", response.Code, response.Body.String())
	}
	p := a.profiles.Profiles[0]
	if p.External == nil || p.External.Protocol != "tor" || p.External.TorBridge != nil || p.External.ExpectedPublicIP != "" || p.DNSMode != "home" || p.DNSHost != "" || p.KillSwitchPolicy != "off" || p.KillSwitch || p.Endpoint != "tor" {
		t.Fatal("plain Tor acquired bridge, public resolver or fixed endpoint")
	}
	for _, body := range []string{
		`{"transport":"tor","bridges":["` + torImportObfs4Bridge + `"]}`,
		`{"transport":"tor","bridges":[""]}`,
		`{"transport":"tor","bridges":[],"socks_port":19951}`,
		`{"transport":"tor","bridges":[],"kill_switch_policy":"unowned"}`,
	} {
		before := cloneRouterProfileStore(a.profiles)
		response = httptest.NewRecorder()
		a.torBridgeImport(response, httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(body)))
		if response.Code < 400 || !reflect.DeepEqual(a.profiles, before) {
			t.Fatal("plain import discarded a bridge or accepted unowned policy", response.Code)
		}
	}
	for _, policy := range []string{"on-connect", "always"} {
		t.Run("direct-"+policy, func(t *testing.T) {
			candidate := torImportTestApp(t, filepath.Join(t.TempDir(), "profiles.json"))
			response := httptest.NewRecorder()
			candidate.torBridgeImport(response, httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", strings.NewReader(`{"transport":"tor","bridges":[],"kill_switch_policy":"`+policy+`"}`)))
			if runtime.GOOS != "linux" {
				if response.Code != http.StatusBadRequest || len(candidate.profiles.Profiles) != 0 || !strings.Contains(response.Body.String(), "Linux native socket owner") {
					t.Fatal("plain Tor borrowed another platform's physical owner", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusOK || len(candidate.profiles.Profiles) != 1 {
				t.Fatal("Linux plain Tor rejected its captured protection policy", response.Code, response.Body.String())
			}
			stored := candidate.profiles.Profiles[0]
			if stored.External.Protocol != "tor" || stored.External.TorBridge != nil || stored.KillSwitchPolicy != policy || !stored.KillSwitch || stored.DNSMode != "home" || stored.DNSHost != "" || candidate.state.Connected || candidate.cmd != nil {
				t.Fatal("idle strict plain import changed selected policy or invented a proved path")
			}
		})
	}
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			f := newDesktopTorConnectFixture(t)
			original := cloneRouterProfile(f.a.profiles.Profiles[0])
			original.MultihopExecution = execution
			f.a.profiles.Profiles[0] = original
			request := torBridgeImportRequest{ID: original.ID, Transport: "tor", ExpectedSelectedNodeID: &f.a.profiles.SelectedID,
				ExpectedProfileTokens: map[string]string{original.ID: publicProfileToken(original), f.a.profiles.Profiles[1].ID: publicProfileToken(f.a.profiles.Profiles[1])}}
			raw, _ := json.Marshal(request)
			response := postTorBridgeUpdate(f.a, raw)
			if response.Code != http.StatusOK {
				t.Fatal(response.Code, response.Body.String())
			}
			updated := f.a.profiles.Profiles[0]
			if updated.External.Protocol != "tor" || updated.External.TorBridge != nil || updated.MultihopExecution != execution || updated.MultihopEntryID != original.MultihopEntryID || updated.MultihopEntryMode != original.MultihopEntryMode || updated.DNSHost != original.DNSHost || updated.DNSProtocol != original.DNSProtocol || updated.KillSwitchPolicy != original.KillSwitchPolicy {
				t.Fatal("explicit plain edit discarded captured entry, execution or DNS")
			}
			if response := postTorBridgeUpdate(f.a, raw); response.Code != http.StatusConflict {
				t.Fatal("old bridge revision overwrote the new plain selection", response.Code)
			}
		})
	}
}

func TestDesktopTorPlainPublicLifecyclePreservesExactExecutionAndDNS(t *testing.T) {
	for _, path := range []string{"direct", "router-local", "router-server", "ordinary-socks5", "ordinary-shadowsocks"} {
		t.Run(path, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			f.unified = true
			f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "last.json")
			f.a.mu.Lock()
			p := &f.a.profiles.Profiles[0]
			p.External = &common.ExternalNodeConfig{Protocol: "tor"}
			p.AutoConnect, p.StartupMode = true, "last"
			direct := path == "direct"
			execution := "local"
			if path == "router-server" {
				execution = "server"
			}
			if direct {
				p.KillSwitchPolicy, p.KillSwitch = "off", false
			} else {
				p.KillSwitchPolicy, p.KillSwitch = "always", true
			}
			profileID := p.ID
			p.MultihopExecution = execution
			f.a.mu.Unlock()
			if strings.HasPrefix(path, "ordinary-") {
				desktopTorOrdinaryFixture(t, f, strings.TrimPrefix(path, "ordinary-"))
			}
			response := f.request(t, externalProfileConnectRequest{ProfileID: profileID, Direct: &direct, Execution: execution})
			if response.Code != http.StatusOK {
				t.Fatal(response.Code, response.Body.String())
			}
			first := f.launch
			f.a.mu.Lock()
			stored, state := cloneRouterProfile(f.a.profiles.Profiles[0]), f.a.state
			f.a.mu.Unlock()
			if !state.Connected || state.RuntimeMode != "external-tor" || first.mode != state.RuntimeMode || stored.External.Protocol != "tor" || stored.MultihopExecution != execution || !strings.Contains(response.Body.String(), `"protocol":"tor"`) {
				t.Fatal("plain runtime reported or saved another mode")
			}
			if strings.HasPrefix(path, "ordinary-") && first.tor.expected.EntryProofKind != mobiletor.ExternalPredecessorProofKind {
				t.Fatal("plain ordinary entry acquired private Router proof authority")
			}
			observed := observedConnection{Connected: true, Phase: "connected", Mode: "external-node", RuntimeMode: state.RuntimeMode, RouterID: stored.ID, Profile: stored}
			dns := proveSelectedDNSWithLookup(context.Background(), f.a, observed, state.RuntimeMode, func(context.Context, string) ([]string, error) {
				t.Fatal("plain Tor escaped to ambient DNS")
				return nil, nil
			})
			if dns.Status != "passed" {
				t.Fatal("plain selected DNS lost native receipt", dns)
			}
			if binding, err := captureDesktopTorMeasurementBinding(f.a, state); err != nil || binding == nil || binding.launch != first {
				t.Fatal("plain measurements lost captured runtime", err)
			}
			last, err := f.a.loadStartupSelection()
			if err != nil || last.External == nil || last.External.Protocol != "tor" || last.RuntimeMode != "external-tor" || last.External.Execution != execution {
				t.Fatal("plain Startup Last changed protocol or execution", err)
			}
			if err := f.a.stopModeWithIntent(true); err != nil {
				t.Fatal(err)
			}
			capture, err := f.a.captureStartupPolicy()
			if err != nil || capture == nil {
				t.Fatal("plain Startup Last could not capture source", err)
			}
			f.a.applyCapturedStartupPolicy(context.Background(), capture, externalConnectRuntime{tor: f.driver})
			f.a.mu.Lock()
			connected := f.a.state.Connected
			f.a.mu.Unlock()
			if !connected || f.launch == first || f.launch.mode != "external-tor" || f.launch.tor.expected.SessionID == first.tor.expected.SessionID || f.launch.tor.expected.DNS != first.tor.expected.DNS || desktopTorExecution(f.launch.tor.expected.Execution) != execution {
				t.Fatal("plain Startup Last lost exact source or fresh proof")
			}
			if err := f.a.stopModeWithIntent(true); err != nil {
				t.Fatal(err)
			}
			response = postSetup(t, f.a, "/api/connection-profile/setup/save", map[string]any{"name": "Plain saved", "mode": "external", "multihop_enabled": false})
			var record struct {
				Profile connectionProfileRecord `json:"profile"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &record) != nil || record.Profile.External == nil || record.Profile.External.Protocol != "tor" || record.Profile.External.MultihopExecution != execution {
				t.Fatal("plain complete profile save failed", response.Code, response.Body.String())
			}
			f.a.mu.Lock()
			f.a.profiles.Profiles[0].DNSHost = "149.112.112.112"
			f.a.mu.Unlock()
			response = desktopTorProfileRequest(t, f, "/api/connection-profile/load", map[string]any{"id": record.Profile.ID})
			if response.Code != http.StatusOK || f.a.profiles.Profiles[0].DNSHost != stored.DNSHost || f.a.profiles.Profiles[0].MultihopExecution != execution || !reflect.DeepEqual(f.a.profiles.Profiles[0].External, stored.External) {
				t.Fatal("plain whole profile restore changed source, DNS or execution", response.Code, response.Body.String())
			}
			response = postSetup(t, f.a, "/api/connection-profile/setup/update", map[string]any{"id": record.Profile.ID, "name": "Plain updated", "mode": "external", "multihop_enabled": false})
			if response.Code != http.StatusOK {
				t.Fatal("plain complete update failed", response.Code, response.Body.String())
			}
			response = desktopTorProfileRequest(t, f, "/api/connection-profile/delete", map[string]any{"id": record.Profile.ID})
			if response.Code != http.StatusOK || !reflect.DeepEqual(f.a.profiles.Profiles[0].External, stored.External) {
				t.Fatal("plain delete changed private source", response.Code)
			}
		})
	}
}
