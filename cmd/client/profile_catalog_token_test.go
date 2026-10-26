package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func catalogTokenProfile() common.RouterProfile {
	return common.RouterProfile{
		ID: "node", NodeKind: "router-vpn", Name: "Home", NodeProofID: strings.Repeat("a", 64),
		Endpoint: "203.0.113.9", RouterAPI: "http://10.77.0.1:8787", APIToken: "private-api-token",
		SocksHost: "10.77.0.1", SocksPort: 1080, SocksUsername: "private-user", SocksPassword: "private-proxy-password",
		DNSMode: "home", IPv6Mode: "on", MTUPolicy: "auto", StartupMode: "manual",
	}
}

func TestPublicProfileTokenBindsCredentialsAndRequestedPolicy(t *testing.T) {
	changes := map[string]func(*common.RouterProfile){
		"identity":       func(p *common.RouterProfile) { p.NodeProofID = strings.Repeat("b", 64) },
		"endpoint":       func(p *common.RouterProfile) { p.Endpoint = "203.0.113.10" },
		"api-token":      func(p *common.RouterProfile) { p.APIToken = "rotated-private-token" },
		"proxy-password": func(p *common.RouterProfile) { p.SocksPassword = "rotated-private-password" },
		"base":           func(p *common.RouterProfile) { p.BaseTunnel = "awg" },
		"fallback":       func(p *common.RouterProfile) { p.BaseFallback = true },
		"custom":         func(p *common.RouterProfile) { p.CustomLayers = []string{"wireguard", "reality"} },
		"start-layer":    func(p *common.RouterProfile) { p.StartLayer = "aes-256-gcm+xor-whitening" },
		"dns":            func(p *common.RouterProfile) { p.AdGuardIPv4 = "10.78.0.1" },
		"dns-policy":     func(p *common.RouterProfile) { p.DNSMode, p.DNSHost = "custom", "9.9.9.9" },
		"lan":            func(p *common.RouterProfile) { p.HomeLANAccess = true },
		"kill-switch":    func(p *common.RouterProfile) { p.KillSwitchPolicy = "always" },
		"ipv6":           func(p *common.RouterProfile) { p.IPv6Mode = "off" },
		"mtu":            func(p *common.RouterProfile) { p.MTUPolicy, p.ManualMTU = "manual", 1380 },
		"entry":          func(p *common.RouterProfile) { p.MultihopEntryID = "entry" },
		"execution":      func(p *common.RouterProfile) { p.MultihopExecution = "server" },
		"entry-mode":     func(p *common.RouterProfile) { p.MultihopEntryMode = "max" },
		"startup":        func(p *common.RouterProfile) { p.StartupMode = "smart-auto" },
		"auto-connect":   func(p *common.RouterProfile) { p.AutoConnect = true },
		"external-key": func(p *common.RouterProfile) {
			p.NodeKind = "external"
			p.External = &common.ExternalNodeConfig{Protocol: "wireguard", WireGuard: &common.ExternalWireGuardConfig{PrivateKey: "private-wg-key"}}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			profile := catalogTokenProfile()
			before := publicProfileForCapabilities(profile, nil).ProfileToken
			change(&profile)
			frozen := cloneRouterProfile(profile)
			after := publicProfileForCapabilities(profile, nil).ProfileToken
			if before == after || len(after) != 64 {
				t.Fatal("catalog failed to retire changed node source or policy")
			}
			if _, err := hex.DecodeString(after); err != nil {
				t.Fatal("catalog token is not an opaque digest")
			}
			if summaries := multihopNodeSummaries([]common.RouterProfile{profile}); len(summaries) != 1 || summaries[0].ProfileToken != after {
				t.Fatal("catalogs disagree about the same node revision")
			}
			if !reflect.DeepEqual(profile, frozen) {
				t.Fatal("reading a catalog token changed the private source")
			}
		})
	}
	for _, protocol := range []string{"wireguard", "amneziawg", "shadowsocks", "socks5", "hysteria2", "openvpn", "tor-bridge"} {
		t.Run("external-"+protocol, func(t *testing.T) {
			profile := externalConnectionTestNode(t, protocol)
			before := publicProfileToken(profile)
			switch protocol {
			case "wireguard":
				profile.External.WireGuard.PrivateKey = "rotated-private-key"
			case "amneziawg":
				profile.External.AmneziaWG.PrivateKey = "rotated-private-key"
			case "shadowsocks":
				profile.External.Shadowsocks.Password = "rotated-private-key"
			case "socks5":
				profile.External.SOCKS5.Password = "rotated-private-key"
			case "hysteria2":
				profile.External.Hysteria2.Password = "rotated-private-key"
			case "openvpn":
				profile.External.OpenVPN.Password = "rotated-private-key"
			case "tor-bridge":
				profile.External.TorBridge.Bridges[0] += " rotated-bridge-identity"
			}
			if publicProfileToken(profile) == before {
				t.Fatal("same-ID external relink retained an old catalog revision")
			}
		})
	}
}

func TestPublicProfileTokenIgnoresTelemetryAndDisplayMetadata(t *testing.T) {
	profile := catalogTokenProfile()
	before := publicProfileToken(profile)
	profile.Name, profile.Location, profile.Latitude, profile.Longitude = "Renamed", "Austin", 30.1, -97.7
	profile.PublicIP, profile.UseCount, profile.LastUsedAt = "198.51.100.8", 20, "2026-10-26"
	profile.LatencySamples, profile.LatencyMedianMs, profile.LatencyLastTest = 50, 2.5, "2026-10-26"
	profile.FastestDNSHost, profile.FastestDNSName, profile.FastestDNSLatencyMs = "9.9.9.9", "measured", 4.5
	profile.DNSResults = []common.DNSBenchmarkResult{{Address: "9.9.9.9", LatencyMs: 4.5}}
	profile.EffectiveMTU, profile.EffectiveMTUSource, profile.EffectiveMTUPathKey = 1380, "fresh-owned-test", "new-path"
	profile.EffectiveUnderlayPMTU, profile.EffectiveMTUMbps, profile.EffectiveMTUTestedAt = 1420, 123.4, "2026-10-26"
	profile.EffectiveMTUMedianRTTMs, profile.EffectiveMTUSuccessRatio = 1.5, 1
	if publicProfileToken(profile) != before {
		t.Fatal("display or measurement persistence invalidated a loaded selection")
	}
}

func TestPublicNodeCatalogHTTPRevisionsAreConsistentAndSecretFree(t *testing.T) {
	a := setupProfileTestApp(t)
	a.profiles.Profiles[0] = catalogTokenProfile()
	a.profiles.SelectedID = "node"
	for _, handler := range []struct {
		name, field string
		serve       http.HandlerFunc
	}{{"nodes", "profiles", a.listPublicNodes}, {"legacy-multihop", "nodes", a.multihopStatus}, {"native-multihop", "nodes", a.nativeMultihopStatus}, {"speed-lab", "nodes", a.speedLabOptions}} {
		t.Run(handler.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.serve(response, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
			if response.Code != http.StatusOK {
				t.Fatal(response.Body.String())
			}
			if response.Header().Get("cache-control") != "no-store" {
				t.Fatal("node revision response may be reused after relinking")
			}
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			var nodes []struct {
				ID    string `json:"id"`
				Token string `json:"profile_token"`
			}
			if err := json.Unmarshal(payload[handler.field], &nodes); err != nil || len(nodes) != len(a.profiles.Profiles) {
				t.Fatal("catalog node set changed", err)
			}
			for _, node := range nodes {
				profile, exists := a.profileByIDLocked(node.ID)
				if !exists || node.Token != publicProfileToken(profile) {
					t.Fatal("public catalog did not bind the exact node source")
				}
			}
			for _, secret := range []string{"private-api-token", "private-user", "private-proxy-password", "ENTRY-SECRET", "EXIT-SECRET", strings.Repeat("a", 64), "api_token", "socks_password"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatal("catalog exposed private source material")
				}
			}
		})
	}
}

func saveCatalogProfile(t *testing.T, a *app, enabled bool, entry, exit string) string {
	t.Helper()
	response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{
		"name": "Captured graph", "mode": "smart-auto", "multihop_enabled": enabled,
		"multihop_entry_id": entry, "multihop_exit_id": exit, "multihop_exit_mode": "naive-h3", "multihop_execution": "auto",
	})
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var payload struct {
		Profile connectionProfileRecord `json:"profile"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Profile.ID
}

func TestConnectionProfileLoadReturnsCommittedGraphRevisions(t *testing.T) {
	for _, graph := range []string{"single", "three-nodes", "selected-entry", "external-exit"} {
		t.Run(graph, func(t *testing.T) {
			a := setupProfileTestApp(t)
			ids := []string{"home"}
			var saved string
			switch graph {
			case "external-exit":
				a = externalConnectionTestApp(t, "socks5", true)
				ids = []string{"external", "entry"}
				saved = savedExternalConnectionID(t, a)
			case "selected-entry":
				ids = []string{"home", "exit"}
				saved = saveCatalogProfile(t, a, true, "home", "exit")
			case "three-nodes":
				ids = []string{"home", "entry", "exit"}
				saved = saveCatalogProfile(t, a, true, "entry", "exit")
			default:
				saved = saveCatalogProfile(t, a, false, "", "")
			}
			// Saved configurations restore policy and retain current private-node
			// credentials. Revisions must describe that committed combination.
			for i := range a.profiles.Profiles {
				if a.profiles.Profiles[i].External != nil {
					a.profiles.Profiles[i].External.SOCKS5.Username = "current-private-user"
					a.profiles.Profiles[i].External.SOCKS5.Password = "private-rotated-after-save"
				} else {
					a.profiles.Profiles[i].APIToken += "-rotated-after-save"
				}
				a.profiles.Profiles[i].HomeLANAccess = true
			}
			response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved})
			if response.Code != http.StatusOK {
				t.Fatal(response.Body.String())
			}
			var payload struct {
				Tokens map[string]string `json:"profile_tokens"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || len(payload.Tokens) != len(ids) {
				t.Fatal("load did not return exactly the deduplicated graph revisions", err)
			}
			for _, id := range ids {
				profile, exists := a.profileByIDLocked(id)
				credential := profile.APIToken
				if profile.External != nil {
					credential = profile.External.SOCKS5.Password
				}
				if !exists || payload.Tokens[id] != publicProfileToken(profile) || !strings.HasSuffix(credential, "-rotated-after-save") {
					t.Fatal("load token describes pre-restore policy or old credentials")
				}
			}
			if strings.Contains(response.Body.String(), "-rotated-after-save") {
				t.Fatal("load response copied private credentials")
			}
			for _, path := range []string{connectionProfileStorePath(a), connectionProfileSetupMetaPath(a)} {
				raw, err := os.ReadFile(path)
				if err != nil || strings.Contains(string(raw), "profile_token") {
					t.Fatal("transient catalog revision became saved configuration", err)
				}
			}
		})
	}
}

func TestConnectionProfileLoadRejectsMissingOrReplacedGraphBeforeReturningRevisions(t *testing.T) {
	for _, id := range []string{"home", "entry", "exit"} {
		for _, fault := range []string{"missing", "replaced"} {
			t.Run(id+"/"+fault, func(t *testing.T) {
				a := setupProfileTestApp(t)
				for i := range a.profiles.Profiles {
					if a.profiles.Profiles[i].External == nil {
						a.profiles.Profiles[i].NodeProofID = strings.Repeat(string(rune('a'+i)), 64)
					}
				}
				saved := saveCatalogProfile(t, a, true, "entry", "exit")
				for i := range a.profiles.Profiles {
					if a.profiles.Profiles[i].ID == id {
						if fault == "missing" {
							a.profiles.Profiles = append(a.profiles.Profiles[:i], a.profiles.Profiles[i+1:]...)
						} else {
							a.profiles.Profiles[i].NodeProofID = strings.Repeat("f", 64)
						}
						break
					}
				}
				before := cloneRouterProfileStore(a.profiles)
				response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved})
				if response.Code != http.StatusConflict || strings.Contains(response.Body.String(), "profile_tokens") || !reflect.DeepEqual(a.profiles, before) {
					t.Fatal("unlinked/replaced graph published revisions or partially applied policy")
				}
			})
		}
	}
}

type catalogLoadWriter struct {
	*httptest.ResponseRecorder
	onWrite func()
}

func (w *catalogLoadWriter) Write(data []byte) (int, error) {
	w.onWrite()
	return w.ResponseRecorder.Write(data)
}

func TestConnectionProfileLoadCapturesRevisionsUnderItsCommitLock(t *testing.T) {
	a := setupProfileTestApp(t)
	saved := saveCatalogProfile(t, a, true, "entry", "exit")
	expected := map[string]string{}
	rotated := make(chan struct{})
	response := &catalogLoadWriter{ResponseRecorder: httptest.NewRecorder()}
	response.onWrite = func() {
		if a.mu.TryLock() {
			a.mu.Unlock()
			t.Error("load published revisions after releasing its committed profile snapshot")
		}
		for _, id := range []string{"home", "entry", "exit"} {
			profile, _ := a.profileByIDLocked(id)
			expected[id] = publicProfileToken(profile)
		}
		attempting := make(chan struct{})
		go func() {
			close(attempting)
			a.mu.Lock()
			a.profiles.Profiles[1].APIToken = "replacement-after-commit"
			a.mu.Unlock()
			close(rotated)
		}()
		<-attempting
	}
	a.loadConnectionProfile(response, httptest.NewRequest(http.MethodPost, "/api/connection-profile/load", strings.NewReader(`{"id":"`+saved+`"}`)))
	<-rotated
	var payload struct {
		Tokens map[string]string `json:"profile_tokens"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || response.Code != http.StatusOK || !reflect.DeepEqual(payload.Tokens, expected) {
		t.Fatal("load revisions were read from another profile transaction", err)
	}
	if publicProfileToken(a.profiles.Profiles[1]) == payload.Tokens["entry"] {
		t.Fatal("same-ID post-commit credential rotation is invisible to the catalog")
	}
}

func TestConnectionProfileSetupRejectsResponseRevisionsAsSaveFields(t *testing.T) {
	a := setupProfileTestApp(t)
	saved := saveCatalogProfile(t, a, false, "", "")
	before, err := os.ReadFile(connectionProfileStorePath(a))
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"save", "update"} {
		for _, field := range []string{"profile_token", "profile_tokens"} {
			body := map[string]any{"name": "Must reject", "mode": "smart-auto", "multihop_enabled": false, field: "response-only"}
			if operation == "update" {
				body["id"] = saved
			}
			response := postSetup(t, a, "/api/connection-profile/setup/"+operation, body)
			if response.Code != http.StatusBadRequest {
				t.Fatal("save accepted a transient response revision")
			}
		}
	}
	after, err := os.ReadFile(connectionProfileStorePath(a))
	if err != nil || string(after) != string(before) {
		t.Fatal("rejected revision fields changed saved profiles", err)
	}
}

func TestConnectionProfileLoadDoesNotPublishRevisionsWhenPersistenceFails(t *testing.T) {
	a := setupProfileTestApp(t)
	saved := saveCatalogProfile(t, a, true, "entry", "exit")
	// A private directory cannot be overwritten by the profile-file transaction.
	// Keep the saved setup files in their original directory for a real load.
	if err := os.Remove(a.cfg.ProfilesFile); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(a.cfg.ProfilesFile, 0700); err != nil {
		t.Fatal(err)
	}
	a.profiles.SelectedID = "entry"
	a.state.RouterID = "entry"
	before, oldState := cloneRouterProfileStore(a.profiles), a.state
	response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved})
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "profile_tokens") || !reflect.DeepEqual(a.profiles, before) || !reflect.DeepEqual(a.state, oldState) {
		t.Fatal("failed persistence published committed revisions or left a partial load")
	}
}
