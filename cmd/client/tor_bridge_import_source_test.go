package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func torBridgeUpdateInputLines() map[string][]string {
	return map[string][]string{
		"obfs4":     {torImportObfs4Bridge},
		"meek_lite": {"meek_lite 192.0.2.20:80 url=https://bridge.example/owned front=front.example"},
		"snowflake": {torImportSnowflakeBridge},
		"webtunnel": {clientWebTunnelBridge},
	}
}

// Public source tokens remain identical in the catalog writer and the separate
// platform payload consumer. These are synthetic private inputs, never user
// bridge credentials or a claim that an actual connection has been proved.
func torBridgeUpdateSourceFixture(t *testing.T) (*app, common.RouterProfile, common.RouterProfile) {
	t.Helper()
	old := existingTorImportProfile("tor-edit")
	entry, _ := desktopNodeFixture(t, "198.51.100.11")
	entry.ID = "entry"
	entry.Name = "Captured Router entry"
	entry.BaseTunnel = "awg"
	old.Name = "Captured Tor exit"
	old.MultihopEnabled = true
	old.MultihopEntryID = entry.ID
	old.MultihopExitID = old.ID
	old.MultihopEntryMode = "awg2-strong"
	old.MultihopExecution = "local"
	old.DNSMode, old.DNSProtocol, old.DNSHost, old.DNSPort, old.DNSServerName, old.DNSPath = "home", "udp", "", 53, "", ""
	old.IPv6Mode = "off"
	old.MTUPolicy = "manual"
	old.ManualMTU = 1280
	old.HomeLANAccess = true
	old.HomeLANCIDRs = []string{"192.168.50.0/24"}
	old.EffectiveMTU = 1400
	old.EffectiveMTUSource = "historical"
	old.LatencySamples = 50
	old.LatencyMedianMs = 19
	for _, profile := range []*common.RouterProfile{&old, &entry} {
		if err := common.NormalizeRouterProfile(profile); err != nil {
			t.Fatal(err)
		}
	}
	// macOS may place test directories below the /var -> /private/var alias.
	// Resolve only this fixture-owned root; production private stores must still
	// reject symlink components in the path they are given.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := torImportTestApp(t, filepath.Join(root, "profiles.json"))
	a.profiles.SelectedID = old.ID
	a.state.RouterID = old.ID
	a.profiles.Profiles = []common.RouterProfile{old, entry}
	return a, cloneRouterProfile(old), cloneRouterProfile(entry)
}

func torBridgeCapturedUpdate(t *testing.T, a *app, transport, kill string) map[string]any {
	t.Helper()
	request := map[string]any{"id": "tor-edit", "transport": transport, "bridges": torBridgeUpdateInputLines()[transport], "expected_selected_node_id": a.profiles.SelectedID}
	if kill != "" {
		request["kill_switch_policy"] = kill
	}
	tokens := map[string]string{}
	for _, node := range a.profiles.Profiles {
		tokens[node.ID] = publicProfileToken(node)
	}
	request["expected_profile_tokens"] = tokens
	return request
}
func torBridgeUpdateBody(t *testing.T, request map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func postTorBridgeUpdate(a *app, raw []byte) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	a.torBridgeImport(response, httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", bytes.NewReader(raw)))
	return response
}

func checkTorBridgePreservedUpdate(t *testing.T, a *app, old, entry common.RouterProfile, response *httptest.ResponseRecorder, transport, kill string) {
	t.Helper()
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"updated":true`) {
		t.Fatal("captured Tor update failed", response.Code, response.Body.String())
	}
	if len(a.profiles.Profiles) != 2 || a.profiles.SelectedID != old.ID || a.state.RouterID != old.ID || !reflect.DeepEqual(entry, a.profiles.Profiles[1]) {
		t.Fatal("bridge edit replaced selection, node count or independent entry credentials")
	}
	updated := a.profiles.Profiles[0]
	if !updated.MultihopEnabled || updated.MultihopEntryID != old.MultihopEntryID || updated.MultihopExitID != old.MultihopExitID || updated.MultihopEntryMode != old.MultihopEntryMode || updated.MultihopExecution != old.MultihopExecution {
		t.Fatal("bridge edit lost the complete saved Router graph")
	}
	if updated.KillSwitchPolicy != kill || updated.KillSwitch != (kill != "off") || updated.External.TorBridge.Transport != transport || updated.External.TorBridge.SocksPort != old.External.TorBridge.SocksPort {
		t.Fatal("bridge edit changed requested protection or standalone SOCKS ownership")
	}
	if updated.DNSMode != old.DNSMode || updated.DNSProtocol != old.DNSProtocol || updated.DNSHost != old.DNSHost || updated.DNSPort != old.DNSPort || updated.DNSServerName != old.DNSServerName || updated.DNSPath != old.DNSPath || updated.IPv6Mode != old.IPv6Mode || updated.MTUPolicy != old.MTUPolicy || updated.ManualMTU != old.ManualMTU || !reflect.DeepEqual(updated.HomeLANCIDRs, old.HomeLANCIDRs) || updated.HomeLANAccess != old.HomeLANAccess {
		t.Fatal("bridge edit substituted independent DNS, MTU, LAN or IPv6 choices")
	}
	if updated.PublicIP != "" || updated.EffectiveMTU != 0 || updated.LatencySamples != 0 || updated.UseCount != old.UseCount || updated.LastUsedAt != old.LastUsedAt {
		t.Fatal("bridge edit retained stale path proof or discarded stable usage")
	}
	for _, secret := range []string{"cert=", "private-token", "1111111111111111111111111111111111111111", "api_token", "expected_profile_tokens"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("public update response disclosed private or request-only source material", secret)
		}
	}
	raw, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("expected_profile_tokens")) || bytes.Contains(raw, []byte("expected_selected_node_id")) {
		t.Fatal("ephemeral editor capture was persisted as node data")
	}
	var saved common.RouterProfileStore
	if err = json.Unmarshal(raw, &saved); err != nil || len(saved.Profiles) != 2 || saved.Profiles[0].MultihopEntryMode != old.MultihopEntryMode || saved.Profiles[0].KillSwitchPolicy != kill {
		t.Fatal("committed private profile differs from successful response", err)
	}
	if a.cmd != nil || a.state.Connected {
		t.Fatal("idle bridge update invented runtime proof")
	}
}

func TestTorBridgeImportCapturedRouterUpdatesPreserveGraphAndProtection(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		for _, mode := range []string{"wg", "awg2-strong", "naive-h3", "max-quic-awg"} {
			for transport := range torBridgeUpdateInputLines() {
				for _, kill := range []string{"off", "on-connect", "always"} {
					t.Run(execution+"/"+mode+"/"+transport+"/"+kill, func(t *testing.T) {
						a, old, entry := torBridgeUpdateSourceFixture(t)
						a.profiles.Profiles[0].MultihopExecution = execution
						old.MultihopExecution = execution
						a.profiles.Profiles[0].MultihopEntryMode = mode
						old.MultihopEntryMode = mode
						body := torBridgeUpdateBody(t, torBridgeCapturedUpdate(t, a, transport, kill))
						checkTorBridgePreservedUpdate(t, a, old, entry, postTorBridgeUpdate(a, body), transport, kill)
					})
				}
			}
		}
	}
	t.Run("omitted-protection-retains-Router-choice", func(t *testing.T) {
		a, old, entry := torBridgeUpdateSourceFixture(t)
		old.KillSwitchPolicy = "always"
		old.KillSwitch = true
		a.profiles.Profiles[0] = old
		body := torBridgeUpdateBody(t, torBridgeCapturedUpdate(t, a, "snowflake", ""))
		checkTorBridgePreservedUpdate(t, a, old, entry, postTorBridgeUpdate(a, body), "snowflake", "always")
	})
	t.Run("omitted-transport-retains-exact-selected-family", func(t *testing.T) {
		a, old, entry := torBridgeUpdateSourceFixture(t)
		old.External.TorBridge.Transport = "webtunnel"
		old.External.TorBridge.Bridges = append([]string(nil), torBridgeUpdateInputLines()["webtunnel"]...)
		a.profiles.Profiles[0] = old
		request := torBridgeCapturedUpdate(t, a, "webtunnel", "always")
		delete(request, "transport")
		checkTorBridgePreservedUpdate(t, a, old, entry, postTorBridgeUpdate(a, torBridgeUpdateBody(t, request)), "webtunnel", "always")
	})
}

func TestTorBridgeImportCapturedSourcesRejectRelinkAndMissingOwners(t *testing.T) {
	for _, change := range []string{"exit-bridge", "entry-credential", "entry-policy", "selected", "missing-target", "missing-entry", "external-entry", "duplicate-target", "duplicate-entry", "missing-entry-token", "unknown-token"} {
		t.Run(change, func(t *testing.T) {
			a, _, _ := torBridgeUpdateSourceFixture(t)
			request := torBridgeCapturedUpdate(t, a, "snowflake", "always")
			switch change {
			case "exit-bridge":
				a.profiles.Profiles[0].External.TorBridge.Bridges = []string{strings.Replace(torImportObfs4Bridge, "203.0.113.44", "203.0.113.45", 1)}
			case "entry-credential":
				a.profiles.Profiles[1].APIToken = "relinked-private-token"
			case "entry-policy":
				a.profiles.Profiles[1].DNSMode = "custom"
			case "selected":
				a.profiles.SelectedID = "entry"
			case "missing-target":
				a.profiles.Profiles = a.profiles.Profiles[1:]
			case "missing-entry":
				a.profiles.Profiles = a.profiles.Profiles[:1]
			case "external-entry":
				a.profiles.Profiles[1].NodeKind = "external"
				a.profiles.Profiles[1].External = &common.ExternalNodeConfig{Protocol: "socks5"}
			case "duplicate-target":
				a.profiles.Profiles = append(a.profiles.Profiles, cloneRouterProfile(a.profiles.Profiles[0]))
			case "duplicate-entry":
				a.profiles.Profiles = append(a.profiles.Profiles, cloneRouterProfile(a.profiles.Profiles[1]))
			case "missing-entry-token":
				delete(request["expected_profile_tokens"].(map[string]string), "entry")
			case "unknown-token":
				request["expected_profile_tokens"].(map[string]string)["unlinked"] = strings.Repeat("a", 64)
			}
			before := cloneRouterProfileStore(a.profiles)
			response := postTorBridgeUpdate(a, torBridgeUpdateBody(t, request))
			if response.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("stale displayed source changed or recreated a private node", change, response.Code, response.Body.String())
			}
		})
	}
}

func TestTorBridgeImportSourceJSONRejectsAmbiguousDowngrades(t *testing.T) {
	a, _, _ := torBridgeUpdateSourceFixture(t)
	valid := torBridgeUpdateBody(t, torBridgeCapturedUpdate(t, a, "snowflake", "always"))
	token := publicProfileToken(a.profiles.Profiles[0])
	for name, raw := range map[string]string{
		"null-top":            "null",
		"null-selected":       `{"id":"tor-edit","expected_selected_node_id":null,"expected_profile_tokens":{}}`,
		"null-map":            `{"id":"tor-edit","expected_selected_node_id":"tor-edit","expected_profile_tokens":null}`,
		"partial-selected":    `{"id":"tor-edit","expected_selected_node_id":"tor-edit"}`,
		"partial-map":         `{"id":"tor-edit","expected_profile_tokens":{}}`,
		"duplicate-field":     `{"id":"tor-edit","expected_selected_node_id":"tor-edit","expected_selected_node_id":"entry","expected_profile_tokens":{}}`,
		"duplicate-token":     `{"id":"tor-edit","expected_selected_node_id":"tor-edit","expected_profile_tokens":{"tor-edit":"` + token + `","tor-edit":"` + token + `"}}`,
		"case-alias":          `{"id":"tor-edit","Expected_Selected_Node_ID":"tor-edit","expected_profile_tokens":{}}`,
		"empty-token":         `{"id":"tor-edit","expected_selected_node_id":"tor-edit","expected_profile_tokens":{"entry":""}}`,
		"numeric-token":       `{"id":"tor-edit","expected_selected_node_id":"tor-edit","expected_profile_tokens":{"entry":3}}`,
		"upper-token":         `{"id":"tor-edit","expected_selected_node_id":"tor-edit","expected_profile_tokens":{"entry":"` + strings.Repeat("A", 64) + `"}}`,
		"changed-entry-field": strings.TrimSuffix(string(valid), "}") + `,"entry_id":"other"}`,
		"direct-override":     strings.TrimSuffix(string(valid), "}") + `,"direct":true}`,
		"trailing-object":     string(valid) + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			before := cloneRouterProfileStore(a.profiles)
			response := postTorBridgeUpdate(a, []byte(raw))
			if response.Code != http.StatusBadRequest || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("ambiguous update weakened the captured source contract", response.Code, response.Body.String())
			}
		})
	}
	t.Run("expected-update-cannot-create", func(t *testing.T) {
		request := torBridgeCapturedUpdate(t, a, "snowflake", "off")
		delete(request, "id")
		response := postTorBridgeUpdate(a, torBridgeUpdateBody(t, request))
		if response.Code != http.StatusBadRequest {
			t.Fatal("captured update became Add", response.Code)
		}
	})
}

func TestTorBridgeImportSavedGraphCannotBeSubstituted(t *testing.T) {
	for _, change := range []string{"server-ordinary", "compare", "wrong-exit", "unknown-mode", "missing-entry", "external-entry"} {
		t.Run(change, func(t *testing.T) {
			a, _, _ := torBridgeUpdateSourceFixture(t)
			switch change {
			case "server-ordinary":
				a.profiles.Profiles[0].MultihopExecution = "server"
				a.profiles.Profiles[1].NodeKind = "external"
				a.profiles.Profiles[1].External = &common.ExternalNodeConfig{Protocol: "socks5"}
			case "compare":
				a.profiles.Profiles[0].MultihopExecution = "auto"
			case "wrong-exit":
				a.profiles.Profiles[0].MultihopExitID = "other"
			case "unknown-mode":
				a.profiles.Profiles[0].MultihopEntryMode = "unknown"
			case "missing-entry":
				a.profiles.Profiles = a.profiles.Profiles[:1]
			case "external-entry":
				a.profiles.Profiles[1].NodeKind = "external"
				a.profiles.Profiles[1].External = &common.ExternalNodeConfig{Protocol: "socks5"}
			}
			request := torBridgeCapturedUpdate(t, a, "snowflake", "always")
			delete(request, "expected_selected_node_id")
			delete(request, "expected_profile_tokens")
			before := cloneRouterProfileStore(a.profiles)
			response := postTorBridgeUpdate(a, torBridgeUpdateBody(t, request))
			if response.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("legacy update coerced an unavailable saved graph", response.Code, response.Body.String())
			}
		})
	}
}

// The normal mutation gate reads this internal context marker after its first
// idle-state check and before it owns operationMu. Holding this read lets the
// test acquire the store mutex at that exact admission boundary; cancellation
// is always the real context cancellation, never a fabricated Err result.
type torBridgeMutationAdmissionContext struct {
	context.Context
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *torBridgeMutationAdmissionContext) Value(key any) any {
	if _, ok := key.(internalMutationContextKey); ok {
		c.once.Do(func() {
			close(c.reached)
			<-c.release
		})
	}
	return c.Context.Value(key)
}

func TestTorBridgeImportCapturedUpdateCancellationAndRollback(t *testing.T) {
	for _, add := range []bool{false, true} {
		t.Run(map[bool]string{false: "Update", true: "Add"}[add]+"-cancel-while-awaiting-store", func(t *testing.T) {
			a, _, _ := torBridgeUpdateSourceFixture(t)
			request := torBridgeCapturedUpdate(t, a, "snowflake", "off")
			if add {
				delete(request, "id")
				delete(request, "expected_selected_node_id")
				delete(request, "expected_profile_tokens")
			}
			before := cloneRouterProfileStore(a.profiles)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			admission := &torBridgeMutationAdmissionContext{Context: ctx, reached: make(chan struct{}), release: make(chan struct{})}
			req := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/import", bytes.NewReader(torBridgeUpdateBody(t, request))).WithContext(admission)
			response := httptest.NewRecorder()
			done := make(chan struct{})
			locked, released := false, false
			defer func() {
				cancel()
				if !released {
					close(admission.release)
				}
				if locked {
					a.mu.Unlock()
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("owned request did not join during cleanup")
				}
			}()
			go func() { a.torBridgeImport(response, req); close(done) }()
			select {
			case <-admission.reached:
			case <-done:
				t.Fatal("request returned before mutation admission", response.Code, response.Body.String())
			case <-time.After(3 * time.Second):
				t.Fatal("request did not reach mutation admission")
			}
			a.mu.Lock()
			locked = true
			close(admission.release)
			released = true
			deadline := time.Now().Add(3 * time.Second)
			for a.operationMu.TryLock() {
				a.operationMu.Unlock()
				if time.Now().After(deadline) {
					t.Fatal("request did not reach the owning mutation gate")
				}
				runtime.Gosched()
			}
			cancel()
			a.mu.Unlock()
			locked = false
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("cancelled mutation did not return")
			}
			if response.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("cancelled request changed private profiles", response.Code, response.Body.String())
			}
		})
	}
	t.Run("persistence-rollback-retains-whole-path", func(t *testing.T) {
		a, _, _ := torBridgeUpdateSourceFixture(t)
		a.cfg.ProfilesFile = t.TempDir()
		before := cloneRouterProfileStore(a.profiles)
		response := postTorBridgeUpdate(a, torBridgeUpdateBody(t, torBridgeCapturedUpdate(t, a, "snowflake", "always")))
		if response.Code < 400 || !reflect.DeepEqual(before, a.profiles) {
			t.Fatal("failed commit lost existing Router/Tor path", response.Code, response.Body.String())
		}
	})
}
