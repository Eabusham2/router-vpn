package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func dnsPolicySnapshotForTest(t *testing.T, a *app) dnsPolicyResponse {
	t.Helper()
	mux := http.NewServeMux()
	registerDNSPolicyRoute(mux, a)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/dns/policy", nil))
	if w.Code != http.StatusOK || w.Header().Get("cache-control") != "no-store" {
		t.Fatalf("DNS snapshot: %d %s", w.Code, w.Body.String())
	}
	for _, secret := range []string{"private_key", "password", "ss-secret", "hy-secret", "proxy-secret", "private-ovpn", "bridges", "api_token", "ENTRY-SECRET"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("DNS editor exposed a private source field %q", secret)
		}
	}
	var snapshot dnsPolicyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.ProfileID != a.profiles.SelectedID || len(snapshot.ProfileToken) != 64 {
		t.Fatal("DNS snapshot has no exact selected source")
	}
	return snapshot
}

func dnsPolicyBodyForTest(t *testing.T, snapshot dnsPolicyResponse, request dnsPolicyRequest) []byte {
	t.Helper()
	request.ProfileID, request.ProfileToken = snapshot.ProfileID, snapshot.ProfileToken
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func postDNSPolicyForTest(a *app, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.dnsPolicy(w, httptest.NewRequest(http.MethodPost, "/api/dns/policy", body))
	return w
}

func externalHomeDNSEntryForTest(a *app) {
	p := &a.profiles.Profiles[1]
	p.NodeProofID, p.AdGuardIPv4, p.AdGuardIPv6 = strings.Repeat("a", 64), "192.168.50.133", "fd42:50::133"
}

func TestExternalDNSPolicySavePreservesAllNinePrivateProtocolsAndOtherSettings(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn", "tor-bridge"} {
		t.Run(protocol, func(t *testing.T) {
			a := externalConnectionTestApp(t, protocol, false)
			before := cloneRouterProfileStore(a.profiles)
			snapshot := dnsPolicySnapshotForTest(t, a)
			if snapshot.NodeKind != "external" || strings.Contains(snapshot.Note, "measured from the selected home node") {
				t.Fatal("external DNS was mislabeled as a Router-only policy/measurement")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			startupPolicyCancels.Store(a, context.CancelFunc(cancel))
			t.Cleanup(func() { cancelPendingStartupPolicy(a) })
			request := dnsPolicyRequest{Mode: "doh", Host: "9.9.9.9", Port: 8443, ServerName: "dns.quad9.net", Path: "/owned-query"}
			w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, request)))
			if w.Code != http.StatusOK {
				t.Fatalf("external DNS save: %d %s", w.Code, w.Body.String())
			}
			if ctx.Err() != context.Canceled {
				t.Fatal("a saved DNS change retained a delayed old startup intent")
			}
			want := cloneRouterProfileStore(before)
			want.Profiles[3].DNSMode, want.Profiles[3].DNSProtocol, want.Profiles[3].DNSHost = "doh", "https", "9.9.9.9"
			want.Profiles[3].DNSPort, want.Profiles[3].DNSServerName, want.Profiles[3].DNSPath = 8443, "dns.quad9.net", "/owned-query"
			if !reflect.DeepEqual(a.profiles, want) {
				t.Fatal("DNS save rewrote private credentials, protocol, graph, protection or another node")
			}
			raw, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			var disk common.RouterProfileStore
			if err := json.Unmarshal(raw, &disk); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(disk.Profiles[3].External, before.Profiles[3].External) || disk.Profiles[3].DNSPath != "/owned-query" || disk.SelectedID != before.SelectedID {
				t.Fatal("DNS policy and private node were not durably preserved")
			}
			if dnsPolicySnapshotForTest(t, a).ProfileToken == snapshot.ProfileToken {
				t.Fatal("saved DNS policy retained the stale editor revision")
			}
		})
	}
}

func TestExternalDNSPolicyHomeBindsCapturedRouterEntryAndKeepsDraftNonRunnable(t *testing.T) {
	a := externalConnectionTestApp(t, "shadowsocks", true)
	externalHomeDNSEntryForTest(a)
	snapshot := dnsPolicySnapshotForTest(t, a)
	w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, dnsPolicyRequest{Mode: "home", Protocol: "doh", Host: "192.168.50.133", Port: 8443, ServerName: "adguard.home.example", Path: "/private-query"})))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	profile := a.profiles.Profiles[3]
	if profile.DNSProtocol != "https" || profile.DNSPort != 8443 || profile.DNSPath != "/private-query" || profile.AdGuardIPv4 != "" || profile.APIToken != "" {
		t.Fatal("encrypted Home policy was replaced or entry credentials leaked into the reusable external node")
	}
	policy, err := externalDNSPolicyForPath(profile, a.profiles.Profiles[1], false)
	if err != nil {
		t.Fatal(err)
	}
	server, err := selectedStandardExitDNS(policy, false)
	if err != nil || server["server"] != "192.168.50.133" || server["detour"] != "entry-wg" || server["server_port"] != 8443 {
		t.Fatal("saved Home policy lost its actual captured runtime route", err, server)
	}
	for _, fault := range []string{"different home", "public home", "missing entry", "wrong exit", "missing token", "wrong proof", "public API", "missing adguard", "external entry"} {
		t.Run(fault, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", true)
			externalHomeDNSEntryForTest(a)
			request := dnsPolicyRequest{Mode: "home"}
			switch fault {
			case "different home":
				request.Host = "10.77.0.53"
			case "public home":
				request.Host = "1.1.1.1"
			case "missing entry":
				a.profiles.Profiles[3].MultihopEntryID = "missing"
			case "wrong exit":
				a.profiles.Profiles[3].MultihopExitID = "exit"
			case "missing token":
				a.profiles.Profiles[1].APIToken = ""
			case "wrong proof":
				a.profiles.Profiles[1].NodeProofID = "not-a-proof"
			case "public API":
				a.profiles.Profiles[1].RouterAPI = "https://1.1.1.1"
			case "missing adguard":
				a.profiles.Profiles[1].AdGuardIPv4, a.profiles.Profiles[1].AdGuardIPv6 = "", ""
			case "external entry":
				p := externalConnectionTestNode(t, "shadowsocks")
				p.ID = "entry"
				a.profiles.Profiles[1] = p
			}
			snapshot := dnsPolicySnapshotForTest(t, a)
			before := cloneRouterProfileStore(a.profiles)
			w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, request)))
			if w.Code != http.StatusBadRequest || !reflect.DeepEqual(a.profiles, before) {
				t.Fatalf("invalid Home owner adopted: %d %s", w.Code, w.Body.String())
			}
		})
	}
	direct := externalConnectionTestApp(t, "wireguard", false)
	snapshot = dnsPolicySnapshotForTest(t, direct)
	w = postDNSPolicyForTest(direct, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, dnsPolicyRequest{Mode: "home"})))
	if w.Code != http.StatusOK || direct.profiles.Profiles[3].DNSHost != "" {
		t.Fatal("Home idle intent acquired a replacement resolver", w.Code, w.Body.String())
	}
	if _, err := externalDNSPolicyForPath(direct.profiles.Profiles[3], common.RouterProfile{}, true); err == nil {
		t.Fatal("saving a Home draft made the unpaired direct external path runnable")
	}
}

func TestExternalDNSPolicyUsesExactRuntimeTransportValidation(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect", "tor-bridge"} {
		for _, mode := range []string{"custom", "doh3", "fastest"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				a := externalConnectionTestApp(t, protocol, false)
				a.profiles.Profiles[3].FastestDNSHost, a.profiles.Profiles[3].FastestDNSLatencyMs = "9.9.9.9", 5
				request := dnsPolicyRequest{Mode: mode, Protocol: "udp", Host: "9.9.9.9", ServerName: "dns.quad9.net"}
				snapshot := dnsPolicySnapshotForTest(t, a)
				before := cloneRouterProfileStore(a.profiles)
				w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, request)))
				if w.Code != http.StatusBadRequest || !reflect.DeepEqual(a.profiles, before) {
					t.Fatalf("TCP-only path accepted a datagram DNS policy: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
	for _, request := range []dnsPolicyRequest{
		{Mode: "doh", Host: "resolver.example.test"},
		{Mode: "custom", Protocol: "tcp", Host: "127.0.0.1"},
		{Mode: "custom", Protocol: "tcp", Host: "0.0.0.0"},
		{Mode: "custom", Protocol: "tcp", Host: "::ffff:9.9.9.9"},
		{Mode: "doh", Host: "9.9.9.9", Path: "//another.example/query"},
		{Mode: "doh", Host: "9.9.9.9", Path: "/query?target=another"},
		{Mode: "doh", Host: "9.9.9.9", ServerName: "localhost"},
		{Mode: "custom", Protocol: "tcp", Host: "9.9.9.9", Port: 65536},
		{Mode: "home", Host: "1.1.1.1"},
	} {
		a := externalConnectionTestApp(t, "shadowsocks", false)
		snapshot := dnsPolicySnapshotForTest(t, a)
		before := cloneRouterProfileStore(a.profiles)
		w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, request)))
		if w.Code != http.StatusBadRequest || !reflect.DeepEqual(a.profiles, before) {
			t.Fatalf("invalid resolver accepted: %+v => %d %s", request, w.Code, w.Body.String())
		}
	}
}

func TestExternalDNSPolicyRescueIsExplicitCanonicalPresetAndFastestRejectsLegacyEvidence(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "tor-bridge"} {
		a := externalConnectionTestApp(t, protocol, false)
		snapshot := dnsPolicySnapshotForTest(t, a)
		w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, dnsPolicyRequest{Mode: "rescue", Host: "9.9.9.9", Port: 5353, ServerName: "leftover.example", Path: "/leftover"})))
		if w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body.String())
		}
		p := a.profiles.Profiles[3]
		if p.DNSMode != "rescue" || p.DNSProtocol != "https" || p.DNSHost != "1.1.1.1" || p.DNSPort != 443 || p.DNSServerName != "cloudflare-dns.com" || p.DNSPath != "/dns-query" {
			t.Fatal("saved Rescue label differs from the shared runtime's explicit preset")
		}
	}
	for _, working := range []bool{false, true} {
		a := externalConnectionTestApp(t, "shadowsocks", false)
		p := &a.profiles.Profiles[3]
		p.FastestDNSHost, p.FastestDNSLatencyMs = "9.9.9.9", 5
		p.DNSResults = []common.DNSBenchmarkResult{{Name: "Quad9", Address: "9.9.9.9", Working: working, LatencyMs: 5}}
		snapshot := dnsPolicySnapshotForTest(t, a)
		before := cloneRouterProfileStore(a.profiles)
		w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, dnsPolicyRequest{Mode: "fastest"})))
		if w.Code != http.StatusBadRequest || !reflect.DeepEqual(a.profiles, before) {
			t.Fatal("Fastest DNS reinterpreted a sample lacking native path, transport or freshness", working, w.Code, w.Body.String())
		}
	}
}

func TestExternalDNSPolicyRejectsStaleNodeEntryAndBenchmarkInputs(t *testing.T) {
	cases := map[string]func(*app){
		"selection":      func(a *app) { a.profiles.SelectedID = "entry" },
		"credentials":    func(a *app) { a.profiles.Profiles[3].External.Shadowsocks.Password = "replacement-private" },
		"DNS":            func(a *app) { a.profiles.Profiles[3].DNSPort++ },
		"entry identity": func(a *app) { a.profiles.Profiles[1].APIToken = "REPLACEMENT-SECRET" },
		"entry DNS":      func(a *app) { a.profiles.Profiles[1].AdGuardIPv4 = "10.77.0.53" },
		"entry mode":     func(a *app) { a.profiles.Profiles[3].MultihopEntryMode = "awg2-strong" },
		"entry removed":  func(a *app) { a.profiles.Profiles[1].ID = "replacement-entry" },
		"execution":      func(a *app) { a.profiles.Profiles[3].MultihopExecution = "server" },
		"protection":     func(a *app) { a.profiles.Profiles[3].KillSwitchPolicy = "off" },
		"fastest":        func(a *app) { a.profiles.Profiles[3].FastestDNSHost = "1.1.1.1" },
		"results": func(a *app) {
			a.profiles.Profiles[3].DNSResults = []common.DNSBenchmarkResult{{Address: "1.1.1.1", Working: true, LatencyMs: 4}}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", true)
			snapshot := dnsPolicySnapshotForTest(t, a)
			change(a)
			before := cloneRouterProfileStore(a.profiles)
			w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, dnsPolicyRequest{Mode: "doh", Host: "9.9.9.9"})))
			if w.Code != http.StatusConflict || !reflect.DeepEqual(a.profiles, before) {
				t.Fatalf("stale DNS editor overwrote a replacement owner: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestExternalDNSPolicyRechecksAndPreservesConcurrentDisplayUpdates(t *testing.T) {
	for _, change := range []string{"selection", "entry", "connected", "closing", "cancelled", "display"} {
		t.Run(change, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", true)
			snapshot := dnsPolicySnapshotForTest(t, a)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &startupSettingsMutationReader{Reader: bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, dnsPolicyRequest{Mode: "doh", Host: "9.9.9.9"})), mutate: func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				switch change {
				case "selection":
					a.profiles.SelectedID = "entry"
				case "entry":
					a.profiles.Profiles[1].APIToken = "CHANGED-SECRET"
				case "connected":
					a.state.Connected = true
				case "closing":
					a.closing = true
				case "cancelled":
					cancel()
				case "display":
					a.profiles.Profiles[3].Name = "Updated display name"
				}
			}}
			w := httptest.NewRecorder()
			a.dnsPolicy(w, httptest.NewRequest(http.MethodPost, "/api/dns/policy", reader).WithContext(ctx))
			if change == "display" {
				if w.Code != http.StatusOK || a.profiles.Profiles[3].Name != "Updated display name" || a.profiles.Profiles[3].DNSMode != "doh" {
					t.Fatal("DNS save overwrote a newer display object", w.Code, w.Body.String())
				}
			} else if w.Code != http.StatusConflict || a.profiles.Profiles[3].DNSMode != "custom" {
				t.Fatal("late source/session change adopted DNS edit", change, w.Code, w.Body.String())
			}
		})
	}
}

func TestExternalDNSPolicyRejectsMalformedUnownedAndFailedSaves(t *testing.T) {
	for _, fault := range []string{"missing identity", "foreign field", "trailing JSON", "oversized", "busy", "operation", "persistence"} {
		t.Run(fault, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", false)
			snapshot := dnsPolicySnapshotForTest(t, a)
			raw := dnsPolicyBodyForTest(t, snapshot, dnsPolicyRequest{Mode: "doh", Host: "9.9.9.9"})
			switch fault {
			case "missing identity":
				raw = []byte(`{"mode":"doh","host":"9.9.9.9"}`)
			case "foreign field":
				raw = bytes.Replace(raw, []byte(`"mode":`), []byte(`"password":"replacement","mode":`), 1)
			case "trailing JSON":
				raw = append(raw, []byte(" {}")...)
			case "oversized":
				raw = append(raw, bytes.Repeat([]byte(" "), 16<<10)...)
			case "busy":
				a.state.Phase = "connecting"
			case "operation":
				a.operationMu.Lock()
				defer a.operationMu.Unlock()
			case "persistence":
				a.cfg.ProfilesFile = t.TempDir()
			}
			before := cloneRouterProfileStore(a.profiles)
			w := postDNSPolicyForTest(a, bytes.NewReader(raw))
			if w.Code < 400 || !reflect.DeepEqual(a.profiles, before) {
				t.Fatal("unowned/failed DNS save changed stored private source", fault, w.Code, w.Body.String())
			}
		})
	}
}

func TestExternalDNSPolicySavedParametersCompileIntoRealNativeGraph(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			p, exit := desktopExternalNativeFixture(t, protocol)
			updated, err := applyCapturedDNSPolicy(p, common.RouterProfile{}, dnsPolicyRequest{Mode: "doh", Host: "9.9.9.9", Port: 8443, ServerName: "dns.quad9.net", Path: "/owned-query"})
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileDesktopExternalCaptured(context.Background(), updated, common.RouterProfile{}, exit, true, "", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var graph map[string]any
			if err := json.Unmarshal(launch.config, &graph); err != nil {
				t.Fatal(err)
			}
			dns := graph["dns"].(map[string]any)
			servers := dns["servers"].([]any)
			if len(servers) != 1 {
				t.Fatal("native graph acquired an unrequested resolver")
			}
			server := servers[0].(map[string]any)
			if server["type"] != "https" || server["server"] != "9.9.9.9" || server["server_port"] != float64(8443) || server["path"] != "/owned-query" || server["tls"].(map[string]any)["server_name"] != "dns.quad9.net" || server["detour"] != "custom-exit" {
				t.Fatal("native compiler changed the editor's resolver/transport/path", server)
			}
		})
	}
}

func TestDNSPolicyLegacyRouterRequestAndCapturedRequestRemainCompatible(t *testing.T) {
	a := setupProfileTestApp(t)
	w := postDNSPolicyForTest(a, strings.NewReader(`{"mode":"doh","host":"9.9.9.9"}`))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	snapshot := dnsPolicySnapshotForTest(t, a)
	w = postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, dnsPolicyRequest{Mode: "custom", Protocol: "tcp", Host: "8.8.8.8"})))
	if w.Code != http.StatusOK || a.profiles.Profiles[0].DNSHost != "8.8.8.8" {
		t.Fatal(w.Code, w.Body.String())
	}
	snapshot = dnsPolicySnapshotForTest(t, a)
	before := cloneRouterProfileStore(a.profiles)
	w = postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, dnsPolicyRequest{Mode: "home", Protocol: "tls", Host: "10.77.0.1", Port: 853, ServerName: "home.example"})))
	if w.Code != http.StatusBadRequest || !reflect.DeepEqual(a.profiles, before) {
		t.Fatal("a Router Home preset silently substituted UDP for an explicit TLS edit")
	}
}
