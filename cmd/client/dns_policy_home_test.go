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
	"strconv"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func homeDNSRequest(protocol, host string) dnsPolicyRequest {
	return dnsPolicyRequest{Mode: "home", Protocol: protocol, Host: host, Port: 5443, ServerName: "adguard.home.example", Path: "/owned-query"}
}

func TestRouterHomeDNSPreservesExactTransportThroughNativeCompilerAndProof(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "dot", "doh", "doh3"} {
		for _, ipv6 := range []bool{false, true} {
			t.Run(protocol+map[bool]string{false: "/IPv4", true: "/IPv6"}[ipv6], func(t *testing.T) {
				p, files := desktopNodeFixture(t, "198.51.100.8")
				p.AdGuardIPv6 = "fd77:77::53"
				host := p.AdGuardIPv4
				if ipv6 {
					host = p.AdGuardIPv6
				}
				before := cloneRouterProfile(p)
				updated, err := applyDNSPolicyToProfile(p, homeDNSRequest(protocol, host))
				if err != nil {
					t.Fatal(err)
				}
				unchanged := cloneRouterProfile(updated)
				copyDNSPolicy(&unchanged, before)
				if !reflect.DeepEqual(before, unchanged) {
					t.Fatal("Home DNS changed credentials, source or another preference")
				}
				selected, err := expectedDNSSelection(updated)
				if err != nil {
					t.Fatal(err)
				}
				wantProtocol := map[string]string{"udp": "udp", "tcp": "tcp", "dot": "tls", "doh": "https", "doh3": "h3"}[protocol]
				if selected.Mode != "home" || selected.Protocol != wantProtocol || selected.Host != host || selected.Port != 5443 {
					t.Fatal("Home selection changed the transport, port or node", selected)
				}
				compiled, _, err := compileDesktopNode(context.Background(), updated, "wg", files, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				var graph map[string]any
				if err := json.Unmarshal([]byte(compiled.Config()), &graph); err != nil {
					t.Fatal(err)
				}
				servers := graph["dns"].(map[string]any)["servers"].([]any)
				server := servers[0].(map[string]any)
				if len(servers) != 1 || server["server"] != host || server["server_port"] != float64(5443) || server["type"] != wantProtocol || server["detour"] != "proxy" {
					t.Fatal("actual native graph substituted or bypassed Home", server)
				}
				root := t.TempDir()
				a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}}
				config := filepath.Join(root, "run", "captured", "sing-box.json")
				if err := os.MkdirAll(filepath.Dir(config), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(config, []byte(compiled.Config()), 0600); err != nil {
					t.Fatal(err)
				}
				if err := verifySingBoxDNSConfig(config, selected); err != nil {
					t.Fatal(err)
				}
				if err := registerActiveDNSRuntimeConfig(a, p.ID, "wg", config); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { clearActiveDNSRuntimeConfig(a) })
				calls := 0
				proof := proveSelectedDNSWithLookup(context.Background(), a, observedConnection{Profile: updated, RouterID: p.ID, Connected: true, Phase: "connected"}, "wg", func(ctx context.Context, name string) ([]string, error) {
					calls++
					if _, bounded := ctx.Deadline(); !bounded || name != "example.com" {
						t.Fatal("proof lost its bounded query")
					}
					return []string{"192.0.2.80"}, nil
				})
				if proof.Status != "passed" || calls != 1 || proof.Host != host || !strings.Contains(proof.Reason, wantProtocol+"://") {
					t.Fatal("captured native Home graph could not reach its owned proof", proof)
				}
			})
		}
	}
}

func TestRouterHomeDNSRejectsForeignMissingOrInvalidPolicyWithoutFallback(t *testing.T) {
	for name, change := range map[string]func(*common.RouterProfile, *dnsPolicyRequest){
		"foreign-private":   func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Host = "10.78.0.53" },
		"public-fallback":   func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Host = "1.1.1.1" },
		"hostname":          func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Host = "resolver.example" },
		"mapped":            func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Host = "::ffff:192.168.50.133" },
		"zone":              func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Host = "fd77::53%en0" },
		"zero-address":      func(p *common.RouterProfile, _ *dnsPolicyRequest) { p.AdGuardIPv4 = "" },
		"bad-saved-address": func(p *common.RouterProfile, _ *dnsPolicyRequest) { p.AdGuardIPv4 = "8.8.8.8" },
		"wrong-family":      func(p *common.RouterProfile, _ *dnsPolicyRequest) { p.AdGuardIPv6 = "10.77.0.53" },
		"ipv6-off": func(p *common.RouterProfile, r *dnsPolicyRequest) {
			p.IPv6Mode = "off"
			p.AdGuardIPv6 = "fd77::53"
			r.Host = p.AdGuardIPv6
		},
		"transport":        func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Protocol = "smtp" },
		"negative-port":    func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Port = -1 },
		"large-port":       func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Port = 65536 },
		"no-tls-name":      func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.ServerName = "" },
		"tls-url":          func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.ServerName = "https://adguard.home.example" },
		"tls-port":         func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.ServerName = "adguard.home.example:443" },
		"tls-single-label": func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.ServerName = "localhost" },
		"absolute-path":    func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Path = "https://foreign.example/query" },
		"authority-path":   func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Path = "//foreign.example/query" },
		"query":            func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Path = "/query?other=1" },
		"fragment":         func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Path = "/query#other" },
		"backslash":        func(_ *common.RouterProfile, r *dnsPolicyRequest) { r.Path = "/query\\other" },
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := desktopNodeFixture(t, "198.51.100.8")
			r := homeDNSRequest("https", p.AdGuardIPv4)
			change(&p, &r)
			before := cloneRouterProfile(p)
			got, err := applyDNSPolicyToProfile(p, r)
			if err == nil || !reflect.DeepEqual(got, before) {
				t.Fatal("invalid Home policy was changed, substituted or accepted")
			}
			p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort, p.DNSServerName, p.DNSPath = r.Mode, r.Protocol, r.Host, r.Port, r.ServerName, r.Path
			if _, err := expectedDNSSelection(p); err == nil {
				t.Fatal("invalid Home acquired expected proof")
			}
			if _, err := desktopNodeDNSBootstrap(p); err == nil {
				t.Fatal("invalid Home reached native bootstrap")
			}
		})
	}
}

func TestRouterHomeDNSDefaultAndTransportPortsAreExplicit(t *testing.T) {
	p := dnsTestProfile()
	for protocol, port := range map[string]int{"": 53, "udp": 53, "tcp": 53, "dot": 853, "tls": 853, "doh": 443, "https": 443, "doh3": 443, "h3": 443} {
		r := homeDNSRequest(protocol, "")
		r.Port = 0
		got, err := applyDNSPolicyToProfile(p, r)
		if err != nil || got.DNSPort != port || got.DNSHost != p.AdGuardIPv4 {
			t.Fatal(protocol, got.DNSPort, err)
		}
		if (got.DNSProtocol == "udp" || got.DNSProtocol == "tcp") && (got.DNSServerName != "" || got.DNSPath != "") {
			t.Fatal("unused encrypted fields survived plain transport")
		}
		if got.DNSProtocol == "tls" && got.DNSPath != "" {
			t.Fatal("DoT retained an unused HTTP path")
		}
	}
}

func TestRouterHomeDNSTLSProofRejectsDifferentIdentityPathAndDuplicateOwner(t *testing.T) {
	p, files := desktopNodeFixture(t, "198.51.100.8")
	p, err := applyDNSPolicyToProfile(p, homeDNSRequest("doh", p.AdGuardIPv4))
	if err != nil {
		t.Fatal(err)
	}
	compiled, _, err := compileDesktopNode(context.Background(), p, "wg", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := expectedDNSSelection(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any, map[string]any){
		"wrong-name":         func(_ map[string]any, s map[string]any) { s["tls"].(map[string]any)["server_name"] = "another.example" },
		"insecure":           func(_ map[string]any, s map[string]any) { s["tls"].(map[string]any)["insecure"] = true },
		"malformed-insecure": func(_ map[string]any, s map[string]any) { s["tls"].(map[string]any)["insecure"] = "false" },
		"disabled-tls":       func(_ map[string]any, s map[string]any) { s["tls"].(map[string]any)["enabled"] = false },
		"path":               func(_ map[string]any, s map[string]any) { s["path"] = "/wrong-query" },
		"duplicate":          func(g map[string]any, s map[string]any) { g["dns"].(map[string]any)["servers"] = []any{s, s} },
		"different-duplicate": func(g map[string]any, s map[string]any) {
			g["dns"].(map[string]any)["servers"] = []any{s, map[string]any{"tag": "selected-dns", "server": "1.1.1.1"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var graph map[string]any
			_ = json.Unmarshal([]byte(compiled.Config()), &graph)
			server := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			mutate(graph, server)
			raw, _ := json.Marshal(graph)
			path := filepath.Join(t.TempDir(), "sing-box.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifySingBoxDNSConfig(path, selected); err == nil {
				t.Fatal("wrong encrypted DNS policy passed proof")
			}
		})
	}
}

func TestRouterHomeDNSCapturedAPISaveAndConnectionProfileRestore(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			a := setupProfileTestApp(t)
			p, _ := desktopNodeFixture(t, "198.51.100.8")
			p.ID = "home"
			p.BaseTunnel = "auto"
			p.StartupMode = "smart-auto"
			p.KillSwitchPolicy = "off"
			a.profiles.Profiles[0] = p
			before := cloneRouterProfileStore(a.profiles)
			snapshot := dnsPolicySnapshotForTest(t, a)
			request := homeDNSRequest(protocol, p.AdGuardIPv4)
			w := postDNSPolicyForTest(a, bytes.NewReader(dnsPolicyBodyForTest(t, snapshot, request)))
			if w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body.String())
			}
			saved := cloneRouterProfile(a.profiles.Profiles[0])
			if saved.DNSProtocol != protocol || saved.DNSPort != 5443 || saved.DNSHost != p.AdGuardIPv4 {
				t.Fatal("API rewrote Home transport")
			}
			unchanged := cloneRouterProfileStore(a.profiles)
			copyDNSPolicy(&unchanged.Profiles[0], before.Profiles[0])
			unchanged.Profiles[0].SchemaVersion = before.Profiles[0].SchemaVersion
			// Persistence may canonicalize legacy defaults; private identity and all
			// other nodes must still remain exact.
			if saved.APIToken != p.APIToken || saved.NodeProofID != p.NodeProofID || !reflect.DeepEqual(a.profiles.Profiles[1:], before.Profiles[1:]) {
				t.Fatal("DNS save changed node credentials or another node")
			}
			rr := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Home encrypted", "mode": "smart-auto", "multihop_enabled": false})
			if rr.Code != http.StatusOK {
				t.Fatal(rr.Code, rr.Body.String())
			}
			store, err := loadConnectionProfileStore(a)
			if err != nil {
				t.Fatal(err)
			}
			if len(store.Profiles) != 1 || !store.Profiles[0].Prefs.HomeDNSCaptured {
				t.Fatal("new explicit Home snapshot lost its capture marker")
			}
			id := store.Profiles[0].ID
			a.profiles.Profiles[0].DNSMode = "custom"
			a.profiles.Profiles[0].DNSProtocol = "tcp"
			a.profiles.Profiles[0].DNSHost = "9.9.9.9"
			a.profiles.Profiles[0].DNSPort = 53
			rr = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if rr.Code != http.StatusOK {
				t.Fatal(rr.Code, rr.Body.String())
			}
			got := a.profiles.Profiles[0]
			if got.DNSMode != "home" || got.DNSProtocol != saved.DNSProtocol || got.DNSHost != saved.DNSHost || got.DNSPort != saved.DNSPort || got.DNSServerName != saved.DNSServerName || got.DNSPath != saved.DNSPath {
				t.Fatal("saved Home policy was normalized into another resolver or transport")
			}
			raw, err := os.ReadFile(connectionProfileStorePath(a))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(p.APIToken)) {
				t.Fatal("Home capture copied private credentials")
			}
			a.profiles.Profiles[0].AdGuardIPv4 = "10.78.0.53"
			changed := cloneRouterProfileStore(a.profiles)
			bad := httptest.NewRecorder()
			a.loadConnectionProfile(bad, httptest.NewRequest(http.MethodPost, "/api/connection-profile/load", strings.NewReader(`{"id":"`+id+`"}`)))
			if bad.Code != http.StatusConflict || !reflect.DeepEqual(changed, a.profiles) {
				t.Fatal("saved Home was restored onto a changed node resolver", bad.Code, bad.Body.String())
			}
		})
	}
}

func TestConnectionProfileExplicitHomeRejectsMalformedCapture(t *testing.T) {
	for _, raw := range []string{
		`{"home_dns_captured":null}`, `{"home_dns_captured":"true"}`, `{"home_dns_captured":true,"dns_mode":"custom"}`,
		`{"home_dns_captured":true,"dns_mode":"home","dns_protocol":"https","dns_host":"10.77.0.53","dns_server_name":""}`,
		`{"home_dns_captured":true,"dns_mode":"home","dns_protocol":"tcp","dns_host":"1.1.1.1"}`,
		`{"home_dns_captured":true,"dns_mode":"home","dns_protocol":"udp"}`,
	} {
		var p connectionProfilePreferences
		if json.Unmarshal([]byte(raw), &p) == nil {
			t.Fatal("malformed exact Home capture accepted", raw)
		}
	}
}

func TestRouterHomeDNSKernelHintRetainsExactTransportIdentity(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			p, _ := desktopNodeFixture(t, "198.51.100.8")
			p, err := applyDNSPolicyToProfile(p, homeDNSRequest(protocol, p.AdGuardIPv4))
			if err != nil {
				t.Fatal(err)
			}
			selected, err := expectedDNSSelection(p)
			if err != nil {
				t.Fatal(err)
			}
			hint := map[string]string{"mode": "home", "protocol": protocol, "server": selected.Host + ":" + strconv.Itoa(selected.Port), "server_name": selected.ServerName, "path": selected.Path}
			if err := verifyDNSHintSelection(hint, selected); err != nil {
				t.Fatal("exact policy was rejected", err)
			}
			fields := []string{"mode", "protocol", "server"}
			if protocol == "tls" || protocol == "https" || protocol == "h3" {
				fields = append(fields, "server_name")
			}
			if protocol == "https" || protocol == "h3" {
				fields = append(fields, "path")
			}
			for _, field := range fields {
				original := hint[field]
				hint[field] = "another-owner"
				if err := verifyDNSHintSelection(hint, selected); err == nil {
					t.Fatal("changed hint accepted", field)
				}
				hint[field] = original
			}
		})
	}
	root := t.TempDir()
	directory := filepath.Join(root, "run", "profile-home-wg")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "wg.conf"), []byte("[Interface]\nDNS = 127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "run", "dns.txt")
	selected := dnsSelection{Mode: "home", Protocol: "https", Host: "10.77.0.53", Port: 8443, ServerName: "home.example.test", Path: "/owned-query"}
	for _, text := range []string{
		"mode=home\nprotocol=https\nserver=10.77.0.53:8443\n",
		"mode=home\nprotocol=https\nserver=10.77.0.53:8443\nserver_name=home.example.test\npath=/different-query\n",
		"mode=home\nprotocol=https\nserver=10.77.0.53:8443\nserver_name=home.example.test\npath=/owned-query\npath=/owned-query\n",
	} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		err := verifyKernelDNSRuntimeContext(context.Background(), root, "home", "wg", selected)
		if err == nil || strings.Contains(err.Error(), "local DNS proxy proof") {
			t.Fatal("invalid hint reached ambient DNS lookup", err)
		}
	}
}
