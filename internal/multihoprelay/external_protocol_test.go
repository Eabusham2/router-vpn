package multihoprelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

var externalProtocols = []string{"shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"}
var externalLayers = []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"}

func externalProxySource(t *testing.T, protocol, layerMode string) (map[string]any, *StartLayer) {
	t.Helper()
	block := strings.ReplaceAll(protocol, "-", "_")
	profile := map[string]any{"server": "203.0.113.20", "port": 443, "password": "private-inner-credential"}
	switch protocol {
	case "shadowsocks":
		profile["method"] = "aes-256-gcm"
	case "hysteria2":
		profile["tls_server_name"] = "exit.example"
	default:
		delete(profile, "server")
		profile["host"], profile["username"] = "203.0.113.20", "private-proxy-user"
		if protocol == "https-connect" {
			profile["tls_server_name"] = "exit.example"
		}
	}
	source := map[string]any{"protocol": protocol, "expected_public_ip": "203.0.113.88", block: profile,
		"response_probe": map[string]any{"url": "https://203.0.113.20/response", "server_name": "exit.example"}}
	var layer *StartLayer
	if layerMode != "" {
		layer = &StartLayer{Mode: layerMode, API: "http://10.88.0.1:8787", Transport: map[string]any{
			"type": "shadowsocks", "tag": "saved-layer", "server": "203.0.113.20", "server_port": 8388,
			"method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))),
		}}
		raw, _ := json.Marshal(layer)
		var saved map[string]any
		if json.Unmarshal(raw, &saved) != nil {
			t.Fatal("invalid fixture layer")
		}
		source["start_layer"] = saved
	}
	return source, layer
}

func externalProxyFixture(t *testing.T, protocol, layerMode string) (Exit, Request) {
	t.Helper()
	source, layer := externalProxySource(t, protocol, layerMode)
	exit, err := ExternalSelection("exit", protocol, source, layer)
	if err != nil {
		t.Fatal(err)
	}
	request := req()
	request.ExitMode, request.ExitStartLayer = protocol, layerMode
	request.Port, request.Username, request.Password = 26240, strings.Repeat("1", 48), strings.Repeat("2", 48)
	request, err = AuthenticateExternalRequest(exit, request)
	if err != nil {
		t.Fatal(err)
	}
	return exit, request
}

func TestExternalProxyFamiliesOwnNativeRelayAndLayerLifecycle(t *testing.T) {
	for _, protocol := range externalProtocols {
		for _, layer := range externalLayers {
			t.Run(protocol+"/"+layer, func(t *testing.T) {
				exit, request := externalProxyFixture(t, protocol, layer)
				cfg := config()
				cfg.Exits = []Exit{exit}
				r := &runner{}
				manager, err := New(cfg, request.EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				catalog, _ := json.Marshal(map[string]any{"node_id": request.EntryNodeID, "execution": "server", "exits": manager.Available()})
				var capabilities Capabilities
				if json.Unmarshal(catalog, &capabilities) != nil || capabilities.Validate(request.EntryNodeID) != nil {
					t.Fatal("new native proxy was omitted from the validated public catalog")
				}
				for _, secret := range []string{"private-inner-credential", "private-proxy-user", request.ExternalAuthentication, strings.Repeat("c", 64)} {
					if strings.Contains(string(catalog), secret) {
						t.Fatal("private proxy material entered public discovery")
					}
				}
				if layer != "" && strings.Contains(string(catalog), exit.StartLayer.Transport["password"].(string)) {
					t.Fatal("private outer credential entered discovery")
				}
				peer := netip.MustParseAddr("10.77.0.2")
				request = challengedExternalFixture(t, manager, exit, request, peer)
				lease, err := manager.Create(context.Background(), peer, request)
				if err != nil || lease.Request != request || lease.ExitNodeID != "" {
					t.Fatal("owned external relay failed", err)
				}
				var graph map[string]any
				if json.Unmarshal(r.configs[0], &graph) != nil || graph["dns"] != nil || graph["endpoints"] != nil || graph["services"] != nil {
					t.Fatal("proxy lease acquired an unowned DNS/system tunnel")
				}
				route := graph["route"].(map[string]any)
				rules := route["rules"].([]any)
				if len(rules) != 2 || rules[0].(map[string]any)["source_ip_cidr"].([]any)[0] != "10.77.0.2/32" ||
					rules[0].(map[string]any)["invert"] != true || rules[0].(map[string]any)["action"] != "reject" ||
					rules[1].(map[string]any)["domain_regex"].([]any)[0] != "." || rules[1].(map[string]any)["action"] != "reject" || route["default_domain_resolver"] != nil {
					t.Fatal("proxy lease lost peer or selected-client-DNS isolation")
				}
				outbounds := graph["outbounds"].([]any)
				inner := outbounds[0].(map[string]any)
				if inner["type"] != exit.Transport["type"] || inner["password"] != exit.Transport["password"] || inner["server_port"] != exit.Transport["server_port"] {
					t.Fatal("running native proxy changed the captured protocol/credential")
				}
				if protocol == "hysteria2" || protocol == "https-connect" {
					if inner["tls"].(map[string]any)["server_name"] != "exit.example" || inner["tls"].(map[string]any)["enabled"] != true {
						t.Fatal("native proxy lost captured TLS validation")
					}
				}
				if layer == "" {
					if len(outbounds) != 1 || inner["server"] != "203.0.113.20" || inner["detour"] != nil {
						t.Fatal("bare proxy acquired an unselected layer")
					}
				} else {
					outer := outbounds[1].(map[string]any)
					wantType := "shadowsocks"
					if layer == "aes-256-gcm+xor-whitening" {
						wantType = "routervpn-aes-xor"
					}
					if len(outbounds) != 2 || inner["server"] != "10.88.0.1" || inner["detour"] != ExitStartLayerTag || outer["type"] != wantType ||
						outer["server"] != "203.0.113.20" || outer["password"] != exit.StartLayer.Transport["password"] || outer["detour"] != nil {
						t.Fatal("native exit layer lost captured endpoint, secret or route ownership")
					}
				}
				if _, err := manager.Create(context.Background(), peer, request); err != nil || r.starts != 1 {
					t.Fatal("renewal replaced its native engine", err)
				}
				wrong := request
				wrong.SessionID = strings.Repeat("b", 32)
				if manager.Delete(context.Background(), peer, wrong) == nil || !r.processes[0].alive {
					t.Fatal("foreign session stopped this proxy")
				}
				if manager.Delete(context.Background(), peer, request) != nil || r.processes[0].alive || len(manager.leases) != 0 {
					t.Fatal("native proxy cleanup lost its owner")
				}
			})
		}
	}
}

func TestExternalProxyPublicIdentityOmitsAllSecretsButPrivateProofBindsThem(t *testing.T) {
	for _, protocol := range externalProtocols {
		for _, layer := range externalLayers {
			t.Run(protocol+"/"+layer, func(t *testing.T) {
				for _, credential := range []string{"password", "username", "outer"} {
					if credential == "username" && (protocol == "shadowsocks" || protocol == "hysteria2") || credential == "outer" && layer == "" {
						continue
					}
					exit, request := externalProxyFixture(t, protocol, layer)
					originalRaw, _ := json.Marshal(exit)
					var original Exit
					if json.Unmarshal(originalRaw, &original) != nil {
						t.Fatal("fixture ownership")
					}
					if credential == "outer" {
						exit.StartLayer.Transport["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
					} else {
						exit.Transport[credential] = "different-private-credential"
					}
					fingerprint, err := ExternalFingerprint(exit)
					if err != nil || fingerprint != request.ExternalFingerprint {
						t.Fatal("public identity became a verifier of "+credential, err)
					}
					next, err := AuthenticateExternalRequest(exit, request)
					if err != nil || next.ExternalAuthentication == request.ExternalAuthentication || ValidateExternalRequest(exit, request) == nil {
						t.Fatal("private request did not bind "+credential, err)
					}
					cfg := config()
					cfg.Exits = []Exit{exit}
					r := &runner{}
					manager, err := New(cfg, request.EntryNodeID, r)
					if err != nil {
						t.Fatal(err)
					}
					request = challengedExternalFixture(t, manager, original, request, netip.MustParseAddr("10.77.0.2"))
					if _, err := manager.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), request); err == nil || r.starts != 0 {
						t.Fatal("substituted private credential started a server engine")
					}
				}
			})
		}
	}
}

func TestExternalSelectionFreezesPrivateLayerAndRejectsUnownedCapture(t *testing.T) {
	for _, protocol := range externalProtocols {
		t.Run(protocol, func(t *testing.T) {
			source, layer := externalProxySource(t, protocol, "aes-256-gcm+xor-whitening")
			exit, err := ExternalSelection("exit", protocol, source, layer)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(exit)
			source["response_probe"].(map[string]any)["url"] = "https://203.0.113.20/new"
			source[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)["password"] = "new-captured-secret"
			layer.Transport["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
			after, _ := json.Marshal(exit)
			if string(before) != string(after) {
				t.Fatal("external selection retained caller-owned mutable credentials")
			}
			for name, change := range map[string]func(map[string]any, *StartLayer){
				"foreign layer":         func(_ map[string]any, l *StartLayer) { l.Transport["server"] = "203.0.113.21" },
				"selected mode changed": func(_ map[string]any, l *StartLayer) { l.Mode = "aes-256-gcm" },
				"opaque field":          func(e map[string]any, _ *StartLayer) { e["helper_script"] = "private" },
				"probe substitution": func(e map[string]any, _ *StartLayer) {
					e["response_probe"].(map[string]any)["url"] = "https://203.0.113.21/response"
				},
				"policy injection":  func(e map[string]any, _ *StartLayer) { e["dns_server"] = "8.8.8.8" },
				"unknown layer key": func(e map[string]any, _ *StartLayer) { e["start_layer"].(map[string]any)["helper"] = "secret" },
				"null layer":        func(e map[string]any, _ *StartLayer) { e["start_layer"] = nil },
				"missing layer":     func(e map[string]any, _ *StartLayer) { delete(e, "start_layer") },
			} {
				source, layer = externalProxySource(t, protocol, "aes-256-gcm+xor-whitening")
				change(source, layer)
				if _, err := ExternalSelection("exit", protocol, source, layer); err == nil {
					t.Fatal("accepted unowned selection: " + name)
				}
			}
		})
	}
}

func TestExternalProxyAuthenticationAndTransportCannotBeDowngraded(t *testing.T) {
	for _, protocol := range externalProtocols {
		t.Run(protocol, func(t *testing.T) {
			for _, password := range []any{"", "a\nb", "a\rb", "a\x00b", string([]byte{0xff}), strings.Repeat("x", 4097), nil, true} {
				source, _ := externalProxySource(t, protocol, "")
				source[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)["password"] = password
				if _, err := ExternalSelection("exit", protocol, source, nil); err == nil {
					t.Fatal("invalid private authentication accepted")
				}
			}
			for name, change := range map[string]func(*Exit){
				"no public egress":   func(e *Exit) { e.External.ExpectedPublicIP = "" },
				"Router identity":    func(e *Exit) { e.NodeID = strings.Repeat("b", 64) },
				"DNS override":       func(e *Exit) { e.DNS = "8.8.8.8" },
				"unowned detour":     func(e *Exit) { e.Transport["detour"] = "direct" },
				"host file":          func(e *Exit) { e.Transport["private_key_path"] = "/etc/private" },
				"nested credentials": func(e *Exit) { e.Transport["password"] = map[string]any{"text": "secret"} },
				"hostname endpoint":  func(e *Exit) { e.Transport["server"] = "exit.example" },
				"private endpoint":   func(e *Exit) { e.Transport["server"] = "192.168.50.1" },
			} {
				exit, _ := externalProxyFixture(t, protocol, "")
				change(&exit)
				cfg := config()
				cfg.Exits = []Exit{exit}
				if _, err := New(cfg, req().EntryNodeID, &runner{}); err == nil {
					t.Fatal("registry accepted " + name)
				}
			}
		})
	}
	for _, protocol := range []string{"socks5", "http-connect", "https-connect"} {
		source, _ := externalProxySource(t, protocol, "")
		profile := source[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)
		delete(profile, "username")
		delete(profile, "password")
		delete(source, "response_probe")
		if _, err := ExternalTransport(protocol, source); err != nil {
			t.Fatal("Local-only uncredentialed proxy was incorrectly tied to comparison proof", err)
		}
		source["response_probe"] = map[string]any{"url": "https://203.0.113.20/response", "server_name": "exit.example"}
		if _, err := ExternalSelection("exit", protocol, source, nil); err == nil {
			t.Fatal("uncredentialed proxy created an empty-secret relay authenticator")
		}
	}
	for _, protocol := range []string{"hysteria2", "https-connect"} {
		for _, tls := range []any{nil, map[string]any{"enabled": true, "server_name": "exit.example", "insecure": true}, map[string]any{"enabled": true, "server_name": "exit.example", "certificate_path": "/etc/private"}} {
			exit, _ := externalProxyFixture(t, protocol, "")
			exit.Transport["tls"] = tls
			if _, err := ExternalFingerprint(exit); err == nil {
				t.Fatal("unverified or opaque TLS entered the relay")
			}
		}
	}
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		source, _, _ := externalPacketSource(t, protocol, "")
		delete(source, "server_peer")
		if _, err := ExternalSelection("exit", protocol, source, nil); err == nil {
			t.Fatal("packet credentials reused without independently provisioned server peer")
		}
	}
	for _, protocol := range []string{"unknown"} {
		if ExternalMode(protocol) {
			t.Fatal("packet/session credentials cannot be reused as proxy credentials")
		}
	}
}

func TestStartLayerTypedImportRejectsAmbiguousOrDroppedPrivateFields(t *testing.T) {
	_, layer := externalProxySource(t, "hysteria2", "aes-256-gcm")
	raw, _ := json.Marshal(layer)
	var decoded StartLayer
	if json.Unmarshal(raw, &decoded) != nil {
		t.Fatal("valid captured layer rejected")
	}
	for _, invalid := range []string{
		`null`, `[]`, `{}`, `{"mode":"aes-256-gcm","api":"http://10.88.0.1:8787","transport":null}`,
		`{"mode":false,"api":"http://10.88.0.1:8787","transport":{"a":1}}`,
		`{"mode":"aes-256-gcm","api":[],"transport":{"a":1}}`,
		strings.Replace(string(raw), `"mode":`, `"helper":"private","mode":`, 1),
		strings.Replace(string(raw), `"mode":`, `"mode":"off","mode":`, 1),
		strings.Replace(string(raw), `"password":`, `"password":"other","password":`, 1),
	} {
		if json.Unmarshal([]byte(invalid), &decoded) == nil {
			t.Fatal("ambiguous/private layer fields were discarded during typed import")
		}
	}
}

func TestLocalAnonymousProxyLayerPreservesAbsentCredentials(t *testing.T) {
	for _, protocol := range []string{"socks5", "http-connect", "https-connect"} {
		for _, layerMode := range externalLayers[1:] {
			source, layer := externalProxySource(t, protocol, layerMode)
			transport, err := ExternalTransport(protocol, source)
			if err != nil {
				t.Fatal(err)
			}
			delete(transport, "username")
			delete(transport, "password")
			inner, _, err := WrapStartLayer(transport, protocol, layer, ExitStartLayerTag, "")
			if err != nil || inner["username"] != nil || inner["password"] != nil {
				t.Fatal("anonymous Local layer acquired invented credentials", protocol, err)
			}
			for _, field := range []string{"username", "password"} {
				for _, value := range []any{"", "secret", nil, true, string([]byte{0xff})} {
					malformed, _ := copyMap(transport)
					malformed[field] = value
					if _, _, err := WrapStartLayer(malformed, protocol, layer, ExitStartLayerTag, ""); err == nil {
						t.Fatal("one-sided or invalid Local proxy credential accepted", protocol, field)
					}
				}
			}
		}
	}
}
