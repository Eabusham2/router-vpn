package multihoprelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func externalOpenVPNSource(t *testing.T, layerMode string) (map[string]any, map[string]any, *StartLayer) {
	t.Helper()
	config := "client\nremote 203.0.113.20 1194 udp\nremote 203.0.113.20 443 tcp\nremote-random\nauth-user-pass\npeer-fingerprint " + strings.Repeat("a", 64) + "\nverify-x509-name provider.example name\ntls-version-min 1.2\ntls-version-max 1.3\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\nauth SHA256\ntun-mtu 1500\nmssfix 1400 mtu\npull-filter ignore \"dhcp-option DNS\"\nroute-nopull\n"
	private := func(char string) string { return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(char, 32))) }
	server := map[string]any{"protocol": "openvpn", "openvpn": map[string]any{"config": config, "username": "server-provider", "password": "server-private-password"}, "pairing_private_key": private("b")}
	public, err := ExternalOpenVPNServerDescriptor(server)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(public)
	var descriptor map[string]any
	if json.Unmarshal(raw, &descriptor) != nil {
		t.Fatal("fixture descriptor")
	}
	external := map[string]any{"protocol": "openvpn", "expected_public_ip": "203.0.113.88", "response_probe": map[string]any{"url": "https://203.0.113.20/response", "server_name": "provider.example"}, "openvpn": map[string]any{"config": config, "username": "local-provider", "password": "local-private-password"}, "openvpn_pairing": map[string]any{"private_key": private("a"), "server": descriptor}}
	var layer *StartLayer
	if layerMode != "" {
		source, l := externalProxySource(t, "shadowsocks", layerMode)
		layer = l
		if layerMode == "aes-256-gcm+xor-whitening" {
			layer.Transport["server_port"] = 8389
		}
		raw, _ := json.Marshal(layer)
		var captured map[string]any
		_ = json.Unmarshal(raw, &captured)
		external["start_layer"] = captured
		_ = source
	}
	return external, server, layer
}

func externalOpenVPNPair(t *testing.T, layer string) (Exit, Exit, Request) {
	t.Helper()
	external, private, wrapped := externalOpenVPNSource(t, layer)
	client, err := ExternalSelection("exit", "openvpn", external, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	server, err := PairExternalOpenVPN("exit", external, private, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	q := req()
	q.ExitMode = "openvpn"
	q.ExitStartLayer = layer
	q.Port = 26240
	q.Username = strings.Repeat("1", 48)
	q.Password = strings.Repeat("2", 48)
	q, err = AuthenticateExternalRequest(client, q)
	if err != nil {
		t.Fatal(err)
	}
	return client, server, q
}

func TestOpenVPNExternalPairRunsSeparateOwnedUserspaceEndpointAndLayers(t *testing.T) {
	for _, layer := range externalLayers {
		t.Run(layer, func(t *testing.T) {
			client, server, prepared := externalOpenVPNPair(t, layer)
			if client.External.OpenVPN.Owner != "client" || server.External.OpenVPN.Owner != "server" || client.Transport["username"] == server.Transport["username"] {
				t.Fatal("provider ownership was shared")
			}
			clientID, err := ExternalFingerprint(client)
			if err != nil {
				t.Fatal(err)
			}
			serverID, err := ExternalFingerprint(server)
			if err != nil || clientID != serverID {
				t.Fatal("counterpart public pairing identities differ", err)
			}
			if err := ValidateExternalRequest(server, prepared); err != nil {
				t.Fatal("separate owners could not authenticate", err)
			}
			serverJSON, _ := json.Marshal(server)
			clientJSON, _ := json.Marshal(client)
			for _, secret := range []string{"local-private-password", client.External.OpenVPN.PrivateKey} {
				if strings.Contains(string(serverJSON), secret) {
					t.Fatal("Local private material crossed into the Server registry")
				}
			}
			for _, secret := range []string{"server-private-password", server.External.OpenVPN.PrivateKey} {
				if strings.Contains(string(clientJSON), secret) {
					t.Fatal("Server private material crossed into the Local capture")
				}
			}
			cfg := config()
			cfg.Exits = []Exit{server}
			r := &runner{}
			m, err := New(cfg, prepared.EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			peer := netip.MustParseAddr("10.77.0.2")
			q := challengedExternalFixture(t, m, client, prepared, peer)
			lease, err := m.Create(context.Background(), peer, q)
			if err != nil || lease.Request != q {
				t.Fatal("owned OpenVPN server acquisition failed", err)
			}
			var graph map[string]any
			if json.Unmarshal(r.configs[0], &graph) != nil {
				t.Fatal("invalid runtime plan")
			}
			endpoints, ok := graph["endpoints"].([]any)
			if !ok || len(endpoints) != 1 || graph["dns"] != nil || graph["services"] != nil {
				t.Fatal("OpenVPN relay acquired unowned DNS or system services")
			}
			endpoint := endpoints[0].(map[string]any)
			if endpoint["type"] != "openvpn-client" || endpoint["system"] != false || endpoint["tag"] != "exit" || endpoint["username"] != "server-provider" || endpoint["password"] != "server-private-password" {
				t.Fatal("runtime lost its independently owned native provider profile")
			}
			remotes := endpoint["servers"].([]any)
			if len(remotes) != 2 || endpoint["server"] != nil || endpoint["remote_random"] != true {
				t.Fatal("server collapsed the captured multi-remote profile")
			}
			wantHost := "203.0.113.20"
			if layer != "" {
				wantHost = "10.88.0.1"
			}
			for i, raw := range remotes {
				remote := raw.(map[string]any)
				if remote["server"] != wantHost || remote["server_port"] != []float64{1194, 443}[i] || remote["network"] != []string{"udp", "tcp"}[i] {
					t.Fatal("layer changed remote transport or ownership")
				}
			}
			outbounds := graph["outbounds"].([]any)
			if layer == "" {
				if len(outbounds) != 0 || endpoint["detour"] != nil {
					t.Fatal("unexpected relay layer")
				}
			} else {
				if len(outbounds) != 1 || endpoint["detour"] != ExitStartLayerTag {
					t.Fatal("missing owned exit layer")
				}
				outer := outbounds[0].(map[string]any)
				if outer["server"] != "203.0.113.20" || outer["detour"] != nil {
					t.Fatal("server layer bypassed physical provider route")
				}
			}
			catalog, _ := json.Marshal(m.Available())
			for _, private := range []string{"server-provider", "local-provider", "server-private-password", "local-private-password", "provider_identity", "pairing_public_key", server.External.OpenVPN.PrivateKey} {
				if strings.Contains(string(catalog), private) {
					t.Fatal("provider identity or private profile entered public discovery")
				}
			}
			var caps Capabilities
			body, _ := json.Marshal(map[string]any{"node_id": q.EntryNodeID, "execution": "server", "exits": m.Available()})
			if json.Unmarshal(body, &caps) != nil || caps.Validate(q.EntryNodeID) != nil {
				t.Fatal("public native OpenVPN capability rejected")
			}
			if err := m.Delete(context.Background(), peer, q); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Create(context.Background(), peer, q); err == nil {
				t.Fatal("deleted OpenVPN acquisition replayed")
			}
			q = challengedExternalFixture(t, m, client, prepared, peer)
			if _, err := m.Create(context.Background(), peer, q); err != nil {
				t.Fatal("repeat winner could not acquire a new proof", err)
			}
			if err := m.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenVPNExternalPairRejectsPrivateOwnerSubstitutionAndNativeInjection(t *testing.T) {
	for name, change := range map[string]func(map[string]any, map[string]any){
		"missing pairing": func(e, s map[string]any) { delete(e, "openvpn_pairing") },
		"wrong pairing key": func(e, s map[string]any) {
			e["openvpn_pairing"].(map[string]any)["private_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
		},
		"same provider username":          func(e, s map[string]any) { s["openvpn"].(map[string]any)["username"] = " LOCAL-PROVIDER " },
		"server replaced by Local source": func(e, s map[string]any) { s["openvpn"] = e["openvpn"] },
		"wrong server key": func(e, s map[string]any) {
			s["pairing_private_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
		},
		"remote transport mismatch": func(e, s map[string]any) {
			s["openvpn"].(map[string]any)["config"] = strings.Replace(s["openvpn"].(map[string]any)["config"].(string), "1194 udp", "1194 tcp", 1)
		},
		"changed public MTU": func(e, s map[string]any) {
			e["openvpn_pairing"].(map[string]any)["server"].(map[string]any)["transport"].(map[string]any)["mtu"] = float64(9000)
		},
		"different remote host": func(e, s map[string]any) {
			e["openvpn"].(map[string]any)["config"] = strings.Replace(e["openvpn"].(map[string]any)["config"].(string), "203.0.113.20 443", "203.0.113.21 443", 1)
		},
		"hidden server private key": func(e, s map[string]any) {
			e["openvpn_pairing"].(map[string]any)["server"].(map[string]any)["private_key"] = "private"
		},
		"arbitrary server private field": func(e, s map[string]any) { s["helper"] = "ignored" },
		"public probe substitution": func(e, s map[string]any) {
			e["response_probe"].(map[string]any)["url"] = "https://203.0.113.21/response"
		},
		"script injection": func(e, s map[string]any) {
			s["openvpn"].(map[string]any)["config"] = s["openvpn"].(map[string]any)["config"].(string) + "up /tmp/private-script\n"
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, s, l := externalOpenVPNSource(t, "")
			change(e, s)
			if _, err := PairExternalOpenVPN("exit", e, s, l); err == nil {
				t.Fatal("unowned OpenVPN pair accepted")
			}
		})
	}
	for name, change := range map[string]func(*Exit){
		"wrong role":                  func(e *Exit) { e.External.OpenVPN.Owner = "client" },
		"changed endpoint credential": func(e *Exit) { e.Transport["password"] = "changed" },
		"changed original source":     func(e *Exit) { e.External.OpenVPN.Profile.Config += "tun-mtu 9000\n" },
		"second system interface":     func(e *Exit) { e.Transport["system"] = true },
		"borrowed packet pair":        func(e *Exit) { e.External.Packet = &ExternalPacketPair{} },
		"native DNS override":         func(e *Exit) { e.Transport["domain_resolver"] = "host" },
		"private source path":         func(e *Exit) { e.Transport["tls"].(map[string]any)["client_key_path"] = "/tmp/private" },
	} {
		t.Run(name, func(t *testing.T) {
			_, server, _ := externalOpenVPNPair(t, "")
			change(&server)
			cfg := config()
			cfg.Exits = []Exit{server}
			if _, err := New(cfg, req().EntryNodeID, &runner{}); err == nil {
				t.Fatal("invalid owned native registry accepted")
			}
		})
	}
	client, _, prepared := externalOpenVPNPair(t, "")
	cfg := config()
	cfg.Exits = []Exit{client}
	if _, err := New(cfg, prepared.EntryNodeID, &runner{}); err == nil {
		t.Fatal("Server registry accepted Local provider credentials")
	}
}

func TestOpenVPNProviderAliasesHaveOneConcurrentRelayOwner(t *testing.T) {
	external, private, layer := externalOpenVPNSource(t, "")
	firstClient, err := ExternalSelection("first", "openvpn", external, layer)
	if err != nil {
		t.Fatal(err)
	}
	first, err := PairExternalOpenVPN("first", external, private, layer)
	if err != nil {
		t.Fatal(err)
	}
	external["openvpn"].(map[string]any)["username"] = "second-local-provider"
	external["openvpn_pairing"].(map[string]any)["private_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32)))
	secondClient, err := ExternalSelection("second", "openvpn", external, layer)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PairExternalOpenVPN("second", external, private, layer)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config()
	cfg.Exits = []Exit{first, second}
	r := &runner{}
	m, err := New(cfg, req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	q := req()
	q.ExitID = "first"
	q.ExitMode = "openvpn"
	q.Port = 26240
	q.Username = strings.Repeat("1", 48)
	q.Password = strings.Repeat("2", 48)
	q, err = AuthenticateExternalRequest(firstClient, q)
	if err != nil {
		t.Fatal(err)
	}
	p1, p2 := netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")
	q = challengedExternalFixture(t, m, firstClient, q, p1)
	if _, err := m.Create(context.Background(), p1, q); err != nil {
		t.Fatal(err)
	}
	other := q
	other.ExitID = "second"
	other.SessionID = strings.Repeat("e", 32)
	other.Port++
	other = challengedExternalFixture(t, m, secondClient, other, p2)
	if _, err := m.Create(context.Background(), p2, other); err == nil || r.starts != 1 {
		t.Fatal("aliased provider username opened another concurrent session")
	}
	r.processes[0].stopFail = true
	if m.Delete(context.Background(), p1, q) == nil {
		t.Fatal("blocked cleanup acknowledged")
	}
	if _, err := m.Create(context.Background(), p2, other); err == nil {
		t.Fatal("failed provider cleanup released session identity")
	}
	r.processes[0].stopFail = false
	if m.Delete(context.Background(), p1, q) != nil {
		t.Fatal("retry cleanup failed")
	}
	if _, err := m.Create(context.Background(), p2, other); err != nil {
		t.Fatal("independent owner could not start after confirmed cleanup", err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOpenVPNPairingFreezesCaptureAndStrictPrivateRegistrySchema(t *testing.T) {
	e, s, layer := externalOpenVPNSource(t, "aes-256-gcm")
	client, err := ExternalSelection("exit", "openvpn", e, layer)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(client)
	e["openvpn"].(map[string]any)["password"] = "changed"
	layer.Transport["password"] = "changed"
	after, _ := json.Marshal(client)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("capture retained caller-owned private maps")
	}
	e, _, layer = externalOpenVPNSource(t, "aes-256-gcm")
	server, err := PairExternalOpenVPN("exit", e, s, layer)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(server.External.OpenVPN)
	for _, invalid := range []string{"null", "[]", string(raw[:len(raw)-1]) + `,"owner":"client"}`, strings.Replace(string(raw), `"profile":{`, `"profile":{"file":"/tmp/profile",`, 1), strings.Replace(string(raw), `"local":{`, `"local":{"private_key":"secret",`, 1)} {
		var pair ExternalOpenVPNPair
		if json.Unmarshal([]byte(invalid), &pair) == nil {
			t.Fatal("private registry decoder dropped ambiguous or secret fields")
		}
	}
}

func TestExportExternalOpenVPNPairingFixtures(t *testing.T) {
	root := os.Getenv("ROUTER_VPN_OPENVPN_PAIR_FIXTURES_DIR")
	if root == "" {
		t.Skip("explicit pairer/native export")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range externalLayers {
		e, s, l := externalOpenVPNSource(t, mode)
		paired, err := PairExternalOpenVPN("exit", e, s, l)
		if err != nil {
			t.Fatal(err)
		}
		public, err := ExternalOpenVPNServerDescriptor(s)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(map[string]any{"external": e, "server_peer_profile": s, "paired": paired, "descriptor": public, "selected_layer": mode})
		if err != nil {
			t.Fatal(err)
		}
		name := mode
		if name == "" {
			name = "off"
		}
		if err := os.WriteFile(filepath.Join(root, name+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
