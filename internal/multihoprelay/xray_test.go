package multihoprelay

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func nativeXrayExit(t *testing.T, mode string) Exit {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	user := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision", "encryption": "none"}
	stream := map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "paired.example.test", "fingerprint": "chrome", "password": base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), "shortId": "0123456789abcdef"}}
	if mode != "reality-vision" {
		user["encryption"] = "mlkem768x25519plus.native.0rtt.fixture-protocol-validator-only"
	}
	if mode == "reality-xhttp" {
		delete(user, "flow")
		stream["network"] = "xhttp"
		stream["xhttpSettings"] = map[string]any{"path": "/authenticated-stream", "mode": "auto"}
	}
	raw, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"protocol": "socks", "listen": "127.0.0.1", "port": 1090, "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "192.0.2.9", "port": 443, "users": []any{user}}}}, "streamSettings": stream}}})
	if err != nil {
		t.Fatal(err)
	}
	return Exit{ID: "exit", Mode: mode, DNS: "10.88.0.1", NodeID: strings.Repeat("b", 64), Transport: map[string]any{"type": "routervpn-xray", "mode": mode, "tag": "proxy", "config_json": string(raw)}}
}
func TestNativeXrayRelayKeepsPairedTransportAndPrivateLease(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config()
			exit := nativeXrayExit(t, mode)
			cfg.Exits = []Exit{exit}
			r := &runner{}
			m, err := New(cfg, req().EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close(context.Background())
			q := req()
			q.ExitMode = mode
			peer := netip.MustParseAddr("10.77.0.2")
			lease, err := m.Create(context.Background(), peer, q)
			if err != nil {
				t.Fatal(err)
			}
			if lease.ExitMode != mode || lease.ExitNodeID != exit.NodeID || r.starts != 1 {
				t.Fatal("relay ownership or mode changed")
			}
			var graph map[string]any
			if err = json.Unmarshal(r.configs[0], &graph); err != nil {
				t.Fatal(err)
			}
			out := graph["outbounds"].([]any)[0].(map[string]any)
			if len(graph["outbounds"].([]any)) != 1 || out["config_json"] != exit.Transport["config_json"] || out["mode"] != mode || out["tag"] != "exit" || len(out) != 4 {
				t.Fatal("paired Xray authentication or graph substituted")
			}
			if graph["endpoints"] != nil || len(graph["inbounds"].([]any)) != 1 {
				t.Fatal("unowned network interface or listener")
			}
			dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if dns["server"] != exit.DNS || dns["detour"] != "exit" {
				t.Fatal("resolver left paired exit")
			}
			inbound := graph["inbounds"].([]any)[0].(map[string]any)
			if inbound["listen"] != cfg.ListenIP || inbound["type"] != "socks" {
				t.Fatal("relay listener exposed outside private endpoint")
			}
			rule := graph["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
			if rule["source_ip_cidr"].([]any)[0] != "10.77.0.2/32" || rule["action"] != "reject" || rule["invert"] != true {
				t.Fatal("client-peer isolation lost")
			}
			public, _ := json.Marshal(m.Available())
			for _, secret := range []string{"config_json", "11111111-1111-4111-8111-111111111111", "fixture-protocol-validator-only"} {
				if strings.Contains(string(public), secret) {
					t.Fatal("capabilities exposed paired configuration")
				}
			}
			again, err := m.Create(context.Background(), peer, q)
			if err != nil || again.Password != lease.Password || r.starts != 1 {
				t.Fatal("renewal replaced the owned encrypted engine")
			}
			if err = m.Delete(context.Background(), peer, q); err != nil || r.processes[0].alive {
				t.Fatal("relay teardown did not release its engine")
			}
		})
	}
}
func TestNativeXrayRelayRejectsUnownedDialPolicyAndProtocol(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, fault := range []string{"label", "raw", "detour", "network", "bind_interface", "certificate_path", "server", "private_key"} {
			cfg := config()
			exit := nativeXrayExit(t, mode)
			switch fault {
			case "label":
				exit.Transport["mode"] = "max"
			case "raw":
				exit.Transport["config_json"] = `{"private":"must-not-print"}`
			default:
				exit.Transport[fault] = "must-not-print"
			}
			cfg.Exits = []Exit{exit}
			r := &runner{}
			if _, err := New(cfg, req().EntryNodeID, r); err == nil || strings.Contains(err.Error(), "must-not-print") || r.starts != 0 {
				t.Fatal("unsafe native transport accepted or echoed private bytes", fault)
			}
		}
	}
}
