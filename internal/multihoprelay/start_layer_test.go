package multihoprelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"router-vpn/internal/applexray"
	"router-vpn/internal/awgpolicy"
	"strings"
	"testing"
)

func layerExit(t *testing.T, mode, layer string) Exit {
	t.Helper()
	var exit Exit
	switch mode {
	case "wg":
		exit = identityExit(t, "exit", mode, scalarAlias(t, 0))
	case "awg2-fast", "awg2-strong":
		exit = awgExit(t, mode)
	case "shadowsocks":
		exit = config().Exits[0]
	case "hysteria2":
		exit = config().Exits[0]
		exit.Mode = mode
		exit.Transport = map[string]any{"type": mode, "tag": "proxy", "server": "192.0.2.2", "server_port": 8443, "password": "private-inner-hy", "tls": map[string]any{"enabled": true, "server_name": "exit.example.test"}, "obfs": map[string]any{"type": "salamander", "password": "inner-obfuscation"}}
	default:
		exit = nativeXrayExit(t, mode)
	}
	host := "192.0.2.2"
	if applexray.SingleTransportMode(mode) {
		host = "192.0.2.9"
	}
	exit.StartLayer = &StartLayer{Mode: layer, API: "http://10.88.0.1:8787", Transport: map[string]any{"type": "shadowsocks", "tag": "proxy", "server": host, "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))}}
	return exit
}
func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func TestExitStartLayerPreservesEveryNativeTransportAndBothIPFamilies(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, api := range []string{"http://10.88.0.1:8787", "https://[fd88::1]:8787"} {
				t.Run(mode+layer+api, func(t *testing.T) {
					exit := layerExit(t, mode, layer)
					exit.StartLayer.API = api
					snapshot, _ := json.Marshal(exit)
					original, e := validateTransport(exit)
					if e != nil {
						t.Fatal(e)
					}
					inside, outside, e := WrapStartLayer(original, mode, exit.StartLayer, ExitStartLayerTag, "entry-wg")
					if e != nil {
						t.Fatal(e)
					}
					expected, _ := copyMap(original)
					host := "10.88.0.1"
					if strings.Contains(api, "fd88") {
						host = "fd88::1"
					}
					if awgpolicy.WireGuardFamily(mode) {
						expected["peers"].([]any)[0].(map[string]any)["address"] = host
					} else if applexray.SingleTransportMode(mode) {
						raw, _ := applexray.Object([]byte(expected["config_json"].(string)))
						raw["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = host
						b, _ := json.Marshal(raw)
						expected["config_json"] = string(b)
					} else {
						expected["server"] = host
					}
					expected["detour"] = ExitStartLayerTag
					if !equalJSON(inside, expected) {
						t.Fatal("changed inner authentication, AWG parameters, TLS or MTU")
					}
					outerExpected, _ := copyMap(exit.StartLayer.Transport)
					outerExpected["tag"] = ExitStartLayerTag
					outerExpected["detour"] = "entry-wg"
					if layer == "aes-256-gcm+xor-whitening" {
						outerExpected["type"] = "routervpn-aes-xor"
						outerExpected["server_port"] = 8389
					}
					if !equalJSON(outside, outerExpected) {
						t.Fatal("wrong outer transport or upstream owner")
					}
					after, _ := json.Marshal(exit)
					if string(after) != string(snapshot) {
						t.Fatal("mutated operator pairing")
					}
					lease := Lease{Request: Request{ExitStartLayer: layer}, Host: "10.77.0.1", Port: 26240, Username: "public-fixture-user", Password: "public-fixture-pass"}
					graph, e := Build(exit, netip.MustParseAddr("10.77.0.2"), lease)
					if e != nil {
						t.Fatal(e)
					}
					var decoded map[string]any
					json.Unmarshal(graph, &decoded)
					dns := decoded["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
					if dns["server"] != exit.DNS || dns["detour"] != "exit" || len(decoded["inbounds"].([]any)) != 1 {
						t.Fatal("DNS or listener ownership changed")
					}
					if len(decoded["outbounds"].([]any)) != map[bool]int{true: 1, false: 2}[awgpolicy.WireGuardFamily(mode)] {
						t.Fatal("wrong native manager count")
					}
				})
			}
		}
	}
}
func TestRequestedExitLayerCannotDowngradeRenewOrSelectAnotherPairing(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		paired := layerExit(t, "shadowsocks", layer)
		cfg := config()
		cfg.Exits = []Exit{paired}
		r := &runner{}
		m, e := New(cfg, req().EntryNodeID, r)
		if e != nil {
			t.Fatal(e)
		}
		peer := netip.MustParseAddr("10.77.0.2")
		q := req()
		if _, e = m.Create(context.Background(), peer, q); !errors.Is(e, ErrUnavailable) || r.starts != 0 {
			t.Fatal("raw request used a layered pairing")
		}
		q.ExitStartLayer = layer
		lease, e := m.Create(context.Background(), peer, q)
		if e != nil || lease.ExitStartLayer != layer {
			t.Fatal(e)
		}
		q.ExitStartLayer = ""
		if _, e = m.Create(context.Background(), peer, q); e == nil || r.starts != 1 {
			t.Fatal("lease renewal changed encryption")
		}
		caps, _ := json.Marshal(m.Available())
		if !strings.Contains(string(caps), `"exit_start_layer":"`+layer+`"`) {
			t.Fatal("capability omitted exact layer")
		}
		for _, secret := range []string{"transport", "password", "config_json", paired.StartLayer.Transport["password"].(string)} {
			if strings.Contains(string(caps), secret) {
				t.Fatal("capabilities exposed credentials")
			}
		}
		q.ExitStartLayer = layer
		if e = m.Delete(context.Background(), peer, q); e != nil {
			t.Fatal(e)
		}
		m.Close(context.Background())
		cfg = config()
		r = &runner{}
		m, e = New(cfg, req().EntryNodeID, r)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = m.Create(context.Background(), peer, q); !errors.Is(e, ErrUnavailable) || r.starts != 0 {
			t.Fatal("layered request downgraded to raw server exit")
		}
		m.Close(context.Background())
	}
	cfg := config()
	cfg.Exits = append(cfg.Exits, layerExit(t, "shadowsocks", "aes-256-gcm"))
	m, e := New(cfg, req().EntryNodeID, &runner{})
	if e != nil {
		t.Fatal("separate explicit raw/layered pairing rejected", e)
	}
	m.Close(context.Background())
	cfg.Exits = append(cfg.Exits, cfg.Exits[1])
	if _, e = New(cfg, req().EntryNodeID, &runner{}); e == nil {
		t.Fatal("duplicate exact layer accepted")
	}
}
func TestExitStartLayerRefusesForeignOrUnownedPolicy(t *testing.T) {
	changes := []func(*Exit){
		func(e *Exit) { e.StartLayer.Mode = "xor" }, func(e *Exit) { e.StartLayer.Mode = "" }, func(e *Exit) { e.StartLayer.API = "http://127.0.0.1:8787" }, func(e *Exit) { e.StartLayer.API = "http://8.8.8.8:8787" }, func(e *Exit) { e.StartLayer.API = "http://10.88.0.1:8787/path" }, func(e *Exit) { e.StartLayer.API = "http://user@10.88.0.1:8787" },
		func(e *Exit) { e.StartLayer.Transport["server"] = "192.0.2.99" }, func(e *Exit) { e.StartLayer.Transport["method"] = "none" }, func(e *Exit) { e.StartLayer.Transport["password"] = "do-not-echo" }, func(e *Exit) { e.StartLayer.Transport["detour"] = "foreign" }, func(e *Exit) { e.StartLayer.Transport["server_port"] = true }, func(e *Exit) { e.StartLayer.Transport["server_port"] = 1.5 }, func(e *Exit) { e.StartLayer.Transport["plugin"] = "unowned" }, func(e *Exit) { e.Transport["detour"] = "direct" },
	}
	for _, change := range changes {
		exit := layerExit(t, "shadowsocks", "aes-256-gcm")
		change(&exit)
		cfg := config()
		cfg.Exits = []Exit{exit}
		r := &runner{}
		_, e := New(cfg, req().EntryNodeID, r)
		if e == nil || r.starts != 0 || strings.Contains(e.Error(), "do-not-echo") {
			t.Fatal("invalid private pairing accepted or exposed")
		}
	}
	exit := layerExit(t, "wg", "aes-256-gcm")
	inner, _ := validateTransport(exit)
	inner["system"] = false
	inner["listen_port"] = 0
	next, _, e := WrapStartLayer(inner, exit.Mode, exit.StartLayer, ExitStartLayerTag, "entry-wg")
	if e != nil || next["system"] != false || next["listen_port"] != float64(0) {
		t.Fatal("mobile-owned packet defaults changed", e)
	}
	inner["system"] = true
	if _, _, e = WrapStartLayer(inner, exit.Mode, exit.StartLayer, ExitStartLayerTag, ""); e == nil {
		t.Fatal("second system interface accepted")
	}
}
