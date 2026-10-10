package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

func selectedLayerFixture(t *testing.T, mode string) []byte {
	t.Helper()
	transport := map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.2", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))}
	graph := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}}, "outbounds": []any{transport}, "route": map[string]any{"final": "proxy"}}
	b, e := json.Marshal(graph)
	if e != nil {
		t.Fatal(e)
	}
	b, e = json.Marshal(map[string]any{"mode": mode, "profile": map[string]string{"sing-box.json": base64.StdEncoding.EncodeToString(b)}})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestCompileSelectedRelayStartLayerMatchesRuntimeAndPrivateLease(t *testing.T) {
	for _, mode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		source := selectedLayerFixture(t, mode)
		before := append([]byte(nil), source...)
		var output bytes.Buffer
		if e := compileRelayStartLayer(bytes.NewReader(source), &output, "192.0.2.2", "http://10.88.0.1:8787"); e != nil {
			t.Fatal(e)
		}
		var layer multihoprelay.StartLayer
		if e := json.Unmarshal(output.Bytes(), &layer); e != nil {
			t.Fatal(e)
		}
		if layer.Mode != mode || layer.API != "http://10.88.0.1:8787" || !bytes.Equal(source, before) {
			t.Fatal("selected source changed")
		}
		exit := multihoprelay.Exit{ID: "exit", Mode: "shadowsocks", NodeID: strings.Repeat("b", 64), DNS: "10.88.0.1", Transport: layer.Transport, StartLayer: &layer}
		lease := relayValidationLease(exit, "10.77.0.1", 26240)
		if lease.ExitMode != exit.Mode || lease.ExitID != exit.ID || lease.ExitStartLayer != mode {
			t.Fatal("offline check omitted exact layer identity")
		}
		actual, e := multihoprelay.Build(exit, netip.MustParseAddr("10.77.0.2"), lease)
		if e != nil {
			t.Fatal(e)
		}
		var graph map[string]any
		json.Unmarshal(actual, &graph)
		outs := graph["outbounds"].([]any)
		if len(outs) != 2 || outs[0].(map[string]any)["detour"] != multihoprelay.ExitStartLayerTag || outs[1].(map[string]any)["password"] != layer.Transport["password"] {
			t.Fatal("saved source did not build into the owned relay")
		}
		lease.ExitStartLayer = ""
		if _, e = multihoprelay.Build(exit, netip.MustParseAddr("10.77.0.2"), lease); e == nil {
			t.Fatal("bare validation lease accepted")
		}
	}
}
func TestCompileSelectedRelayLayerRejectsForeignOrAmbiguousInputs(t *testing.T) {
	valid := selectedLayerFixture(t, "aes-256-gcm")
	for _, pair := range [][2]string{{"192.0.2.99", "http://10.88.0.1:8787"}, {"name.invalid", "http://10.88.0.1:8787"}, {"192.0.2.2", "http://127.0.0.1:8787"}, {"192.0.2.2", "http://8.8.8.8:8787"}, {"192.0.2.2", "http://user@10.88.0.1:8787"}} {
		var out bytes.Buffer
		if e := compileRelayStartLayer(bytes.NewReader(valid), &out, pair[0], pair[1]); e == nil || out.Len() != 0 {
			t.Fatal("invalid node published a layer")
		}
	}
	for _, body := range [][]byte{nil, []byte(`{"mode":"aes","mode":"aes","profile":{}}`), []byte(`{"mode":true,"profile":{}}`), []byte(`{"mode":"aes","profile":{},"extra":0}`), bytes.Repeat([]byte{'x'}, 16385), selectedLayerFixture(t, "off"), selectedLayerFixture(t, "xor")} {
		var out bytes.Buffer
		e := compileRelayStartLayer(bytes.NewReader(body), &out, "192.0.2.2", "http://10.88.0.1:8787")
		if e == nil || out.Len() != 0 {
			t.Fatal("invalid payload published private output")
		}
	}
	for _, bad := range []string{"key", "route", "extra", "method"} {
		var source map[string]any
		json.Unmarshal(valid, &source)
		profile := source["profile"].(map[string]any)
		raw, _ := base64.StdEncoding.DecodeString(profile["sing-box.json"].(string))
		var graph map[string]any
		json.Unmarshal(raw, &graph)
		out := graph["outbounds"].([]any)[0].(map[string]any)
		switch bad {
		case "key":
			out["password"] = "must-never-echo"
		case "method":
			out["method"] = "none"
		case "route":
			graph["route"].(map[string]any)["rules"] = []any{map[string]any{"outbound": "direct"}}
		case "extra":
			profile["another-file"] = "e30="
		}
		raw, _ = json.Marshal(graph)
		profile["sing-box.json"] = base64.StdEncoding.EncodeToString(raw)
		body, _ := json.Marshal(source)
		var result bytes.Buffer
		e := compileRelayStartLayer(bytes.NewReader(body), &result, "192.0.2.2", "http://10.88.0.1:8787")
		if e == nil || result.Len() != 0 || strings.Contains(e.Error(), "must-never-echo") {
			t.Fatal("invalid selected source or diagnostic", bad)
		}
	}
}
