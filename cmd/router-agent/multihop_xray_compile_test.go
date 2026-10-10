package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func relayCompileFixture(t *testing.T) []byte {
	t.Helper()
	raw := map[string]any{"inbounds": []any{map[string]any{"protocol": "socks", "listen": "127.0.0.1", "port": 1090, "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "192.0.2.2", "port": 443, "users": []any{map[string]any{"id": "11111111-1111-4111-8111-111111111111", "encryption": "none", "flow": "xtls-rprx-vision"}}}}}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "paired.example.test", "fingerprint": "chrome", "password": "public-protocol-fixture", "shortId": "0123456789abcdef"}}}}}
	wrapper := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}}, "outbounds": []any{map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1090, "version": "5"}}, "route": map[string]any{"final": "proxy"}}
	a, e := json.Marshal(raw)
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(wrapper)
	if e != nil {
		t.Fatal(e)
	}
	output, e := json.Marshal(map[string]string{"xray.json": base64.StdEncoding.EncodeToString(a), "sing-box.json": base64.StdEncoding.EncodeToString(b)})
	if e != nil {
		t.Fatal(e)
	}
	return output
}

type failedRelayOutput struct{}

func (failedRelayOutput) Write([]byte) (int, error) { return 0, errors.New("fixture write failed") }
func TestNativeRelayCompilerUsesShippingPolicyAndBoundedStdIO(t *testing.T) {
	source := relayCompileFixture(t)
	var output bytes.Buffer
	if err := compileNativeRelayProfile(bytes.NewReader(source), &output, "reality-vision"); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if e := json.Unmarshal(output.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if len(result) != 4 || result["type"] != "routervpn-xray" || result["mode"] != "reality-vision" {
		t.Fatal("unexpected native transport")
	}
	var assets map[string]string
	json.Unmarshal(source, &assets)
	raw, _ := base64.StdEncoding.DecodeString(assets["xray.json"])
	if result["config_json"] != string(raw) {
		t.Fatal("pairing command changed original authentication")
	}
	for _, mode := range []string{"max", "split", "tor", ""} {
		var o bytes.Buffer
		if e := compileNativeRelayProfile(bytes.NewReader(source), &o, mode); e == nil || o.Len() != 0 {
			t.Fatal("unsupported mode wrote partial private output")
		}
	}
	for _, body := range [][]byte{nil, []byte(`{"secret":"must-not-leak"}`), bytes.Repeat([]byte{'x'}, (8<<20)+1)} {
		var o bytes.Buffer
		e := compileNativeRelayProfile(bytes.NewReader(body), &o, "reality-vision")
		if e == nil || o.Len() != 0 || strings.Contains(e.Error(), "must-not-leak") {
			t.Fatal("invalid input leaked private output")
		}
	}
	if e := compileNativeRelayProfile(bytes.NewReader(source), failedRelayOutput{}, "reality-vision"); e == nil {
		t.Fatal("write failure ignored")
	}
}

var _ io.Writer = failedRelayOutput{}
