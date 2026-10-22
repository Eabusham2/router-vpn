package common

import (
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func TestExternalResponseProbeSharesNativeValidationAndNeverChangesLiteralRoute(t *testing.T) {
	for _, host := range []string{"203.0.113.20", "2001:db8::20"} {
		urlHost := host
		if strings.Contains(host, ":") {
			urlHost = "[" + host + "]"
		}
		for _, name := range []string{"", "node.example", "Node.example"} {
			probe := &ExternalResponseProbe{URL: "https://" + urlHost + ":8443/node-response", ServerName: name}
			if err := ValidateExternalResponseProbe(host, probe); err != nil {
				t.Fatal(err)
			}
			if err := (multihoprelay.ResponseProbe{URL: probe.URL, ServerName: probe.ServerName}).Validate(host); err != nil {
				t.Fatal("native contract diverged", err)
			}
		}
	}
	for _, value := range []struct{ host, url, name string }{
		{"203.0.113.20", "http://203.0.113.20/response", ""},
		{"203.0.113.20", "https://203.0.113.21/response", ""},
		{"203.0.113.20", "https://node.example/response", "node.example"},
		{"203.0.113.20", "https://203.0.113.20/response?key=private", ""},
		{"203.0.113.20", "https://203.0.113.20/response?", ""},
		{"203.0.113.20", "https://secret@203.0.113.20/response", ""},
		{"203.0.113.20", "https://203.0.113.20/response#fragment", ""},
		{"203.0.113.20", "https://203.0.113.20:0/response", ""},
		{"203.0.113.20", "https://203.0.113.20:65536/response", ""},
		{"203.0.113.20", "https://203.0.113.20:/response", ""},
		{"203.0.113.20", "https://203.0.113.20/%2fother", ""},
		{"203.0.113.20", "https://203.0.113.20/response", "localhost"},
		{"203.0.113.20", "https://203.0.113.20/response", "203.0.113.20"},
		{"203.0.113.20", "https://203.0.113.20/response", "node.example."},
		{"203.0.113.20", "https://203.0.113.20/response", "node.example\r\nsecret"},
		{"192.168.50.1", "https://192.168.50.1/response", "node.example"},
		{"100.64.0.1", "https://100.64.0.1/response", "node.example"},
		{"127.0.0.1", "https://127.0.0.1/response", "node.example"},
		{"::ffff:203.0.113.20", "https://[::ffff:203.0.113.20]/response", "node.example"},
	} {
		probe := &ExternalResponseProbe{URL: value.url, ServerName: value.name}
		if err := ValidateExternalResponseProbe(value.host, probe); err == nil {
			t.Fatal("unsafe endpoint accepted", value)
		}
		if err := (multihoprelay.ResponseProbe{URL: value.url, ServerName: value.name}).Validate(value.host); err == nil {
			t.Fatal("native validator accepted unsafe endpoint", value)
		}
	}
}

func TestExternalResponseProbeImportRoundTripAndCaptureAreIndependent(t *testing.T) {
	p := RouterProfile{ID: "external", NodeKind: "external", External: &ExternalNodeConfig{Protocol: "shadowsocks", ExpectedPublicIP: "203.0.113.88", Shadowsocks: &ExternalShadowsocksConfig{Server: "203.0.113.20", Port: 8388, Method: "aes-256-gcm", Password: "private-test-key"}, ResponseProbe: &ExternalResponseProbe{URL: "https://203.0.113.20/response", ServerName: "node.example"}}}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var loaded RouterProfile
	if err := json.Unmarshal(body, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.External.ResponseProbe == nil || *loaded.External.ResponseProbe != *p.External.ResponseProbe {
		t.Fatal("import lost response endpoint")
	}
	captured := copyProfileForJSON(p)
	p.External.ResponseProbe.URL = "https://203.0.113.20/replacement"
	if captured.External.ResponseProbe == p.External.ResponseProbe || captured.External.ResponseProbe.URL == p.External.ResponseProbe.URL {
		t.Fatal("captured endpoint aliases mutable selection")
	}
	p.External.Protocol = "socks5"
	p.External.Shadowsocks = nil
	p.External.SOCKS5 = &ExternalSOCKS5Config{Host: "203.0.113.20", Port: 1080}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("unsupported external graph silently retained comparison endpoint")
	}
}
