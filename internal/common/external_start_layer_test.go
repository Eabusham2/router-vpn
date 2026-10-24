package common

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func externalLayerTestProfile(protocol, mode string) RouterProfile {
	ext := &ExternalNodeConfig{Protocol: protocol, ExpectedPublicIP: "203.0.113.88", ResponseProbe: &ExternalResponseProbe{URL: "https://203.0.113.20/response", ServerName: "node.example"}}
	switch protocol {
	case "shadowsocks":
		ext.Shadowsocks = &ExternalShadowsocksConfig{Server: "203.0.113.20", Port: 8388, Method: "aes-256-gcm", Password: " private proxy key "}
	case "hysteria2":
		ext.Hysteria2 = &ExternalHysteria2Config{Server: "203.0.113.20", Port: 443, TLSServerName: "node.example", Password: " private proxy key "}
	case "socks5":
		ext.SOCKS5 = &ExternalSOCKS5Config{Host: "203.0.113.20", Port: 1080, Username: " exact user ", Password: " exact password "}
	case "http-connect":
		ext.HTTPConnect = &ExternalHTTPConnectConfig{Host: "203.0.113.20", Port: 8080, Username: " exact user ", Password: " exact password "}
	case "https-connect":
		ext.HTTPSConnect = &ExternalHTTPConnectConfig{Host: "203.0.113.20", Port: 443, TLSServerName: "node.example", Username: " exact user ", Password: " exact password "}
	}
	if mode != StartLayerOff {
		ext.StartLayer = &ExternalStartLayer{Mode: mode, API: "http://10.77.0.1:8787", Transport: map[string]any{"type": "shadowsocks", "tag": "imported-layer", "server": "203.0.113.20", "server_port": float64(8389), "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}}
	}
	return RouterProfile{ID: "external", NodeKind: "external", External: ext, StartLayer: mode, DNSMode: "custom", DNSProtocol: "tls", DNSHost: "203.0.113.30", DNSPort: 853, DNSServerName: "dns.example", IPv6Mode: "on"}
}

func TestExternalStartLayerImportRoundTripRetainsExactCredentialsAndSelectedDNS(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"} {
		for _, mode := range []string{StartLayerOff, StartLayerAES256GCM, StartLayerAES256GCMXOR} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				p := externalLayerTestProfile(protocol, mode)
				before := unnormalizedProfileJSON(t, p)
				raw, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				var loaded RouterProfile
				if err := json.Unmarshal(raw, &loaded); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(p.External, loaded.External) || loaded.StartLayer != mode || loaded.DNSHost != p.DNSHost || loaded.DNSProtocol != "tls" || loaded.DNSPort != 853 || loaded.DNSServerName != p.DNSServerName || loaded.IPv6Mode != "on" {
					t.Fatal("import changed the captured private node, layer or resolver")
				}
				if !bytes.Equal(before, unnormalizedProfileJSON(t, p)) {
					t.Fatal("serialization mutated the live node")
				}
				if mode != StartLayerOff {
					captured := copyProfileForJSON(p)
					p.External.StartLayer.Transport["server"] = "203.0.113.21"
					if captured.External.StartLayer.Transport["server"] != "203.0.113.20" {
						t.Fatal("captured layer aliases mutable private transport")
					}
				}
			})
		}
	}
}

func TestExternalStartLayerLocalDoesNotRequireCompareEndpointOrProxyAuthentication(t *testing.T) {
	for _, protocol := range []string{"socks5", "http-connect", "https-connect"} {
		p := externalLayerTestProfile(protocol, StartLayerAES256GCM)
		p.External.ResponseProbe = nil
		switch protocol {
		case "socks5":
			p.External.SOCKS5.Username, p.External.SOCKS5.Password = "", ""
		case "http-connect":
			p.External.HTTPConnect.Username, p.External.HTTPConnect.Password = "", ""
		case "https-connect":
			p.External.HTTPSConnect.Username, p.External.HTTPSConnect.Password = "", ""
		}
		if _, err := json.Marshal(p); err != nil {
			t.Fatal(protocol, err)
		}
	}
}

func TestExternalStartLayerRejectsMismatchedOrInjectedPrivateOwnership(t *testing.T) {
	for name, mutate := range map[string]func(*RouterProfile){
		"missing provision":        func(p *RouterProfile) { p.External.StartLayer = nil },
		"off with provision":       func(p *RouterProfile) { p.StartLayer = StartLayerOff },
		"different mode":           func(p *RouterProfile) { p.External.StartLayer.Mode = StartLayerAES256GCMXOR },
		"different public server":  func(p *RouterProfile) { p.External.StartLayer.Transport["server"] = "203.0.113.21" },
		"public inner target":      func(p *RouterProfile) { p.External.StartLayer.API = "http://203.0.113.20:8787" },
		"inner credential URL":     func(p *RouterProfile) { p.External.StartLayer.API = "http://secret@10.77.0.1:8787" },
		"unselected router proof":  func(p *RouterProfile) { p.APIToken = "unrelated-admin-token" },
		"outer detour":             func(p *RouterProfile) { p.External.StartLayer.Transport["detour"] = "unowned" },
		"different cipher":         func(p *RouterProfile) { p.External.StartLayer.Transport["method"] = "aes-256-gcm" },
		"invalid outer key":        func(p *RouterProfile) { p.External.StartLayer.Transport["password"] = "invalid-secret" },
		"response from other node": func(p *RouterProfile) { p.External.ResponseProbe.URL = "https://203.0.113.21/response" },
	} {
		t.Run(name, func(t *testing.T) {
			p := externalLayerTestProfile("shadowsocks", StartLayerAES256GCM)
			mutate(&p)
			before := unnormalizedProfileJSON(t, p)
			if _, err := json.Marshal(p); err == nil {
				t.Fatal("invalid private layer accepted")
			}
			if !bytes.Equal(before, unnormalizedProfileJSON(t, p)) {
				t.Fatal("rejected serialization changed the live profile")
			}
		})
	}
	for _, addition := range []string{`,"unowned":"value"`, `,"detour":"other"`} {
		p := externalLayerTestProfile("shadowsocks", StartLayerAES256GCM)
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]json.RawMessage
		_ = json.Unmarshal(raw, &decoded)
		var external map[string]json.RawMessage
		_ = json.Unmarshal(decoded["external"], &external)
		layer := strings.TrimSuffix(string(external["start_layer"]), "}") + addition + "}"
		external["start_layer"] = json.RawMessage(layer)
		decoded["external"], _ = json.Marshal(external)
		raw, _ = json.Marshal(decoded)
		var imported RouterProfile
		if json.Unmarshal(raw, &imported) == nil {
			t.Fatal("unknown private Start Layer fields silently discarded")
		}
	}
}
