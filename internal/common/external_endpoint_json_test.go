package common

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExternalNodeJSONNormalizesProtocolHostsBeforeSchemaAdoption(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		got  func(ExternalNodeConfig) string
	}{
		{"socks hostname", `{"protocol":"socks5","expected_public_ip":"8.8.8.8","socks5":{"host":"Proxy.Example.COM","port":1080}}`, func(e ExternalNodeConfig) string { return e.SOCKS5.Host }},
		{"http url", `{"protocol":"http-connect","expected_public_ip":"8.8.8.8","http_connect":{"host":"https://Proxy.Example.COM/supplied/path?ignored=1","port":8080}}`, func(e ExternalNodeConfig) string { return e.HTTPConnect.Host }},
		{"https hostname", `{"protocol":"https-connect","expected_public_ip":"8.8.8.8","https_connect":{"host":"Proxy.Example.COM","port":443,"tls_server_name":"proxy.example.com"}}`, func(e ExternalNodeConfig) string { return e.HTTPSConnect.Host }},
		{"shadowsocks hostname", `{"protocol":"shadowsocks","expected_public_ip":"8.8.8.8","shadowsocks":{"server":"Proxy.Example.COM","port":8388,"method":"aes-256-gcm","password":"secret"}}`, func(e ExternalNodeConfig) string { return e.Shadowsocks.Server }},
		{"hysteria hostname", `{"protocol":"hysteria2","expected_public_ip":"8.8.8.8","hysteria2":{"server":"Hy.Example.COM","port":8443,"password":"secret","tls_server_name":"hy.example.com"}}`, func(e ExternalNodeConfig) string { return e.Hysteria2.Server }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ext ExternalNodeConfig
			if err := json.Unmarshal([]byte(tc.raw), &ext); err != nil { t.Fatal(err) }
			want := "proxy.example.com"
			if strings.HasPrefix(tc.name, "hysteria") { want = "hy.example.com" }
			if got := tc.got(ext); got != want { t.Fatalf("normalized host=%q want=%q", got, want) }
		})
	}
}

func TestExternalNodeJSONNormalizesWireGuardEndpointForms(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`{"protocol":"wireguard","wireguard":{"endpoint":"Vpn.Example.COM","private_key":"x"}}`, "vpn.example.com"},
		{`{"protocol":"wireguard","wireguard":{"endpoint":"Vpn.Example.COM:51820","private_key":"x"}}`, "vpn.example.com:51820"},
		{`{"protocol":"wireguard","wireguard":{"endpoint":"[2001:4860:4860::8888]:51820","private_key":"x"}}`, "[2001:4860:4860::8888]:51820"},
		{`{"protocol":"wireguard","wireguard":{"endpoint":"2001:4860:4860::8888","private_key":"x"}}`, "2001:4860:4860::8888"},
	} {
		var ext ExternalNodeConfig
		if err := json.Unmarshal([]byte(tc.raw), &ext); err != nil { t.Fatalf("%s: %v", tc.raw, err) }
		if ext.WireGuard == nil || ext.WireGuard.Endpoint != tc.want { t.Fatalf("endpoint=%v want=%q", ext.WireGuard, tc.want) }
	}
}

func TestExternalNodeJSONRejectsMalformedHostsBeforeProfilePersistence(t *testing.T) {
	for _, host := range []string{"proxy.example.com/path", "proxy.example.com?x=1", "user@proxy.example.com", "proxy example.com", "proxy.example.com\nother.example.com", ".proxy.example.com", "proxy..example.com"} {
		raw, err := json.Marshal(map[string]any{
			"protocol": "socks5",
			"expected_public_ip": "8.8.8.8",
			"socks5": map[string]any{"host": host, "port": 1080},
		})
		if err != nil { t.Fatal(err) }
		var ext ExternalNodeConfig
		if err := json.Unmarshal(raw, &ext); err == nil { t.Fatalf("unsafe host %q decoded without rejection", host) }
	}
}

func TestRouterProfileJSONUsesExternalEndpointDecodeGuard(t *testing.T) {
	raw := `{"schema_version":4,"id":"raw-ext","name":"Raw","node_kind":"external","external":{"protocol":"socks5","expected_public_ip":"8.8.8.8","socks5":{"host":"bad host.example","port":1080}}}`
	var p RouterProfile
	if err := json.Unmarshal([]byte(raw), &p); err == nil || !strings.Contains(err.Error(), "external SOCKS5 host") {
		t.Fatalf("RouterProfile raw import bypassed external endpoint guard: %v", err)
	}
}
