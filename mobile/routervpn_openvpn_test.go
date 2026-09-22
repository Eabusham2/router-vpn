package libbox

import (
	"encoding/json"
	"strings"
	"testing"
)

// Deliberately synthetic PEM: these tests verify configuration semantics, not a
// TLS handshake. The pinned native-core tests perform certificate parsing.
const fixture = "client\ndev tun\nproto udp\nremote 192.0.2.25 1194\nauth-user-pass\nremote-cert-tls server\n<ca>\n-----BEGIN CERTIFICATE-----\nfixture-only\n-----END CERTIFICATE-----\n</ca>\n"

func compiled(t *testing.T, text string) map[string]any {
	t.Helper()
	raw, err := RouterOpenVPNEndpoint(text, "user", " secret ", "custom-exit", "")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func TestNativeOpenVPNBasic(t *testing.T) {
	for _, text := range []string{fixture, strings.ReplaceAll(fixture, "\n", "\r\n"), "\ufeff" + fixture, strings.ReplaceAll(fixture, "\n", "\r")} {
		p := compiled(t, text)
		if p["type"] != "openvpn-client" || p["system"] != false || p["server"] != "192.0.2.25" || p["password"] != " secret " || p["server_port"] != float64(1194) {
			t.Fatalf("wrong native endpoint: keys=%d", len(p))
		}
		tls := p["tls"].(map[string]any)
		if tls["remote_certificate_tls"] != "server" || tls["version_min"] != "1.2" {
			t.Fatal("server verification lost")
		}
		if p["detour"] != nil {
			t.Fatal("direct endpoint unexpectedly detoured")
		}
	}
}
func TestNativeOpenVPNDetourAndCredentials(t *testing.T) {
	raw, err := RouterOpenVPNEndpoint(fixture, "user", "password", "custom-exit", "entry-wg")
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(raw), &p)
	if p["detour"] != "entry-wg" {
		t.Fatal("entry ownership missing")
	}
	for _, pair := range [][2]string{{"", "p"}, {"u", ""}, {"u\nx", "p"}, {"u", "p\r"}, {"\x00", "p"}, {strings.Repeat("x", 4097), "p"}} {
		if _, e := RouterOpenVPNEndpoint(fixture, pair[0], pair[1], "exit", ""); e == nil {
			t.Fatal("unsafe credential accepted")
		}
	}
	if _, e := RouterOpenVPNEndpoint(fixture, "", "", "exit", ""); e == nil {
		t.Fatal("missing required credentials accepted")
	}
	for _, tags := range [][2]string{{"", ""}, {"exit", "exit"}, {"exit", "../foo"}, {"bad tag", "entry"}} {
		if _, e := RouterOpenVPNEndpoint(fixture, "u", "p", tags[0], tags[1]); e == nil {
			t.Fatal("bad graph tag accepted")
		}
	}
}
func TestNativeOpenVPNRemoteList(t *testing.T) {
	text := strings.Replace(fixture, "remote 192.0.2.25 1194", "remote 192.0.2.25\nremote 2001:db8::25 443 tcp6-client\nrport 1443\nremote-random", 1)
	p := compiled(t, text)
	r := p["servers"].([]any)
	if len(r) != 2 || p["server_port"] != float64(1443) || p["remote_random"] != true || r[1].(map[string]any)["network"] != "tcp6" {
		t.Fatal("remote ordering/options not preserved")
	}
	for _, n := range []string{"tcp-client", "tcp4-client", "udp4", "udp"} {
		p := compiled(t, strings.Replace(fixture, "proto udp", "proto "+n, 1))
		if strings.Contains(p["network"].(string), "client") {
			t.Fatal("protocol alias not normalized")
		}
	}
}
func TestNativeOpenVPNTLSAndControlWrap(t *testing.T) {
	p := compiled(t, fixture+"verify-x509-name 'VPN Server' name\ntls-version-max 1.3\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\nauth SHA256\n")
	tls := p["tls"].(map[string]any)
	if tls["server_name"] != "VPN Server" || tls["server_name_type"] != "name" || len(p["data_ciphers"].([]any)) != 2 {
		t.Fatal("TLS/cipher policy not preserved")
	}
	for _, kind := range []string{"tls-auth", "tls-crypt", "tls-crypt-v2"} {
		suffix := "<" + kind + ">\nprivate control key\n</" + kind + ">\n"
		if kind == "tls-auth" {
			suffix += "key-direction 1\n"
		}
		p := compiled(t, fixture+suffix)
		wrap := p["tls"].(map[string]any)["control_wrap"].(map[string]any)
		if wrap["type"] != strings.ReplaceAll(kind, "-", "_") {
			t.Fatal("control wrapping lost")
		}
		if kind == "tls-auth" && wrap["direction"] != "client" {
			t.Fatal("client direction lost")
		}
	}
	cert := strings.Replace(fixture, "auth-user-pass\n", "", 1) + "<cert>\nclient cert\n</cert>\n<key>\nprivate key\n</key>\n"
	if _, err := RouterOpenVPNEndpoint(cert, "", "", "exit", ""); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Replace(fixture, "<ca>\n-----BEGIN CERTIFICATE-----\nfixture-only\n-----END CERTIFICATE-----\n</ca>", "peer-fingerprint "+strings.Repeat("ab", 32), 1)
	p = compiled(t, fingerprint)
	if p["tls"].(map[string]any)["peer_fingerprint"] == nil {
		t.Fatal("fingerprint missing")
	}
}
func TestNativeOpenVPNOptions(t *testing.T) {
	cases := map[string]string{
		"tun-mtu 1400": "mtu", "mssfix 1380 mtu": "mss_fix", "mssfix 0": "mss_fix_disabled",
		"ping 10": "ping_interval", "ping-restart 60": "ping_restart", "reneg-sec 0": "renegotiate_disabled",
		"reneg-sec 3600": "renegotiate_interval", "keepalive 10 60": "ping_interval", "explicit-exit-notify": "explicit_exit_notify",
		"data-ciphers-fallback AES-256-CBC": "data_ciphers_fallback", "cipher AES-128-GCM": "cipher",
		"comp-lzo no": "compression_lzo", "compress stub-v2": "compression", "allow-compression no": "allow_compression",
		"route-nopull": "route_no_pull", "redirect-gateway def1": "redirect_gateway", "pull-filter ignore 'dhcp-option DNS'": "pull_filters",
	}
	for text, key := range cases {
		t.Run(text, func(t *testing.T) {
			p := compiled(t, fixture+text+"\n")
			if p[key] == nil {
				t.Fatal("option disappeared")
			}
		})
	}
	for _, opt := range []string{"nobind", "persist-key", "persist-tun", "auth-nocache", "verb 3", "mute 20", "tls-client", "pull", "dev-type tun"} {
		_ = compiled(t, fixture+opt+"\n")
	}
}
func TestNativeOpenVPNRejectsUnsafeProfiles(t *testing.T) {
	unsafe := []string{
		"up /tmp/SECRET_VALUE", "down /tmp/SECRET_VALUE", "plugin SECRET_VALUE", "script-security 2", "config SECRET_VALUE", "management 127.0.0.1 1234",
		"ca SECRET_VALUE", "cert SECRET_VALUE", "key SECRET_VALUE", "auth-user-pass SECRET_VALUE", "http-proxy SECRET_VALUE 80", "socks-proxy SECRET_VALUE 1080",
		"remote-cert-tls none", "tls-version-min 1.0", "cipher none", "cipher BF-CBC", "data-ciphers AES-256-GCM:none", "auth none", "allow-compression yes", "comp-lzo yes", "compress lz4",
		"route 10.0.0.0 255.0.0.0 net_gateway", "dhcp-option DNS 8.8.8.8", "route-up SECRET_VALUE", "ignore-unknown-option up", "setenv opt up SECRET_VALUE",
		"tls-verify SECRET_VALUE", "crl-verify SECRET_VALUE", "pkcs12 SECRET_VALUE", "secret SECRET_VALUE", "dev tap", "dev tun0", "client extra", "unknownoption SECRET_VALUE",
		"tun-mtu 1279", "tun-mtu 9001", "tun-mtu true", "tun-mtu -1", "tun-mtu 1.4", "mssfix 1300 bogus", "fragment 99999", "ping 99999999999", "key-direction 2", "key-direction 1",
		"remote hostname.example 1194", "remote 127.0.0.1 1194", "remote 0.0.0.0 1194", "remote 224.0.0.1 1194", "remote :: 1194", "remote fe80::1%en0 1194", "remote ::ffff:192.0.2.1 1194",
		"remote 192.0.2.1 0", "remote 192.0.2.1 65536", "remote 192.0.2.1 1194 tcp-server", "remote 192.0.2.1 1194 udp6",
		"verify-x509-name 'unterminated", "verify-x509-name a\x01b", "<ca>\nsecond-ca\n</ca>", "<up>\nSECRET_VALUE\n</up>", "<key>\nSECRET_VALUE\n",
		"<cert>\ncert\n<key>\nSECRET_VALUE\n</key>\n</cert>", "<tls-auth>\nkey\n</tls-auth>\n<tls-crypt>\nkey\n</tls-crypt>",
		"tls-version-min 1.3\ntls-version-max 1.2", "auth-retry interact", "static-challenge 'OTP' 0",
	}
	for i, option := range unsafe {
		t.Run(strconvTest(i), func(t *testing.T) {
			_, err := RouterOpenVPNEndpoint(fixture+option+"\n", "u", "p", "exit", "")
			if err == nil {
				t.Fatalf("accepted unsafe case %d", i)
			}
			if strings.Contains(err.Error(), "SECRET_VALUE") {
				t.Fatal("secret leaked in error")
			}
		})
	}
	for _, text := range []string{"", strings.Repeat("x", routerOpenVPNMaxBytes+1), fixture + "\x00", fixture + string([]byte{0xff}), strings.Replace(fixture, "remote 192.0.2.25 1194\n", "", 1), fixture + strings.Repeat("remote 192.0.2.26 1194\n", 17)} {
		if _, e := RouterOpenVPNEndpoint(text, "u", "p", "exit", ""); e == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
}
func strconvTest(n int) string {
	const digits = "0123456789"
	if n < 10 {
		return string(digits[n])
	}
	return strconvTest(n/10) + string(digits[n%10])
}
func FuzzNativeOpenVPN(f *testing.F) {
	for _, s := range []string{fixture, "<ca>\n", `remote "`, fixture + "remote 2001:db8::1 443 tcp6"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		raw, e := RouterOpenVPNEndpoint(s, "u", "p", "exit", "")
		if e == nil {
			var v map[string]any
			if json.Unmarshal([]byte(raw), &v) != nil || v["type"] != "openvpn-client" || v["system"] != false {
				t.Fatal("invalid native endpoint emitted")
			}
		}
	})
}
