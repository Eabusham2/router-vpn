package mobilemultihop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func wireGuardFixture() (string, string) {
	private := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	public := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	psk := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	proof := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + public))
	text := "[Interface]\nAddress = 10.77.0.2/24, fd77:77::2/64\nPrivateKey = " + private + "\nDNS = 192.168.50.133\nMTU = 1420\n[Peer]\nPublicKey = " + public + "\nPresharedKey = " + psk + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
	return text, hex.EncodeToString(proof[:])
}
func TestWireGuardProfilePreservesKeysRoutesMTUAndKeepalive(t *testing.T) {
	text, id := wireGuardFixture()
	encoded, err := CompileWireGuardProfile(text, id)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal([]byte(encoded), &root); err != nil {
		t.Fatal(err)
	}
	endpoint := root["endpoint"].(map[string]any)
	peer := endpoint["peers"].([]any)[0].(map[string]any)
	if endpoint["system"] != false || endpoint["mtu"] != float64(1420) || endpoint["tag"] != nil || endpoint["detour"] != nil {
		t.Fatal("unowned endpoint options")
	}
	if peer["persistent_keepalive_interval"] != float64(25) || peer["pre_shared_key"] == nil {
		t.Fatal("peer policy was dropped")
	}
	if len(endpoint["address"].([]any)) != 2 || len(peer["allowed_ips"].([]any)) != 2 {
		t.Fatal("dual-stack routes were dropped")
	}
	if root["dns"].([]any)[0] != "192.168.50.133" {
		t.Fatal("DNS was replaced")
	}
	ipv6 := strings.Replace(text, "192.0.2.1:51820", "[2001:db8::1]:51820", 1)
	if _, err = CompileWireGuardProfile(ipv6, id); err != nil {
		t.Fatal(err)
	}
	crlf := strings.ReplaceAll(text, "\n", "\r\n")
	if _, err = CompileWireGuardProfile(crlf, id); err != nil {
		t.Fatal(err)
	}
}
func TestWireGuardProfileRejectsAmbiguityAndUnsafeInput(t *testing.T) {
	text, id := wireGuardFixture()
	tests := map[string]string{
		"missing-interface":   strings.Replace(text, "[Interface]", "", 1),
		"extra-interface":     text + "[Interface]\n",
		"extra-peer":          text + "[Peer]\n",
		"unknown-section":     strings.Replace(text, "[Peer]", "[Other]", 1),
		"duplicate-private":   strings.Replace(text, "[Peer]", "PrivateKey = "+base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))+"\n[Peer]", 1),
		"duplicate-endpoint":  text + "Endpoint = 192.0.2.2:51820\n",
		"hook":                strings.Replace(text, "[Peer]", "PostUp = execute-me\n[Peer]", 1),
		"routing-table":       strings.Replace(text, "[Peer]", "Table = 52\n[Peer]", 1),
		"amnezia-field":       strings.Replace(text, "[Peer]", "Jc = 5\n[Peer]", 1),
		"unscoped":            "PrivateKey = secret\n" + text,
		"nul":                 text + "\x00",
		"invalid-utf8":        text + string([]byte{255}),
		"large":               strings.Repeat("#", 1024*1024+1),
		"long-line":           text + "#" + strings.Repeat("x", 16384),
		"dns-hostname":        strings.Replace(text, "192.168.50.133", "dns.example.test", 1),
		"duplicate-address":   strings.Replace(text, "10.77.0.2/24, fd77:77::2/64", "10.77.0.2/24, 10.77.0.2/24", 1),
		"ipv4-only":           strings.Replace(text, ", ::/0", "", 1),
		"split-routes":        strings.Replace(text, "0.0.0.0/0, ::/0", "10.77.0.0/24, fd77:77::/64", 1),
		"bad-mtu":             strings.Replace(text, "MTU = 1420", "MTU = 9001", 1),
		"signed-mtu":          strings.Replace(text, "MTU = 1420", "MTU = +1420", 1),
		"bad-keepalive":       strings.Replace(text, "PersistentKeepalive = 25", "PersistentKeepalive = 65536", 1),
		"unknown-peer-option": text + "Injected = ignored\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileWireGuardProfile(input, id); err == nil {
				t.Fatal("accepted unsafe input")
			}
		})
	}
	for _, host := range []string{"example.test:51820", "0.1.2.3:51820", "240.0.0.1:51820", "127.0.0.1:51820", "0.0.0.0:51820", "255.255.255.255:51820", "224.0.0.1:51820", "169.254.1.1:51820", "[::1]:51820", "[::]:51820", "[fe80::1%en0]:51820", "[::ffff:192.0.2.1]:51820", "192.0.2.1:0", "192.0.2.1:65536", "192.0.2.1:+51820"} {
		t.Run(host, func(t *testing.T) {
			if _, err := CompileWireGuardProfile(strings.Replace(text, "192.0.2.1:51820", host, 1), id); err == nil {
				t.Fatal("accepted unowned endpoint")
			}
		})
	}
	for _, key := range []string{"", base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(make([]byte, 31)), strings.Repeat("b", 43) + "!"} {
		invalid := strings.Replace(text, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), key, 1)
		if _, err := CompileWireGuardProfile(invalid, id); err == nil {
			t.Fatal("invalid private key accepted")
		}
	}
	if _, err := CompileWireGuardProfile(text, strings.Repeat("f", 64)); err == nil {
		t.Fatal("wrong paired node accepted")
	}
	if _, err := CompileWireGuardProfile(text, ""); err == nil {
		t.Fatal("missing node proof accepted")
	}
}
func TestWireGuardExitHasOneNativeEndpointAndNoBypass(t *testing.T) {
	text, id := wireGuardFixture()
	encoded, err := WireGuardExitConfig(text, id)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	_ = json.Unmarshal([]byte(encoded), &root)
	if len(root["outbounds"].([]any)) != 0 || len(root["endpoints"].([]any)) != 1 {
		t.Fatal("unowned exit path")
	}
	if root["endpoints"].([]any)[0].(map[string]any)["tag"] != "proxy" {
		t.Fatal("lost owned exit tag")
	}
	tun := root["inbounds"].([]any)[0].(map[string]any)
	if tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true || len(tun["address"].([]any)) != 2 {
		t.Fatal("lost full-device TUN")
	}
	dns := root["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if dns["detour"] != "proxy" || dns["server"] != "192.168.50.133" {
		t.Fatal("DNS bypasses encrypted exit")
	}
	for _, input := range []string{strings.Replace(text, "DNS = 192.168.50.133\n", "", 1), strings.Replace(text, "DNS = 192.168.50.133", "DNS = 192.168.50.133, 1.1.1.1", 1)} {
		if _, err = WireGuardExitConfig(input, id); err == nil {
			t.Fatal("ambiguous exit DNS accepted")
		}
	}
}
