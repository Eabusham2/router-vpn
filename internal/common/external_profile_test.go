package common

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyProfileDefaultsToRouterVPNKind(t *testing.T) {
	var p RouterProfile
	if err := json.Unmarshal([]byte(`{"schema_version":2,"id":"home","home_lan_access":false}`), &p); err != nil { t.Fatal(err) }
	if p.SchemaVersion != 3 { t.Fatalf("schema=%d", p.SchemaVersion) }
	if p.NodeKind != "router-vpn" { t.Fatalf("node_kind=%q", p.NodeKind) }
	if p.External != nil { t.Fatal("legacy Router VPN profile gained external config") }
}

func TestExternalWireGuardRoundTrip(t *testing.T) {
	p := RouterProfile{
		ID: "wg-exit", Name: "Office WireGuard", NodeKind: "external", HomeLANAccess: false,
		External: &ExternalNodeConfig{Protocol: " WireGuard ", WireGuard: &ExternalWireGuardConfig{
			PrivateKey: "private", Addresses: []string{"10.10.0.2/32"}, PeerPublicKey: "public",
			Endpoint: "vpn.example.com:51820", AllowedIPs: []string{"0.0.0.0/0", "::/0"}, DNS: []string{"1.1.1.1"}, MTU: 1380,
		}},
	}
	b, err := json.Marshal(p); if err != nil { t.Fatal(err) }
	if strings.Contains(string(b), `"node_kind":"router-vpn"`) { t.Fatalf("wrong kind: %s", b) }
	var out RouterProfile
	if err := json.Unmarshal(b, &out); err != nil { t.Fatal(err) }
	if out.NodeKind != "external" || out.External == nil || out.External.Protocol != "wireguard" { t.Fatalf("bad roundtrip: %+v", out) }
	if out.External.WireGuard == nil || out.External.WireGuard.MTU != 1380 { t.Fatalf("wireguard data lost: %+v", out.External) }
}

func TestExternalOpenVPNProfileAcceptedAsDataOnly(t *testing.T) {
	p := RouterProfile{ID: "ovpn", NodeKind: "external", External: &ExternalNodeConfig{
		Protocol: "openvpn", OpenVPN: &ExternalOpenVPNConfig{Config: "client\nremote vpn.example.com 1194 udp\n<ca>\nTEST\n</ca>"},
	}}
	if err := NormalizeRouterProfile(&p); err != nil { t.Fatal(err) }
	if p.External.Protocol != "openvpn" { t.Fatalf("protocol=%q", p.External.Protocol) }
}

func TestExternalProtocolsRequireExactlyMatchingBlock(t *testing.T) {
	bad := []RouterProfile{
		{ID:"none", NodeKind:"external", External:&ExternalNodeConfig{Protocol:"wireguard"}},
		{ID:"two", NodeKind:"external", External:&ExternalNodeConfig{Protocol:"socks5", SOCKS5:&ExternalSOCKS5Config{Host:"127.0.0.1",Port:1080}, Shadowsocks:&ExternalShadowsocksConfig{Server:"x",Port:8388,Method:"2022-blake3-aes-128-gcm",Password:"secret"}}},
		{ID:"wrong", NodeKind:"external", External:&ExternalNodeConfig{Protocol:"wireguard", SOCKS5:&ExternalSOCKS5Config{Host:"127.0.0.1",Port:1080}}},
		{ID:"unknown", NodeKind:"external", External:&ExternalNodeConfig{Protocol:"pptp", SOCKS5:&ExternalSOCKS5Config{Host:"127.0.0.1",Port:1080}}},
	}
	for _, p := range bad { if err := NormalizeRouterProfile(&p); err == nil { t.Fatalf("expected rejection: %+v", p) } }
}

func TestExternalNodeRejectsRouterVPNAdminSecrets(t *testing.T) {
	for _, mutate := range []func(*RouterProfile){
		func(p *RouterProfile){ p.APIToken="secret" },
		func(p *RouterProfile){ p.RouterAPI="http://10.77.0.1:8787" },
		func(p *RouterProfile){ p.NodeProofID=strings.Repeat("a",64) },
	} {
		p := RouterProfile{ID:"ext", NodeKind:"external", External:&ExternalNodeConfig{Protocol:"socks5", SOCKS5:&ExternalSOCKS5Config{Host:"10.0.0.1",Port:1080}}}
		mutate(&p)
		if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "proof/admin") { t.Fatalf("expected admin-secret rejection, got %v", err) }
	}
}

func TestExternalCredentialPairsFailClosed(t *testing.T) {
	p := RouterProfile{ID:"socks", NodeKind:"external", External:&ExternalNodeConfig{Protocol:"socks5", SOCKS5:&ExternalSOCKS5Config{Host:"10.0.0.1",Port:1080,Username:"u"}}}
	if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "username/password") { t.Fatalf("expected incomplete auth rejection, got %v", err) }
	p = RouterProfile{ID:"ovpn", NodeKind:"external", External:&ExternalNodeConfig{Protocol:"openvpn", OpenVPN:&ExternalOpenVPNConfig{Config:"client\nremote x 1194",Password:"p"}}}
	if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "username/password") { t.Fatalf("expected incomplete auth rejection, got %v", err) }
}

func TestProfileStoreRejectsDuplicateAndMissingSelection(t *testing.T) {
	store := RouterProfileStore{SelectedID:"missing",Profiles:[]RouterProfile{{ID:"one"}}}
	if err := NormalizeRouterProfileStore(&store); err == nil || !strings.Contains(err.Error(), "not present") { t.Fatalf("expected missing selection rejection, got %v", err) }
	store = RouterProfileStore{Profiles:[]RouterProfile{{ID:"dup"},{ID:"dup"}}}
	if err := NormalizeRouterProfileStore(&store); err == nil || !strings.Contains(err.Error(), "duplicate") { t.Fatalf("expected duplicate rejection, got %v", err) }
}
