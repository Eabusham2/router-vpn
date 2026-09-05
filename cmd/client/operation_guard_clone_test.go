package main

import (
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

func TestCloneRouterProfileStoreDeeplyIsolatesMutableProfileState(t *testing.T) {
	store := common.RouterProfileStore{
		SchemaVersion: 4,
		SelectedID:    "external",
		Profiles: []common.RouterProfile{{
			SchemaVersion: 4,
			ID:            "external",
			Name:          "External",
			NodeKind:      "external",
			CustomLayers:  []string{"wg", "padding"},
			HomeLANCIDRs:  []string{"192.168.50.0/24"},
			DNSResults: []common.DNSBenchmarkResult{{
				Name: "resolver", Address: "1.1.1.1", Working: true, LatencyMs: 8.5,
			}},
			External: &common.ExternalNodeConfig{
				Protocol:         "wireguard",
				ExpectedPublicIP: "203.0.113.10",
				WireGuard: &common.ExternalWireGuardConfig{
					PrivateKey: "private",
					Addresses:  []string{"10.0.0.2/32"},
					PeerPublicKey: "peer",
					Endpoint:      "198.51.100.1:51820",
					AllowedIPs:    []string{"0.0.0.0/0", "::/0"},
					DNS:           []string{"9.9.9.9"},
				},
				OpenVPN:     &common.ExternalOpenVPNConfig{Config: "client", Username: "ovpn-user", Password: "ovpn-pass"},
				Shadowsocks: &common.ExternalShadowsocksConfig{Server: "198.51.100.2", Port: 443, Method: "2022-blake3-aes-128-gcm", Password: "ss-pass"},
				SOCKS5:      &common.ExternalSOCKS5Config{Host: "198.51.100.3", Port: 1080, Username: "socks-user", Password: "socks-pass"},
				HTTPConnect:  &common.ExternalHTTPConnectConfig{Host: "198.51.100.4", Port: 8080, Username: "http-user", Password: "http-pass"},
				HTTPSConnect: &common.ExternalHTTPConnectConfig{Host: "198.51.100.5", Port: 8443, TLSServerName: "proxy.example"},
				Hysteria2:    &common.ExternalHysteria2Config{Server: "198.51.100.6", Port: 443, Password: "hy2-pass", TLSServerName: "hy2.example"},
				TorBridge:    &common.ExternalTorBridgeConfig{Transport: "obfs4", Bridges: []string{"obfs4 198.51.100.7:443 cert=abc iat-mode=0"}, SocksPort: 39050},
			},
		}},
	}

	cloned := cloneRouterProfileStore(store)
	if !reflect.DeepEqual(cloned, store) {
		t.Fatalf("deep clone changed profile values: cloned=%#v source=%#v", cloned, store)
	}

	// Mutate every reference-bearing field in the source. The rollback snapshot
	// must remain exactly as it was when cloneRouterProfileStore returned.
	source := &store.Profiles[0]
	source.CustomLayers[0] = "changed-source-layer"
	source.HomeLANCIDRs[0] = "10.0.0.0/8"
	source.DNSResults[0].Name = "changed-source-dns"
	source.External.ExpectedPublicIP = "203.0.113.99"
	source.External.WireGuard.Addresses[0] = "10.9.9.9/32"
	source.External.WireGuard.AllowedIPs[0] = "10.0.0.0/8"
	source.External.WireGuard.DNS[0] = "8.8.8.8"
	source.External.OpenVPN.Username = "changed-source-openvpn"
	source.External.Shadowsocks.Password = "changed-source-ss"
	source.External.SOCKS5.Username = "changed-source-socks"
	source.External.HTTPConnect.Username = "changed-source-http"
	source.External.HTTPSConnect.TLSServerName = "changed-source-https"
	source.External.Hysteria2.Password = "changed-source-hy2"
	source.External.TorBridge.Bridges[0] = "obfs4 192.0.2.1:443 cert=changed iat-mode=0"

	snapshot := &cloned.Profiles[0]
	checks := map[string]bool{
		"custom layers":            snapshot.CustomLayers[0] == "wg",
		"home LAN CIDRs":           snapshot.HomeLANCIDRs[0] == "192.168.50.0/24",
		"DNS results":              snapshot.DNSResults[0].Name == "resolver",
		"external config":          snapshot.External.ExpectedPublicIP == "203.0.113.10",
		"WireGuard addresses":      snapshot.External.WireGuard.Addresses[0] == "10.0.0.2/32",
		"WireGuard allowed IPs":    snapshot.External.WireGuard.AllowedIPs[0] == "0.0.0.0/0",
		"WireGuard DNS":            snapshot.External.WireGuard.DNS[0] == "9.9.9.9",
		"OpenVPN pointer":          snapshot.External.OpenVPN.Username == "ovpn-user",
		"Shadowsocks pointer":      snapshot.External.Shadowsocks.Password == "ss-pass",
		"SOCKS5 pointer":           snapshot.External.SOCKS5.Username == "socks-user",
		"HTTP CONNECT pointer":     snapshot.External.HTTPConnect.Username == "http-user",
		"HTTPS CONNECT pointer":    snapshot.External.HTTPSConnect.TLSServerName == "proxy.example",
		"Hysteria2 pointer":        snapshot.External.Hysteria2.Password == "hy2-pass",
		"Tor bridge pointer/slice": snapshot.External.TorBridge.Bridges[0] == "obfs4 198.51.100.7:443 cert=abc iat-mode=0",
	}
	for field, ok := range checks {
		if !ok {
			t.Errorf("source mutation leaked into cloned %s", field)
		}
	}

	// Mutate the snapshot too. Rollback callers may reuse a snapshot after a
	// failed persistence attempt, so the snapshot must not mutate the live store.
	snapshot.CustomLayers[1] = "changed-snapshot-layer"
	snapshot.External.WireGuard.Addresses[0] = "10.8.8.8/32"
	snapshot.External.OpenVPN.Password = "changed-snapshot-openvpn"
	snapshot.External.TorBridge.Bridges[0] = "snowflake changed-snapshot"
	if source.CustomLayers[1] != "padding" {
		t.Fatal("snapshot custom-layer mutation leaked back into live profile")
	}
	if source.External.WireGuard.Addresses[0] != "10.9.9.9/32" {
		t.Fatal("snapshot WireGuard mutation leaked back into live profile")
	}
	if source.External.OpenVPN.Password != "ovpn-pass" {
		t.Fatal("snapshot OpenVPN mutation leaked back into live profile")
	}
	if source.External.TorBridge.Bridges[0] != "obfs4 192.0.2.1:443 cert=changed iat-mode=0" {
		t.Fatal("snapshot Tor bridge mutation leaked back into live profile")
	}
}
