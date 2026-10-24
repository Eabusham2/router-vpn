package common

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func externalPacketTestProfile(t *testing.T, protocol, layer string) RouterProfile {
	t.Helper()
	local := bytes.Repeat([]byte{19}, 32)
	remote, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{23}, 32))
	server, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{29}, 32))
	p := externalLayerTestProfile("shadowsocks", layer)
	p.External.Protocol = protocol
	p.External.Shadowsocks = nil
	w := ExternalWireGuardConfig{PrivateKey: base64.StdEncoding.EncodeToString(local), Addresses: []string{"10.93.0.2/32", "fd93::2/128"}, PeerPublicKey: base64.StdEncoding.EncodeToString(remote.PublicKey().Bytes()), PresharedKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{31}, 32)), Endpoint: "203.0.113.20:51820", AllowedIPs: []string{"0.0.0.0/0", "::/0"}, MTU: 1380}
	if protocol == "wireguard" {
		p.External.WireGuard = &w
	} else {
		p.External.AmneziaWG = &ExternalAmneziaWGConfig{ExternalWireGuardConfig: w, Parameters: map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10-19", "h2": "20-29", "h3": "30-39", "h4": "40-49"}}
	}
	p.External.ServerPeer = &ExternalServerPeer{PublicKey: base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), Addresses: []string{"10.93.0.3/32", "fd93::3/128"}, MTU: 1360, PersistentKeepalive: 25}
	return p
}

func TestExternalPacketPublicServerPeerRoundTripAndCaptureOwnsAddresses(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, layer := range []string{StartLayerOff, StartLayerAES256GCM, StartLayerAES256GCMXOR} {
			t.Run(protocol+"/"+layer, func(t *testing.T) {
				p := externalPacketTestProfile(t, protocol, layer)
				before := unnormalizedProfileJSON(t, p)
				raw, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				var imported RouterProfile
				if json.Unmarshal(raw, &imported) != nil || imported.External.ServerPeer.PublicKey != p.External.ServerPeer.PublicKey || imported.External.ServerPeer.MTU != 1360 || imported.External.ServerPeer.PersistentKeepalive != 25 || imported.StartLayer != layer {
					t.Fatal("typed packet public peer or layer lost on import")
				}
				if !bytes.Equal(before, unnormalizedProfileJSON(t, p)) {
					t.Fatal("serialization mutated live captured peer")
				}
				clone := CloneRouterProfile(p)
				p.External.ServerPeer.Addresses[0] = "10.93.0.99/32"
				p.External.ServerPeer.MTU = 1500
				if clone.External.ServerPeer.Addresses[0] != "10.93.0.3/32" || clone.External.ServerPeer.MTU != 1360 {
					t.Fatal("captured server descriptor aliases live node")
				}
				var object map[string]json.RawMessage
				_ = json.Unmarshal(raw, &object)
				var ext map[string]json.RawMessage
				_ = json.Unmarshal(object["external"], &ext)
				if strings.Contains(string(ext["server_peer"]), "private_key") || strings.Contains(string(ext["server_peer"]), "preshared_key") {
					t.Fatal("server descriptor contains a private credential")
				}
			})
		}
	}
}

func TestExternalPacketPublicServerPeerRejectsAmbiguousSecretAndAliasImports(t *testing.T) {
	p := externalPacketTestProfile(t, "wireguard", StartLayerOff)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	var ext map[string]json.RawMessage
	_ = json.Unmarshal(object["external"], &ext)
	good := string(ext["server_peer"])
	for _, bad := range []string{"null", "{}", "[]", strings.TrimSuffix(good, "}") + `,"private_key":"secret"}`, strings.TrimSuffix(good, "}") + `,"preshared_key":"secret"}`, strings.Replace(good, `"mtu":1360`, `"mtu":null`, 1), strings.Replace(good, `"mtu":1360`, `"mtu":1360,"mtu":1500`, 1), strings.Replace(good, `"mtu":1360`, `"mtu":1360.5`, 1)} {
		ext["server_peer"] = json.RawMessage(bad)
		object["external"], _ = json.Marshal(ext)
		changed, _ := json.Marshal(object)
		var imported RouterProfile
		if json.Unmarshal(changed, &imported) == nil {
			t.Fatal("ambiguous or secret-bearing server descriptor accepted")
		}
	}
	mutations := []func(*RouterProfile){
		func(p *RouterProfile) { p.External.ServerPeer.MTU = 1279 }, func(p *RouterProfile) { p.External.ServerPeer.PersistentKeepalive = 65536 },
		func(p *RouterProfile) { p.External.ServerPeer.Addresses = []string{"10.93.0.2/24", "fd93::3/128"} },
		func(p *RouterProfile) { p.External.ServerPeer.Addresses = []string{"10.93.0.3/32"} },
		func(p *RouterProfile) {
			p.External.ServerPeer.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
		},
		func(p *RouterProfile) {
			raw, _ := base64.StdEncoding.DecodeString(p.External.ServerPeer.PublicKey)
			raw[31] |= 128
			p.External.ServerPeer.PublicKey = base64.StdEncoding.EncodeToString(raw)
		},
		func(p *RouterProfile) {
			raw, _ := base64.StdEncoding.DecodeString(p.External.WireGuard.PrivateKey)
			key, _ := ecdh.X25519().NewPrivateKey(raw)
			p.External.ServerPeer.PublicKey = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
		},
	}
	for _, mutate := range mutations {
		p := externalPacketTestProfile(t, "wireguard", StartLayerOff)
		mutate(&p)
		if _, err := json.Marshal(p); err == nil {
			t.Fatal("unsafe server public peer serialized")
		}
	}
	p = externalLayerTestProfile("shadowsocks", StartLayerOff)
	p.External.ServerPeer = &ExternalServerPeer{PublicKey: "captured", Addresses: []string{"10.93.0.3/32"}, MTU: 1280}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("proxy accepted packet-only credentials")
	}
}
