package common

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/nativeopenvpn"
)

func externalOpenVPNPairedTestProfile(t *testing.T, layer string) RouterProfile {
	t.Helper()
	p := externalLayerTestProfile("shadowsocks", layer)
	config := "\nclient\nremote \"203.0.113.20\" 1194 udp\nremote 203.0.113.20 443 tcp\npeer-fingerprint " + strings.Repeat("a", 64) + "\nverify-x509-name provider.example name\ntun-mtu 1500\n"
	p.External.Protocol = "openvpn"
	p.External.Shadowsocks = nil
	p.External.OpenVPN = &ExternalOpenVPNConfig{Config: config, Username: " exact local user ", Password: " exact local password "}
	server := *p.External.OpenVPN
	server.Username = "separate server user"
	server.Password = "separate server password"
	private := func(char string) string { return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(char, 32))) }
	descriptor, err := nativeopenvpn.DescribePeer(server, private("b"))
	if err != nil {
		t.Fatal(err)
	}
	p.External.OpenVPNPairing = &ExternalOpenVPNPairing{PrivateKey: private("a"), Server: descriptor}
	return p
}

func TestExternalOpenVPNPairingRoundtripPreservesOriginalSourceAndOwnedPrivateCapture(t *testing.T) {
	for _, layer := range []string{StartLayerOff, StartLayerAES256GCM, StartLayerAES256GCMXOR} {
		t.Run(layer, func(t *testing.T) {
			p := externalOpenVPNPairedTestProfile(t, layer)
			before := unnormalizedProfileJSON(t, p)
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			var imported RouterProfile
			if err := json.Unmarshal(raw, &imported); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, unnormalizedProfileJSON(t, p)) {
				t.Fatal("serialization mutated private original OpenVPN source")
			}
			if *imported.External.OpenVPN != *p.External.OpenVPN || imported.External.OpenVPNPairing.PrivateKey != p.External.OpenVPNPairing.PrivateKey || imported.StartLayer != layer {
				t.Fatal("import changed original profile, credentials, pairing key or Start Layer")
			}
			clone := CloneRouterProfile(p)
			p.External.OpenVPNPairing.Server.Transport["servers"].([]any)[0].(map[string]any)["server_port"] = float64(9999)
			p.External.OpenVPNPairing.Server.Transport["tls"].(map[string]any)["server_name"] = "changed"
			p.External.OpenVPN.Password = "changed"
			if clone.External.OpenVPNPairing.Server.Transport["servers"].([]any)[0].(map[string]any)["server_port"] != float64(1194) || clone.External.OpenVPNPairing.Server.Transport["tls"].(map[string]any)["server_name"] != "provider.example" || clone.External.OpenVPN.Password == "changed" {
				t.Fatal("clone retained another profile's private descriptor ownership")
			}
			public, _ := json.Marshal(imported.External.OpenVPNPairing.Server)
			for _, secret := range []string{"separate server password", imported.External.OpenVPNPairing.PrivateKey, "client_key", "password", "private_key"} {
				if strings.Contains(string(public), secret) {
					t.Fatal("public counterpart descriptor contains private source")
				}
			}
		})
	}
}

func TestExternalOpenVPNPairingSchemaRejectsDroppedSecretFieldsNullAndDuplicateIdentity(t *testing.T) {
	p := externalOpenVPNPairedTestProfile(t, StartLayerOff)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(raw, &root)
	var ext map[string]json.RawMessage
	_ = json.Unmarshal(root["external"], &ext)
	good := string(ext["openvpn_pairing"])
	for _, bad := range []string{"null", "[]", "{}", strings.TrimSuffix(good, "}") + `,"private_key":"duplicate"}`, strings.Replace(good, `"server":{`, `"server":{"private_key":"hidden",`, 1), strings.Replace(good, `"provider_identity":{`, `"provider_identity":{"password":"hidden",`, 1), strings.Replace(good, `"pairing_public_key":`, `"pairing_public_key":null,"pairing_public_key":`, 1)} {
		ext["openvpn_pairing"] = json.RawMessage(bad)
		root["external"], _ = json.Marshal(ext)
		changed, _ := json.Marshal(root)
		var imported RouterProfile
		if json.Unmarshal(changed, &imported) == nil {
			t.Fatal("ambiguous OpenVPN private import accepted")
		}
	}
	for _, mutate := range []func(*RouterProfile){
		func(p *RouterProfile) { p.External.OpenVPN.Username = "separate server user" },
		func(p *RouterProfile) { p.External.OpenVPNPairing.Server.Transport["mtu"] = float64(9000) },
		func(p *RouterProfile) {
			p.External.OpenVPNPairing.Server.ProviderIdentity.Username = "exact local user"
		},
		func(p *RouterProfile) { p.External.OpenVPNPairing.Server.Transport["password"] = "hidden" },
		func(p *RouterProfile) { p.External.ResponseProbe.URL = "https://203.0.113.21/response" },
		func(p *RouterProfile) {
			p.External.OpenVPN.Config = strings.Replace(p.External.OpenVPN.Config, "203.0.113.20 443", "203.0.113.21 443", 1)
		},
	} {
		candidate := externalOpenVPNPairedTestProfile(t, StartLayerOff)
		mutate(&candidate)
		if _, err := json.Marshal(candidate); err == nil {
			t.Fatal("unowned provider pairing serialized")
		}
	}
}

func TestExternalOpenVPNLocalMultiremoteRemainsAvailableWithoutPairing(t *testing.T) {
	p := externalOpenVPNPairedTestProfile(t, StartLayerOff)
	p.External.OpenVPNPairing = nil
	p.External.ResponseProbe = nil
	p.External.OpenVPN.Config = strings.Replace(p.External.OpenVPN.Config, "203.0.113.20 443", "2001:db8::24 443", 1)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal("Local import lost different-host remote support", err)
	}
	var imported RouterProfile
	if json.Unmarshal(raw, &imported) != nil || imported.External.OpenVPN.Config != p.External.OpenVPN.Config {
		t.Fatal("Local source was replaced during serialization")
	}
}
