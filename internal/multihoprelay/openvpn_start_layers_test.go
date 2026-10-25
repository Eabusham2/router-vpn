package multihoprelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/nativeopenvpn"
)

func externalOpenVPNLayeredMapSource(t *testing.T, mode string) (map[string]any, map[string]any) {
	t.Helper()
	external, server := externalOpenVPNMappedSource(t)
	layers := map[string]any{}
	for index, host := range []string{"203.0.113.20", "203.0.113.21"} {
		layers[host] = map[string]any{"mode": mode, "api": "http://10.93.0.1:8787", "transport": map[string]any{
			"type": "shadowsocks", "tag": "provisioned-start", "server": host, "server_port": float64(8388 + index*2), "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune('s'+index)), 32))),
		}}
	}
	external["openvpn_start_layers"] = layers
	return external, server
}

func TestOpenVPNMappedStartLayersBindEveryPrivateOwnerAndPreserveV5(t *testing.T) {
	v5Client, _, v5Request := externalOpenVPNMappedPair(t)
	v5Before, _ := ExternalFingerprint(v5Client)
	for _, mode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(mode, func(t *testing.T) {
			external, serverSource := externalOpenVPNLayeredMapSource(t, mode)
			client, err := ExternalSelection("exit", "openvpn", external, nil)
			if err != nil {
				t.Fatal(err)
			}
			server, err := PairExternalOpenVPN("exit", external, serverSource, nil)
			if err != nil {
				t.Fatal(err)
			}
			request := v5Request
			request.ExitStartLayer = mode
			request, err = AuthenticateExternalRequest(client, request)
			if err != nil || ValidateExternalRequest(server, request) != nil || externalOpenVPNVersion(client) != "v6" || !OpenVPNLayersRequired(client) || ExitLayerMode(server) != mode {
				t.Fatal("v6 independent owner authentication failed", err)
			}
			fingerprint, _ := ExternalFingerprint(server)
			if fingerprint != request.ExternalFingerprint || fingerprint == v5Before || ValidateExternalRequest(server, v5Request) == nil {
				t.Fatal("v5/v6 ownership domains mixed")
			}
			for host := range server.External.OpenVPNStartLayers {
				body, _ := json.Marshal(server)
				var changed Exit
				_ = json.Unmarshal(body, &changed)
				changed.External.OpenVPNStartLayers[host].Transport["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
				public, _ := ExternalFingerprint(changed)
				if public != fingerprint {
					t.Fatal("public fingerprint contains a reusable private password hash")
				}
				if ValidateExternalRequest(changed, request) == nil {
					t.Fatal("one provider's private layer key was not authenticated")
				}
			}
			cfg := config()
			cfg.Exits = []Exit{server}
			runner := &openVPNRemoteTestRunner{}
			manager, err := New(cfg, request.EntryNodeID, runner)
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close(context.Background())
			caps := Capabilities{NodeID: request.EntryNodeID, Execution: "server"}
			encoded, _ := json.Marshal(manager.Available())
			if json.Unmarshal(encoded, &caps.Exits) != nil || caps.Validate(request.EntryNodeID) != nil || caps.Exits[0].OpenVPNLayers != "captured-per-remote-v1" || caps.Exits[0].Layer != mode {
				t.Fatal("mapped layer capability lost exact policy")
			}
			old := caps
			old.Exits = append([]Capability(nil), caps.Exits...)
			old.Exits[0].OpenVPNLayers = ""
			if old.Validate(request.EntryNodeID) == nil {
				t.Fatal("old remote observer falsely advertised mapped layer support")
			}
			peer := netip.MustParseAddr("10.77.0.2")
			request = challengedExternalFixture(t, manager, client, request, peer)
			lease, err := manager.Create(context.Background(), peer, request)
			if err != nil || lease.ExitStartLayer != mode || !lease.OpenVPNRemote {
				t.Fatal("mapped layer native lease rejected", err)
			}
			var graph map[string]any
			if json.Unmarshal(runner.config, &graph) != nil {
				t.Fatal("compiled native graph")
			}
			endpoint := graph["endpoints"].([]any)[0].(map[string]any)
			mapper := graph["outbounds"].([]any)[0].(map[string]any)
			if !reflect.DeepEqual(endpoint["servers"], server.Transport["servers"]) || endpoint["detour"] != OpenVPNStartLayerMapTag || mapper["type"] != nativeopenvpn.LayerMapType || mapper["detour"] != nil {
				t.Fatal("mapped relay rewrote original remote identity or added foreign detour")
			}
			for _, key := range []string{"type", "tag"} {
				delete(mapper, key)
			}
			raw, _ := json.Marshal(mapper)
			var mapping nativeopenvpn.LayerMap
			if json.Unmarshal(raw, &mapping) != nil || !reflect.DeepEqual(mapping.Layers, server.External.OpenVPNStartLayers) {
				t.Fatal("compiled mapper substituted per-host private credentials")
			}
			if err := manager.Delete(context.Background(), peer, request); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Create(context.Background(), peer, request); err == nil {
				t.Fatal("deleted v6 attempt replay recreated a lease")
			}
		})
	}
	if current, _ := ExternalFingerprint(v5Client); current != v5Before || externalOpenVPNVersion(v5Client) != "v5" {
		t.Fatal("legacy mapped Off identity changed")
	}
}

func TestOpenVPNMappedStartLayersRejectPartialOrForeignPolicy(t *testing.T) {
	external, _ := externalOpenVPNLayeredMapSource(t, "aes-256-gcm")
	raw, _ := json.Marshal(external)
	for name, mutate := range map[string]func(map[string]any){
		"no probes":        func(e map[string]any) { delete(e, "openvpn_response_probes") },
		"null singular":    func(e map[string]any) { e["start_layer"] = nil },
		"null legacy":      func(e map[string]any) { e["response_probe"] = nil },
		"missing provider": func(e map[string]any) { delete(e["openvpn_start_layers"].(map[string]any), "203.0.113.21") },
		"mixed modes": func(e map[string]any) {
			e["openvpn_start_layers"].(map[string]any)["203.0.113.21"].(map[string]any)["mode"] = "aes-256-gcm+xor-whitening"
		},
		"other provider key owner": func(e map[string]any) {
			e["openvpn_start_layers"].(map[string]any)["203.0.113.21"].(map[string]any)["transport"].(map[string]any)["server"] = "203.0.113.20"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var other map[string]any
			_ = json.Unmarshal(raw, &other)
			mutate(other)
			if _, err := ExternalTransport("openvpn", other); err == nil {
				t.Fatal("Local accepted malformed mapped policy")
			}
			if _, err := ExternalSelection("exit", "openvpn", other, nil); err == nil {
				t.Fatal("Server accepted malformed mapped policy")
			}
		})
	}
}

func TestOpenVPNMappedLayerKeysCannotDiscloseEitherPairingPrivateIdentity(t *testing.T) {
	for _, role := range []string{"local", "server"} {
		for _, alias := range []bool{false, true} {
			external, server := externalOpenVPNLayeredMapSource(t, "aes-256-gcm")
			secret := external["openvpn_pairing"].(map[string]any)["private_key"].(string)
			if role == "server" {
				secret = server["pairing_private_key"].(string)
			}
			if alias {
				value, _ := base64.StdEncoding.DecodeString(secret)
				value[0] ^= 7
				secret = base64.StdEncoding.EncodeToString(value)
				clear(value)
			}
			layer := external["openvpn_start_layers"].(map[string]any)["203.0.113.21"].(map[string]any)
			layer["transport"].(map[string]any)["password"] = secret
			if ValidateExternalOpenVPNPairing("openvpn", external) == nil {
				t.Fatal("Local accepted an outer key disclosing a pairing identity")
			}
			if _, err := ExternalSelection("exit", "openvpn", external, nil); err == nil {
				t.Fatal("client captured a reusable pairing private identity as a shared outer key")
			}
			if _, err := PairExternalOpenVPN("exit", external, server, nil); err == nil {
				t.Fatal("pairer exported a role's private pairing identity")
			}
		}
	}
}
