package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func packetAgentFixture(t *testing.T, protocol string) (map[string]any, multihoprelay.Exit, multihoprelay.Exit, multihoprelay.Request) {
	t.Helper()
	local, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	server, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{29}, 32))
	remote, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{41}, 32))
	block := map[string]any{"private_key": base64.StdEncoding.EncodeToString(local.Bytes()), "addresses": []string{"10.93.0.2/32", "fd93::2/128"}, "peer_public_key": base64.StdEncoding.EncodeToString(remote.PublicKey().Bytes()), "endpoint": "203.0.113.20:51820", "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "mtu": 1380}
	if protocol == "amneziawg" {
		block["parameters"] = map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10-19", "h2": "20-29", "h3": "30-39", "h4": "40-49"}
	}
	ext := map[string]any{"protocol": protocol, protocol: block, "expected_public_ip": "203.0.113.88", "response_probe": map[string]any{"url": "https://203.0.113.20/response", "server_name": "node.example"}, "server_peer": map[string]any{"public_key": base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), "addresses": []string{"10.93.0.3/32", "fd93::3/128"}, "mtu": 1360}}
	raw, _ := json.Marshal(block)
	var serverBlock map[string]any
	_ = json.Unmarshal(raw, &serverBlock)
	serverBlock["private_key"], serverBlock["addresses"], serverBlock["mtu"] = base64.StdEncoding.EncodeToString(server.Bytes()), []string{"10.93.0.3/32", "fd93::3/128"}, 1360
	serverProfile := map[string]any{"protocol": protocol, protocol: serverBlock}
	client, err := multihoprelay.ExternalSelection("external-exit", protocol, ext, nil)
	if err != nil {
		t.Fatal(err)
	}
	paired, err := multihoprelay.PairExternalPacket(client.ID, protocol, ext, serverProfile, nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := multihoprelay.AuthenticateExternalRequest(client, multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: strings.Repeat("a", 64), ExitID: client.ID, ExitMode: protocol, Port: 26240, Username: strings.Repeat("d", 48), Password: strings.Repeat("e", 48)})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"alias": client.ID, "external": ext, "server_peer_profile": serverProfile, "selected_layer": "off"}, client, paired, q
}

func TestExternalPacketOfflinePairCompilerPreservesOnlyCorrectPrivateOwner(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		t.Run(protocol, func(t *testing.T) {
			payload, client, server, _ := packetAgentFixture(t, protocol)
			body, _ := json.Marshal(payload)
			var output bytes.Buffer
			if err := compileExternalPacketPair(bytes.NewReader(body), &output); err != nil {
				t.Fatal(err)
			}
			var actual multihoprelay.Exit
			if json.Unmarshal(output.Bytes(), &actual) != nil || actual.External.Packet.Owner != "server" || actual.Transport["private_key"] != server.Transport["private_key"] || strings.Contains(output.String(), client.Transport["private_key"].(string)) {
				t.Fatal("offline pairing leaked or substituted local key")
			}
			expected, _ := multihoprelay.ExternalFingerprint(client)
			identity, err := multihoprelay.ExternalFingerprint(actual)
			if err != nil || identity != expected {
				t.Fatal("compiled server changed public pairing identity")
			}
			for _, raw := range []string{string(body) + "{}", strings.Replace(string(body), `"alias":`, `"alias":"other","alias":`, 1), strings.Replace(string(body), `"selected_layer":"off"`, `"selected_layer":null`, 1), strings.Replace(string(body), `"server_peer":{`, `"server_peer":{"private_key":"secret",`, 1)} {
				output.Reset()
				if compileExternalPacketPair(strings.NewReader(raw), &output) == nil || output.Len() != 0 {
					t.Fatal("ambiguous packet input emitted private output")
				}
			}
		})
	}
}

func TestExternalPacketHTTPChallengeDecoderLeaseAndRetiredReplay(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		t.Run(protocol, func(t *testing.T) {
			_, client, paired, prepared := packetAgentFixture(t, protocol)
			runner := &layerRunner{}
			manager, err := multihoprelay.New(multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26241, Exits: []multihoprelay.Exit{paired}}, prepared.EntryNodeID, runner)
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close(context.Background())
			_, subnet, _ := net.ParseCIDR("10.77.0.0/24")
			server := &server{cfg: cfg{Token: "private-route-token", NodeID: prepared.EntryNodeID}, nets: []*net.IPNet{subnet}, relay: manager}
			mux := http.NewServeMux()
			registerMultihopRelayRoute(mux, server)
			call := func(method, path, body, peer, token string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.RemoteAddr = peer
				r.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				return w
			}
			const peer, token = "10.77.0.2:4321", "private-route-token"
			legacy := call("GET", multihopRelayPath, "", peer, token)
			if legacy.Code != 200 || strings.Contains(legacy.Body.String(), "external_packet_challenge") {
				t.Fatal("legacy strict catalog changed")
			}
			for _, credentials := range [][2]string{{peer, "wrong"}, {"192.0.2.1:4321", token}} {
				if w := call("GET", multihopRelayPath+"?external_packet=1", "", credentials[0], credentials[1]); w.Code != 403 {
					t.Fatal("unproved caller received challenge")
				}
			}
			for _, query := range []string{"?external_packet=0", "?external_packet=1&external_packet=1", "?external_packet=1&peer=10.77.0.99"} {
				if w := call("GET", multihopRelayPath+query, "", peer, token); w.Code != 400 {
					t.Fatal("ambiguous challenge query accepted")
				}
			}
			w := call("GET", multihopRelayPath+"?external_packet=1", "", peer, token)
			var caps multihoprelay.Capabilities
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &caps) != nil || caps.Validate(prepared.EntryNodeID) != nil || caps.PacketChallenge == nil || caps.PacketChallenge.Peer != "10.77.0.2" {
				t.Fatal("entry did not bind challenge to actual tunnel peer")
			}
			q, err := multihoprelay.ChallengeExternalPacketRequest(client, prepared, *caps.PacketChallenge)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(q)
			if decoded, err := decodeRelayRequest(bytes.NewReader(body)); err != nil || decoded != q {
				t.Fatal("signed packet ownership was dropped by production decoder", err)
			}
			for _, field := range []string{"external_epoch", "external_peer", "external_expires_at", "external_attempt"} {
				var object map[string]any
				_ = json.Unmarshal(body, &object)
				delete(object, field)
				raw, _ := json.Marshal(object)
				if _, err := decodeRelayRequest(bytes.NewReader(raw)); err == nil {
					t.Fatal("partial packet challenge accepted")
				}
				_ = json.Unmarshal(body, &object)
				object[field] = nil
				raw, _ = json.Marshal(object)
				if _, err := decodeRelayRequest(bytes.NewReader(raw)); err == nil {
					t.Fatal("null challenge accepted")
				}
			}
			for _, raw := range []string{strings.Replace(string(body), `"external_attempt":`, `"external_attempt":"`+strings.Repeat("f", 32)+`","external_attempt":`, 1), strings.Replace(string(body), `"external_expires_at":`, `"external_expires_at":1.5,"external_expires_at":`, 1), strings.Replace(string(body), `"exit_mode":"`+protocol+`"`, `"exit_mode":"shadowsocks"`, 1)} {
				if _, err := decodeRelayRequest(strings.NewReader(raw)); err == nil {
					t.Fatal("ambiguous/cross-family challenge accepted")
				}
			}
			if w := call("PUT", multihopRelayPath, string(body), "10.77.0.3:4321", token); w.Code != 403 || runner.starts != 0 {
				t.Fatal("signed acquisition replayed by different peer")
			}
			if w := call("DELETE", multihopRelayPath, string(body), peer, token); w.Code != 200 {
				t.Fatal("cancel-before-PUT not acknowledged")
			}
			if w := call("PUT", multihopRelayPath, string(body), peer, token); w.Code != 403 || runner.starts != 0 {
				t.Fatal("delayed retired acquisition started")
			}
			q, err = multihoprelay.ChallengeExternalPacketRequest(client, prepared, *caps.PacketChallenge)
			if err != nil {
				t.Fatal(err)
			}
			body, _ = json.Marshal(q)
			if w := call("PUT", multihopRelayPath, string(body), peer, token); w.Code != 200 || runner.starts != 1 {
				t.Fatal("fresh independent packet acquisition failed", w.Code)
			}
			if w := call("DELETE", multihopRelayPath, string(body), peer, token); w.Code != 200 || runner.process.alive {
				t.Fatal("owned packet deletion failed")
			}
			if _, err := manager.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); err == nil {
				t.Fatal("stopped request reactivated")
			}
		})
	}
}
