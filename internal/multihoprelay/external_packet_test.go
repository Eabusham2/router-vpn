package multihoprelay

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExternalPacketHKDFMatchesRFC5869SHA256CaseOne(t *testing.T) {
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	got := packetHKDF([]byte(strings.Repeat("\x0b", 22)), salt, string(info))
	if hex.EncodeToString(got) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" {
		t.Fatal("packet HKDF differs from the standard extract/expand vector")
	}
}

// Pairing tests invoke the actual Go compiler with these valid captured keys;
// Python never reimplements X25519 or constructs a successful pairing result.
func TestExportExternalPacketPairingFixtures(t *testing.T) {
	path := os.Getenv("ROUTERVPN_EXTERNAL_PACKET_PAIR_FIXTURES")
	if path == "" {
		t.Skip("external packet pairing fixture export not requested")
	}
	fixtures := map[string]any{}
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, layer := range externalLayers {
			ext, server, _ := externalPacketSource(t, protocol, layer)
			profile := map[string]any{"id": "external-exit", "node_kind": "external", "external": ext, "start_layer": layer}
			bundle := map[string]any{"selectedRouterID": "external-exit", "routerProfiles": []any{profile}}
			fixtures[protocol+"/"+layer] = map[string]any{"bundle": bundle, "server": server}
		}
	}
	raw, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func packetKey(t *testing.T, seed byte) (string, string) {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func externalPacketSource(t *testing.T, protocol, layerMode string) (map[string]any, map[string]any, *StartLayer) {
	t.Helper()
	local, _ := packetKey(t, 'l')
	server, serverPublic := packetKey(t, 'v')
	_, remote := packetKey(t, 'r')
	clientPSK, _ := packetKey(t, 'p')
	serverPSK, _ := packetKey(t, 'q')
	block := map[string]any{"private_key": local, "addresses": []string{"10.93.0.2/32", "fd93::2/128"}, "peer_public_key": remote, "preshared_key": clientPSK,
		"endpoint": "203.0.113.20:51820", "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "mtu": 1380, "persistent_keepalive_interval": 19, "dns": []string{"10.93.0.1"}}
	if protocol == "amneziawg" {
		block["parameters"] = map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10-19", "h2": "20-29", "h3": "30-39", "h4": "40-49"}
	}
	serverBlock, _ := copyMap(block)
	serverBlock["private_key"], serverBlock["preshared_key"], serverBlock["addresses"], serverBlock["mtu"], serverBlock["persistent_keepalive_interval"] = server, serverPSK, []string{"10.93.0.3/32", "fd93::3/128"}, 1360, 25
	serverProfile := map[string]any{"protocol": protocol, protocol: serverBlock}
	proxy, layer := externalProxySource(t, "shadowsocks", layerMode)
	ext := map[string]any{"protocol": protocol, protocol: block, "expected_public_ip": "203.0.113.88", "response_probe": proxy["response_probe"],
		"server_peer": map[string]any{"public_key": serverPublic, "addresses": []string{"10.93.0.3/32", "fd93::3/128"}, "mtu": 1360, "persistent_keepalive_interval": 25}}
	if layer != nil {
		ext["start_layer"] = proxy["start_layer"]
	}
	return ext, serverProfile, layer
}

func packetPair(t *testing.T, protocol, layer string) (Exit, Exit, Request) {
	t.Helper()
	ext, serverSource, wrapped := externalPacketSource(t, protocol, layer)
	client, err := ExternalSelection("exit", protocol, ext, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	server, err := PairExternalPacket("exit", protocol, ext, serverSource, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	q := req()
	q.ExitMode, q.ExitStartLayer = protocol, layer
	q.Port, q.Username, q.Password = 26240, strings.Repeat("1", 48), strings.Repeat("2", 48)
	q, err = AuthenticateExternalRequest(client, q)
	if err != nil {
		t.Fatal(err)
	}
	return client, server, q
}

func packetManager(t *testing.T, server Exit) (*Manager, *runner) {
	t.Helper()
	cfg := config()
	cfg.Exits = []Exit{server}
	r := &runner{}
	m, err := New(cfg, req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	return m, r
}

func packetChallenge(t *testing.T, m *Manager, client Exit, peer netip.Addr, q Request) Request {
	t.Helper()
	challenge, err := m.PacketChallenge(peer)
	if err != nil {
		t.Fatal(err)
	}
	q, err = ChallengeExternalPacketRequest(client, q, challenge)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestExternalPacketPairOwnsDistinctPrivatePeersAndPublicIdentity(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, layer := range externalLayers {
			t.Run(protocol+"/"+layer, func(t *testing.T) {
				client, server, q := packetPair(t, protocol, layer)
				if client.Transport["private_key"] == server.Transport["private_key"] || client.External.Packet.Owner != "client" || server.External.Packet.Owner != "server" {
					t.Fatal("packet private owners collapsed")
				}
				fingerprint, err := ExternalFingerprint(server)
				if err != nil || fingerprint != q.ExternalFingerprint || ValidateExternalRequest(server, q) != nil {
					t.Fatal("bilateral key agreement did not authenticate identical public captures", err)
				}
				localPrivate := client.Transport["private_key"].(string)
				serverPrivate := server.Transport["private_key"].(string)
				clientPSK := client.Transport["peers"].([]any)[0].(map[string]any)["pre_shared_key"].(string)
				serverPSK := server.Transport["peers"].([]any)[0].(map[string]any)["pre_shared_key"].(string)
				clientJSON, _ := json.Marshal(client)
				serverJSON, _ := json.Marshal(server)
				publicJSON, _ := json.Marshal(server.External)
				if strings.Contains(string(clientJSON), serverPrivate) || strings.Contains(string(clientJSON), serverPSK) || strings.Contains(string(serverJSON), localPrivate) || strings.Contains(string(serverJSON), clientPSK) {
					t.Fatal("opposite private key or PSK crossed pairing boundary")
				}
				for _, secret := range []string{localPrivate, serverPrivate, clientPSK, serverPSK} {
					if strings.Contains(string(publicJSON), secret) {
						t.Fatal("packet public identity contains credential material")
					}
				}
				cfg := config()
				cfg.Exits = []Exit{client}
				if _, err := New(cfg, q.EntryNodeID, &runner{}); err == nil {
					t.Fatal("registry accepted the local client owner")
				}
				m, r := packetManager(t, server)
				peer := netip.MustParseAddr("10.77.0.2")
				if _, err := m.Create(context.Background(), peer, q); err == nil {
					t.Fatal("prepared but unchallenged request started a packet relay")
				}
				q = packetChallenge(t, m, client, peer, q)
				lease, err := m.Create(context.Background(), peer, q)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Build(client, peer, lease); err == nil {
					t.Fatal("local private key entered server build")
				}
				var graph map[string]any
				if json.Unmarshal(r.configs[0], &graph) != nil {
					t.Fatal("invalid native packet graph")
				}
				endpoint := graph["endpoints"].([]any)[0].(map[string]any)
				nativePeer := endpoint["peers"].([]any)[0].(map[string]any)
				if endpoint["private_key"] != serverPrivate || nativePeer["pre_shared_key"] != serverPSK || !reflect.DeepEqual(endpoint["address"], server.Transport["address"]) || endpoint["mtu"] != float64(1360) || nativePeer["persistent_keepalive_interval"] != float64(25) {
					t.Fatal("server packet engine lost its independent exact private configuration")
				}
				if graph["dns"] != nil || graph["services"] != nil || len(graph["inbounds"].([]any)) != 1 {
					t.Fatal("packet lease acquired unowned resolver/listeners")
				}
				if protocol == "amneziawg" && !reflect.DeepEqual(endpoint["amnezia"], client.Transport["amnezia"]) {
					t.Fatal("AWG parameters substituted")
				}
				if layer == "" {
					if endpoint["detour"] != nil || nativePeer["address"] != "203.0.113.20" || len(graph["outbounds"].([]any)) != 0 {
						t.Fatal("unselected packet wrapper")
					}
				} else {
					outer := graph["outbounds"].([]any)[0].(map[string]any)
					if endpoint["detour"] != ExitStartLayerTag || nativePeer["address"] != "10.88.0.1" || outer["server"] != "203.0.113.20" || outer["password"] != server.StartLayer.Transport["password"] {
						t.Fatal("packet layer changed endpoint or ownership")
					}
				}
				var caps Capabilities
				catalog, _ := json.Marshal(map[string]any{"node_id": q.EntryNodeID, "execution": "server", "exits": m.Available()})
				if json.Unmarshal(catalog, &caps) != nil || caps.Validate(q.EntryNodeID) != nil || caps.Exits[0].PublicKey != server.External.Packet.Server["client_public_key"] {
					t.Fatal("packet public capability does not prove captured server peer")
				}
				for _, secret := range []string{localPrivate, serverPrivate, clientPSK, serverPSK, q.ExternalAuthentication} {
					if strings.Contains(string(catalog), secret) {
						t.Fatal("secret entered catalog")
					}
				}
				if m.Delete(context.Background(), peer, q) != nil || r.processes[0].alive {
					t.Fatal("packet teardown failed")
				}
			})
		}
	}
}

func TestExternalPacketPairRejectsWrongOwnersKeysAliasesAndRemoteParameters(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		mutations := map[string]func(map[string]any, map[string]any){
			"missing-server": func(ext, server map[string]any) { delete(ext, "server_peer") },
			"server-secret-in-client": func(ext, server map[string]any) {
				ext["server_peer"].(map[string]any)["private_key"] = server[protocol].(map[string]any)["private_key"]
			},
			"server-psk-in-client": func(ext, server map[string]any) {
				ext["server_peer"].(map[string]any)["preshared_key"] = server[protocol].(map[string]any)["preshared_key"]
			},
			"wrong-server-key": func(ext, server map[string]any) {
				key, _ := packetKey(t, 'x')
				server[protocol].(map[string]any)["private_key"] = key
			},
			"same-key": func(ext, server map[string]any) {
				_, public := packetKey(t, 'l')
				ext["server_peer"].(map[string]any)["public_key"] = public
			},
			"same-address": func(ext, server map[string]any) {
				ext["server_peer"].(map[string]any)["addresses"] = []string{"10.93.0.2/24", "fd93::3/128"}
			},
			"wrong-address": func(ext, server map[string]any) {
				server[protocol].(map[string]any)["addresses"] = []string{"10.93.0.4/32", "fd93::4/128"}
			},
			"wrong-remote": func(ext, server map[string]any) { server[protocol].(map[string]any)["endpoint"] = "203.0.113.21:51820" },
			"wrong-remote-key": func(ext, server map[string]any) {
				_, key := packetKey(t, 'x')
				server[protocol].(map[string]any)["peer_public_key"] = key
			},
			"wrong-mtu": func(ext, server map[string]any) { server[protocol].(map[string]any)["mtu"] = 1380 },
			"wrong-keepalive": func(ext, server map[string]any) {
				server[protocol].(map[string]any)["persistent_keepalive_interval"] = 19
			},
			"incomplete-family": func(ext, server map[string]any) {
				ext["server_peer"].(map[string]any)["addresses"] = []string{"10.93.0.3/32"}
			},
			"remote-response": func(ext, server map[string]any) {
				ext["response_probe"].(map[string]any)["url"] = "https://203.0.113.21/response"
			},
		}
		for name, mutate := range mutations {
			t.Run(protocol+"/"+name, func(t *testing.T) {
				ext, server, layer := externalPacketSource(t, protocol, "")
				mutate(ext, server)
				if _, err := PairExternalPacket("exit", protocol, ext, server, layer); err == nil {
					t.Fatal("inconsistent packet pairing accepted")
				}
			})
		}
		for _, raw := range [][]byte{make([]byte, 32), append([]byte{1}, make([]byte, 31)...), append([]byte{237}, append([]byte(strings.Repeat("\xff", 30)), 127)...)} {
			ext, _, _ := externalPacketSource(t, protocol, "")
			ext["server_peer"].(map[string]any)["public_key"] = base64.StdEncoding.EncodeToString(raw)
			if ValidateExternalServerPeer(protocol, ext) == nil {
				t.Fatal("low-order or noncanonical public key admitted before connection")
			}
		}
		ext, _, _ := externalPacketSource(t, protocol, "")
		pub := ext["server_peer"].(map[string]any)["public_key"].(string)
		raw, _ := base64.StdEncoding.DecodeString(pub)
		raw[31] |= 128
		ext["server_peer"].(map[string]any)["public_key"] = base64.StdEncoding.EncodeToString(raw)
		if ValidateExternalServerPeer(protocol, ext) == nil {
			t.Fatal("X25519 public high-bit alias accepted")
		}
		for alias := 0; alias < 32; alias++ {
			ext, server, layer := externalPacketSource(t, protocol, "")
			raw, _ := base64.StdEncoding.DecodeString(ext[protocol].(map[string]any)["private_key"].(string))
			raw[0] = raw[0]&248 | byte(alias&7)
			raw[31] = raw[31]&63 | byte((alias>>3)&3)<<6
			server[protocol].(map[string]any)["private_key"] = base64.StdEncoding.EncodeToString(raw)
			if _, err := PairExternalPacket("exit", protocol, ext, server, layer); err == nil {
				t.Fatal("aliased local private key used for server")
			}
		}
	}
}

func TestExternalPacketZeroKeepaliveOmissionPreservesSamePublicOwner(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		var want string
		for _, explicit := range []bool{false, true} {
			ext, server, layer := externalPacketSource(t, protocol, "")
			delete(ext[protocol].(map[string]any), "persistent_keepalive_interval")
			delete(ext["server_peer"].(map[string]any), "persistent_keepalive_interval")
			server[protocol].(map[string]any)["persistent_keepalive_interval"] = 0
			if explicit {
				ext[protocol].(map[string]any)["persistent_keepalive_interval"] = 0
				ext["server_peer"].(map[string]any)["persistent_keepalive_interval"] = 0
			}
			client, err := ExternalSelection("exit", protocol, ext, layer)
			if err != nil {
				t.Fatal(err)
			}
			paired, err := PairExternalPacket("exit", protocol, ext, server, layer)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint, err := ExternalFingerprint(paired)
			if err != nil {
				t.Fatal(err)
			}
			other, _ := ExternalFingerprint(client)
			if fingerprint != other || want != "" && fingerprint != want {
				t.Fatal("zero keepalive changed canonical pairing identity")
			}
			want = fingerprint
		}
	}
}

func TestExternalPacketRegistryPairDecoderDoesNotDiscardPrivateOrDuplicateFields(t *testing.T) {
	_, server, _ := packetPair(t, "wireguard", "")
	raw, _ := json.Marshal(server.External.Packet)
	for _, body := range []string{"null", "[]", "{}", strings.TrimSuffix(string(raw), "}") + `,"server_private_key":"secret"}`, strings.Replace(string(raw), `"owner":`, `"owner":"client","owner":`, 1), strings.Replace(string(raw), `"client_public_key":`, `"client_public_key":"other","client_public_key":`, 1)} {
		var decoded ExternalPacketPair
		if json.Unmarshal([]byte(body), &decoded) == nil {
			t.Fatal("private/ambiguous pairing fields silently discarded")
		}
	}
}

func TestExternalPacketRequestBindsChallengePeerAndEveryOwnerField(t *testing.T) {
	client, server, prepared := packetPair(t, "amneziawg", "aes-256-gcm+xor-whitening")
	m, r := packetManager(t, server)
	peer := netip.MustParseAddr("10.77.0.2")
	q := packetChallenge(t, m, client, peer, prepared)
	mutations := []func(*Request){func(q *Request) { q.ExternalEpoch = strings.Repeat("c", 64) }, func(q *Request) { q.ExternalPeer = "10.77.0.3" }, func(q *Request) { q.ExternalExpiresAt++ }, func(q *Request) { q.ExternalAttempt = strings.Repeat("f", 32) }, func(q *Request) { q.Port++ }, func(q *Request) { q.Password = strings.Repeat("f", 48) }, func(q *Request) { q.ExitStartLayer = "aes-256-gcm" }, func(q *Request) { q.SessionID = strings.Repeat("c", 32) }}
	for _, mutate := range mutations {
		bad := q
		mutate(&bad)
		if _, err := m.Create(context.Background(), peer, bad); err == nil {
			t.Fatal("unsigned field mutation acquired a packet lease")
		}
	}
	if _, err := m.Create(context.Background(), peer.Next(), q); err == nil {
		t.Fatal("valid request replayed by another tunnel peer")
	}
	wrong, _, _ := packetPair(t, "amneziawg", "aes-256-gcm+xor-whitening")
	wrong.StartLayer.Transport["password"], _ = packetKey(t, 'x')
	bad, err := AuthenticateExternalRequest(wrong, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), peer, bad); err == nil {
		t.Fatal("wrong outer layer secret authenticated")
	}
	if r.starts != 0 {
		t.Fatal("invalid acquisition altered engine state")
	}
	if _, err := m.Create(context.Background(), peer, q); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestExternalPacketAttemptsCannotReplayAfterCancelStopExpiryOrRestart(t *testing.T) {
	client, server, prepared := packetPair(t, "wireguard", "")
	peer := netip.MustParseAddr("10.77.0.2")
	for _, reason := range []string{"delete-before-put", "stopped", "expired", "failed-start", "failed-stop", "restart"} {
		t.Run(reason, func(t *testing.T) {
			m, r := packetManager(t, server)
			now := time.Now()
			m.now = func() time.Time { return now }
			q := packetChallenge(t, m, client, peer, prepared)
			switch reason {
			case "delete-before-put":
				if err := m.Delete(context.Background(), peer, q); err != nil {
					t.Fatal(err)
				}
			case "failed-start":
				r.fail = true
				if _, err := m.Create(context.Background(), peer, q); err == nil {
					t.Fatal("failed engine became usable")
				}
				r.fail = false
			case "restart":
				m, _ = packetManager(t, server)
			default:
				if _, err := m.Create(context.Background(), peer, q); err != nil {
					t.Fatal(err)
				}
				if reason == "expired" {
					now = now.Add(16 * time.Second)
					if err := m.Sweep(context.Background()); err != nil {
						t.Fatal(err)
					}
				} else {
					if reason == "failed-stop" {
						r.processes[0].stopFail = true
					}
					err := m.Delete(context.Background(), peer, q)
					if (err != nil) != (reason == "failed-stop") {
						t.Fatal("unexpected cleanup", err)
					}
				}
			}
			starts := r.starts
			if _, err := m.Create(context.Background(), peer, q); err == nil || r.starts != starts {
				t.Fatal("retired/foreign epoch attempt resurrected a relay")
			}
			if reason == "failed-stop" {
				now = now.Add(61 * time.Second)
				if _, err := m.Create(context.Background(), peer, q); err == nil {
					t.Fatal("expired tombstone revived unverified process")
				}
				r.processes[0].stopFail = false
				if err := m.Sweep(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			fresh := packetChallenge(t, m, client, peer, prepared)
			if fresh.ExternalAttempt == q.ExternalAttempt {
				t.Fatal("repeat winner reused the retired acquisition")
			}
			if _, err := m.Create(context.Background(), peer, fresh); err != nil {
				t.Fatal("fresh repeated winner did not acquire", err)
			}
			if err := m.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExternalPacketRenewalOutlivesInitialChallengeOnlyWhileOwned(t *testing.T) {
	client, server, prepared := packetPair(t, "wireguard", "")
	m, r := packetManager(t, server)
	peer := netip.MustParseAddr("10.77.0.2")
	now := time.Now()
	m.now = func() time.Time { return now }
	q := packetChallenge(t, m, client, peer, prepared)
	for i := 0; i < 12; i++ {
		if _, err := m.Create(context.Background(), peer, q); err != nil {
			t.Fatal("live owned renewal expired with acquisition challenge", err)
		}
		now = now.Add(10 * time.Second)
	}
	if r.starts != 1 {
		t.Fatal("renewal restarted packet engine")
	}
	if m.Delete(context.Background(), peer, q) != nil {
		t.Fatal("expired initial challenge prevented owned cleanup")
	}
	if _, err := m.Create(context.Background(), peer, q); err == nil {
		t.Fatal("expired acquisition recreated stopped packet engine")
	}
}

func TestExternalPacketCanonicalAliasesAcrossFamiliesHaveOneConcurrentOwner(t *testing.T) {
	_, server, _ := packetPair(t, "wireguard", "")
	cfg := config()
	cfg.Exits = nil
	cfg.LastPort = cfg.FirstPort + 31
	serverKey := server.Transport["private_key"].(string)
	var clients []Exit
	for i := 0; i < 32; i++ {
		protocol := "wireguard"
		if i%2 == 1 {
			protocol = "amneziawg"
		}
		ext, private, layer := externalPacketSource(t, protocol, "")
		raw, _ := base64.StdEncoding.DecodeString(serverKey)
		raw[0] = raw[0]&248 | byte(i&7)
		raw[31] = raw[31]&63 | byte((i>>3)&3)<<6
		private[protocol].(map[string]any)["private_key"] = base64.StdEncoding.EncodeToString(raw)
		id := fmt.Sprintf("alias-%d", i)
		e, err := PairExternalPacket(id, protocol, ext, private, layer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ExternalSelection(id, protocol, ext, layer)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Exits = append(cfg.Exits, e)
		clients = append(clients, c)
	}
	r := &runner{}
	m, err := New(cfg, req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for i := 0; i < 32; i++ {
		peer := netip.AddrFrom4([4]byte{10, 77, 0, byte(i + 2)})
		q := req()
		q.ExitID, q.ExitMode = clients[i].ID, clients[i].Mode
		q.Port, q.Username, q.Password = 26240+i, strings.Repeat("1", 48), strings.Repeat("2", 48)
		q, err = AuthenticateExternalRequest(clients[i], q)
		if err != nil {
			t.Fatal(err)
		}
		q = packetChallenge(t, m, clients[i], peer, q)
		wg.Add(1)
		go func(peer netip.Addr, q Request) {
			defer wg.Done()
			_, err := m.Create(context.Background(), peer, q)
			results <- err
		}(peer, q)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 || r.starts != 1 {
		t.Fatal("canonical packet aliases stole each other's roaming endpoint", success, r.starts)
	}
	if m.Close(context.Background()) != nil {
		t.Fatal("alias owner cleanup failed")
	}
}

func TestExternalPacketReplayMemoryIsBoundedAndDoesNotEvictUnexpiredAttempts(t *testing.T) {
	client, server, prepared := packetPair(t, "wireguard", "")
	m, r := packetManager(t, server)
	peer := netip.MustParseAddr("10.77.0.2")
	now := time.Now()
	m.now = func() time.Time { return now }
	for i := 0; i < maxPacketAttempts; i++ {
		m.packetAttempts[fmt.Sprintf("%064x", i)] = now.Add(time.Minute).Unix()
	}
	q := packetChallenge(t, m, client, peer, prepared)
	if _, err := m.Create(context.Background(), peer, q); err == nil || r.starts != 0 || len(m.packetAttempts) != maxPacketAttempts {
		t.Fatal("full replay ledger evicted live ownership or started untracked relay")
	}
	now = now.Add(time.Minute)
	q = packetChallenge(t, m, client, peer, prepared)
	if _, err := m.Create(context.Background(), peer, q); err != nil || len(m.packetAttempts) != 1 {
		t.Fatal("expired replay receipts did not release bounded capacity", err)
	}
	if m.Close(context.Background()) != nil {
		t.Fatal("bounded ledger cleanup")
	}
}

func TestExternalPacketAliasCannotRoamAnExistingRouterPacketLease(t *testing.T) {
	client, external, prepared := packetPair(t, "wireguard", "")
	for _, routerMode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(routerMode, func(t *testing.T) {
			key, _ := base64.StdEncoding.DecodeString(external.Transport["private_key"].(string))
			key[0] ^= 7
			key[31] ^= 192
			router := identityExit(t, "router-exit", routerMode, base64.StdEncoding.EncodeToString(key))
			cfg := config()
			cfg.Exits = []Exit{router, external}
			r := &runner{}
			m, err := New(cfg, prepared.EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			owner, other := netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")
			if _, err := m.Create(context.Background(), owner, identityRequest(router.ID, routerMode)); err != nil {
				t.Fatal(err)
			}
			request := packetChallenge(t, m, client, other, prepared)
			request.Port = 26241
			request, err = AuthenticateExternalRequest(client, request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Create(context.Background(), other, request); err == nil || r.starts != 1 {
				t.Fatal("external alias stole an active Router peer")
			}
			r.processes[0].stopFail = true
			if m.Delete(context.Background(), owner, identityRequest(router.ID, routerMode)) == nil {
				t.Fatal("cleanup failure missing")
			}
			if _, err := m.Create(context.Background(), other, request); err == nil || r.starts != 1 {
				t.Fatal("unverified Router cleanup released aliased packet peer")
			}
			r.processes[0].stopFail = false
			if m.Delete(context.Background(), owner, identityRequest(router.ID, routerMode)) != nil {
				t.Fatal("owned cleanup retry failed")
			}
			if _, err := m.Create(context.Background(), other, request); err != nil {
				t.Fatal("confirmed Router cleanup did not release canonical peer", err)
			}
			if m.Close(context.Background()) != nil {
				t.Fatal("external alias cleanup")
			}
		})
	}
}
