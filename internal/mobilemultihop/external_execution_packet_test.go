package mobilemultihop

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func externalPacketServerKey(t *testing.T) (string, string) {
	t.Helper()
	raw := []byte(strings.Repeat("v", 32))
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func externalExecutionPacketFixture(t *testing.T, protocol, selection, layer string) (string, string) {
	t.Helper()
	graph, capture := externalTestFixture(t, "wireguard", "router-wg")
	if protocol == "amneziawg" {
		externalAmneziaReplace(t, graph, capture, false, "strong")
	}
	entry := externalTestFind(t, graph, "entry-wg")
	entry["mtu"] = float64(1500)
	profile := capture["profile"].(map[string]any)
	profile["multihop_enabled"], profile["multihop_entry_id"], profile["multihop_exit_id"], profile["multihop_exit_mode"], profile["multihop_execution"] = true, "saved-entry", "saved-exit", protocol, selection
	ext := profile["external"].(map[string]any)
	block := ext[protocol].(map[string]any)
	native := externalTestFind(t, graph, ExternalFinalTag)
	peer := native["peers"].([]any)[0].(map[string]any)
	peer["address"] = "203.0.113.20"
	block["endpoint"] = net.JoinHostPort("203.0.113.20", "443")
	peer["port"] = float64(443)
	ext["response_probe"] = map[string]any{"url": "https://203.0.113.20/node-response", "server_name": "example.com"}
	_, public := externalPacketServerKey(t)
	ext["server_peer"] = map[string]any{"public_key": public, "addresses": []string{"10.94.0.3/32", "fd94::3/128"}, "mtu": 1360, "persistent_keepalive_interval": 25}
	if layer != "" {
		profile["start_layer"] = layer
		ext["start_layer"] = map[string]any{"mode": layer, "api": "http://10.93.0.1:8787", "transport": map[string]any{"type": "shadowsocks", "tag": "captured-exit-start", "server": "203.0.113.20", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("w", 32)))}}
	}
	return externalTestJSON(t, graph), externalTestJSON(t, capture)
}

func externalPacketServerProfile(t *testing.T, protocol string, external map[string]any) map[string]any {
	t.Helper()
	block := predecessorCopy(external[protocol].(map[string]any))
	descriptor := external["server_peer"].(map[string]any)
	private, _ := externalPacketServerKey(t)
	block["private_key"], block["preshared_key"], block["addresses"], block["mtu"], block["persistent_keepalive_interval"] = private, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32))), descriptor["addresses"], descriptor["mtu"], descriptor["persistent_keepalive_interval"]
	return map[string]any{"protocol": protocol, protocol: block}
}

func TestExternalPacketExecutionCapturesBothEndpointsAndBoundedLayerMTU(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, execution := range []string{"local", "server", "auto"} {
				t.Run(protocol+"/"+layer+"/"+execution, func(t *testing.T) {
					source, capture := externalExecutionPacketFixture(t, protocol, execution, layer)
					prepared, err := PrepareExternalExecutionCapture(source, capture, "")
					if err != nil {
						t.Fatal(err)
					}
					policy, err := NewExternalPolicy(source, prepared)
					if err != nil {
						t.Fatal(err)
					}
					graph := externalTestRead(t, policy.Config())
					tag := LocalTag
					if execution == "local" {
						tag = ExternalFinalTag
					}
					local := externalTestFind(t, graph, tag)
					original := externalTestFind(t, externalTestRead(t, source), ExternalFinalTag)
					if local["private_key"] != original["private_key"] || !reflect.DeepEqual(local["address"], original["address"]) || local["type"] != original["type"] {
						t.Fatal("local private packet owner changed")
					}
					localPeer := local["peers"].([]any)[0].(map[string]any)
					originalPeer := original["peers"].([]any)[0].(map[string]any)
					if localPeer["public_key"] != originalPeer["public_key"] || localPeer["pre_shared_key"] != originalPeer["pre_shared_key"] || !reflect.DeepEqual(localPeer["allowed_ips"], originalPeer["allowed_ips"]) {
						t.Fatal("packet peer credentials/routes changed")
					}
					if layer != "" {
						if localPeer["address"] != "10.93.0.1" || local["detour"] != multihoprelay.ExitStartLayerTag {
							t.Fatal("packet wrapper missing")
						}
						outer := externalTestFind(t, graph, multihoprelay.ExitStartLayerTag)
						if outer["detour"] != "entry-wg" {
							t.Fatal("packet wrapper bypassed entry")
						}
					}
					meta := externalTestRead(t, policy.Metadata())
					if meta["dns_detour"] != ExternalFinalTag || meta["entry_proof"] != "required" || meta["public_exit_proof"] != "required" || meta["configured_mtu"] != float64(1280) {
						t.Fatal("packet execution lost selected policies")
					}
					serverKey, _ := externalPacketServerKey(t)
					if strings.Contains(policy.Config(), serverKey) {
						t.Fatal("server private peer entered the native client graph")
					}
					if execution != "local" {
						c, err := newExternalExecution(policy)
						if err != nil || c.localPublicKey == "" || c.proposal.ExternalEpoch != "" {
							t.Fatal("prepared packet selection manufactured a live acquisition")
						}
						if _, err := externalRelaySelection(policy.capture); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		source, capture := externalExecutionPacketFixture(t, "amneziawg", "auto", layer)
		graph := externalTestRead(t, source)
		externalTestFind(t, graph, "entry-wg")["mtu"] = float64(1420)
		if _, err := PrepareExternalExecutionCapture(externalTestJSON(t, graph), capture, ""); err == nil {
			t.Fatal("nested AWG plus SS2022 exceeded entry MTU without rejection")
		}
	}
}

func TestExternalPacketExecutionCompareRepeatsWithFreshAttemptAndExactScore(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public-a", "http://1.0.0.1/public-b"}
	defer func() { Targets = previous }()
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(protocol+"/"+layer, func(t *testing.T) {
				source, capture := externalExecutionPacketFixture(t, protocol, "auto", layer)
				request, engine := externalExecutionCapturedRequest(t, source, capture, "")
				if _, err := request.Run(); err != nil {
					t.Fatal(err)
				}
				if !request.Healthy() || request.Execution() != "server" {
					t.Fatal("lower valid packet Server score did not win")
				}
				var progress Progress
				if json.Unmarshal([]byte(request.ProgressJSON()), &progress) != nil || len(progress.Measurements) != 2 {
					t.Fatal("packet Compare missing measurements")
				}
				for _, m := range progress.Measurements {
					if !m.Eligible || m.ScoreMS == nil || *m.ScoreMS != m.LastNodeMS/2+m.ExternalMS/2 {
						t.Fatal("packet Compare changed required average")
					}
				}
				engine.mu.Lock()
				attempts := append([]multihoprelay.Request(nil), engine.leaseRequests...)
				targets := engine.probeTargets
				engine.mu.Unlock()
				if len(attempts) != 2 || attempts[0].ExternalAttempt == attempts[1].ExternalAttempt || attempts[0].SessionID != attempts[1].SessionID || attempts[0].Password != attempts[1].Password || attempts[0].ExternalFingerprint != attempts[1].ExternalFingerprint {
					t.Fatal("winner repeat reused retired attempt or changed captured graph")
				}
				if targets[LocalTag][1] != targets[ServerTag][1] || targets[ServerTag][1] != targets[ServerTag][3] {
					t.Fatal("packet candidates used different external targets")
				}
				if _, err := engine.manager.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), attempts[0]); err == nil {
					t.Fatal("old trial attempt replaced retained winner")
				}
				if err := request.Close(); err != nil {
					t.Fatal(err)
				}
				for _, p := range engine.runner.processes {
					if p.Alive() {
						t.Fatal("packet trial engine leaked")
					}
				}
			})
		}
	}
}

func TestExternalPacketExecutionRejectsUnprovedChallengeOrServerIdentity(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public"}
	defer func() { Targets = previous }()
	for _, bad := range []string{"missing", "peer", "epoch", "expired", "future", "server-key", "substitute-server-key"} {
		t.Run(bad, func(t *testing.T) {
			source, capture := externalExecutionPacketFixture(t, "wireguard", "server", "")
			request, engine := externalExecutionCapturedRequest(t, source, capture, "")
			engine.mu.Lock()
			engine.badPacketChallenge = bad
			engine.mu.Unlock()
			if result, err := request.Run(); err == nil || result != "" || request.Healthy() {
				t.Fatal("unproved server peer/challenge reported connected")
			}
			if len(engine.runner.processes) != 0 {
				t.Fatal("invalid packet challenge started a relay")
			}
		})
	}
}

func TestExternalPacketExecutionRestoresProvedChoiceWithoutComparingAgain(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public"}
	defer func() { Targets = previous }()
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, winner := range []string{"local", "server"} {
			t.Run(protocol+"/"+winner, func(t *testing.T) {
				source, capture := externalExecutionPacketFixture(t, protocol, "auto", "aes-256-gcm+xor-whitening")
				request, engine := externalExecutionCapturedRequest(t, source, capture, winner)
				if _, err := request.Run(); err != nil {
					t.Fatal(err)
				}
				if request.Execution() != winner || len(engine.nodeCalls) != 1 || request.policy.capture.Profile["multihop_execution"] != "auto" {
					t.Fatal("packet restoration replaced saved Compare or ran other candidate")
				}
			})
		}
	}
}

func TestExternalPacketAliasCannotRoamCompleteMAXBaseOwner(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		t.Run(mode, func(t *testing.T) {
			maxExit, _ := pairedMAXFixture(t, mode, "")
			source, capture := externalExecutionPacketFixture(t, "wireguard", "server", "")
			prepared, err := PrepareExternalExecutionCapture(source, capture, "")
			if err != nil {
				t.Fatal(err)
			}
			policy, err := NewExternalPolicy(source, prepared)
			if err != nil {
				t.Fatal(err)
			}
			client, err := externalRelaySelection(policy.capture)
			if err != nil {
				t.Fatal(err)
			}
			ext := policy.capture.Profile["external"].(map[string]any)
			server, err := multihoprelay.PairExternalPacket(client.ID, "wireguard", ext, externalPacketServerProfile(t, "wireguard", ext), nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := base64.StdEncoding.DecodeString(server.Transport["private_key"].(string))
			raw[0] ^= 7
			raw[31] ^= 192
			maxExit.Transport["endpoint"].(map[string]any)["private_key"] = base64.StdEncoding.EncodeToString(raw)
			for _, packetFirst := range []bool{false, true} {
				runner := &maxRelayRunner{}
				cfg := maxRelayConfiguration(maxExit)
				cfg.Exits = append(cfg.Exits, server)
				m, err := multihoprelay.New(cfg, strings.Repeat("a", 64), runner)
				if err != nil {
					t.Fatal(err)
				}
				first, second := netip.MustParseAddr("10.99.0.2"), netip.MustParseAddr("10.99.0.3")
				packetPeer := second
				if packetFirst {
					packetPeer = first
				}
				q := policy.capture.Execution.Request
				q.EntryNodeID = strings.Repeat("a", 64)
				q, err = multihoprelay.AuthenticateExternalRequest(client, q)
				if err != nil {
					t.Fatal(err)
				}
				challenge, _ := m.PacketChallenge(packetPeer)
				q, err = multihoprelay.ChallengeExternalPacketRequest(client, q, challenge)
				if err != nil {
					t.Fatal(err)
				}
				firstQ, secondQ := maxRelayRequest(maxExit), q
				if packetFirst {
					firstQ, secondQ = secondQ, firstQ
				}
				if _, err := m.Create(context.Background(), first, firstQ); err != nil {
					t.Fatal(err)
				}
				if _, err := m.Create(context.Background(), second, secondQ); err == nil || len(runner.configs) != 1 {
					t.Fatal("complete MAX and external packet label split the same roaming identity")
				}
				if m.Close(context.Background()) != nil {
					t.Fatal("MAX packet owner cleanup")
				}
			}
		})
	}
}

func TestCompleteMAXIndependentWGKeysCannotReuseAnActivePQIdentity(t *testing.T) {
	first, _ := pairedMAXFixture(t, "max-quic-wg", "")
	encoded, _ := json.Marshal(first)
	var second multihoprelay.Exit
	_ = json.Unmarshal(encoded, &second)
	second.ID = "other-max"
	second.Transport["endpoint"].(map[string]any)["private_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
	cfg := maxRelayConfiguration(first)
	cfg.Exits = append(cfg.Exits, second)
	runner := &maxRelayRunner{}
	m, err := multihoprelay.New(cfg, strings.Repeat("a", 64), runner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), netip.MustParseAddr("10.99.0.2"), maxRelayRequest(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background(), netip.MustParseAddr("10.99.0.3"), maxRelayRequest(second)); err == nil || len(runner.configs) != 1 {
		t.Fatal("independent WG key hid reused active MAX PQ credential")
	}
	if m.Close(context.Background()) != nil {
		t.Fatal("MAX PQ ownership cleanup")
	}
}

func TestExternalPacketCaptureRejectsSubstitutedPublicServerProvision(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		source, capture := externalExecutionPacketFixture(t, protocol, "auto", "")
		prepared, err := PrepareExternalExecutionCapture(source, capture, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(map[string]any){
			func(p map[string]any) {
				p["public_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32)))
			},
			func(p map[string]any) { p["addresses"] = []string{"10.94.0.9/32", "fd94::9/128"} },
			func(p map[string]any) { p["mtu"] = float64(1400) }, func(p map[string]any) { p["persistent_keepalive_interval"] = float64(20) },
			func(p map[string]any) { p["private_key"] = "forbidden-server-secret" },
		} {
			changed := externalTestRead(t, prepared)
			peer := changed["profile"].(map[string]any)["external"].(map[string]any)["server_peer"].(map[string]any)
			mutate(peer)
			if _, err := NewExternalPolicy(source, externalTestJSON(t, changed)); err == nil {
				t.Fatal("prepared graph adopted a substituted server peer")
			}
		}
	}
}
