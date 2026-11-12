package mobilemultihop

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nodeChainExecutionFixtureSource(t *testing.T, count int, layer, execution string) NodeChainExecutionSource {
	t.Helper()
	modes, layers, identityModes, identityLayers := make([]string, count), make([]string, count), make([]string, count), make([]string, count)
	for i := range modes {
		modes[i], layers[i], identityModes[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3], layer, "wg"
	}
	modes[count-1] = "shadowsocks"
	localNodes := nodeChainModeFixtureNodes(t, modes, layers)
	identities := nodeChainModeFixtureNodes(t, identityModes, identityLayers)
	return nodeChainExecutionFixtureFromNodes(t, localNodes, identities, execution)
}

func nodeChainExecutionFixtureFromNodes(t *testing.T, localNodes, identities []*NodeProfile, execution string) NodeChainExecutionSource {
	t.Helper()
	if len(localNodes) != len(identities) {
		t.Fatal("missing original identity inventory")
	}
	localSource := nodeChainFixtureSource(t, localNodes)
	for _, identity := range identities {
		localSource.IdentitySources = append(localSource.IdentitySources, identity.inputs.Files)
	}
	serverSource := NodeChainServerSource{Schema: 1, EntryID: predecessorText(localNodes[0].profile, "id"), EntryNodeID: predecessorText(localNodes[0].profile, "node_proof_id"), EntryMode: localNodes[0].mode}
	for i, node := range localNodes[1:] {
		position := i + 1
		identity := identities[position].inputs.Files
		serverNode := node
		if NodeChainPrefixMode(node.mode) {
			var assets map[string]string
			if err := json.Unmarshal([]byte(node.inputs.Files), &assets); err != nil {
				t.Fatal(err)
			}
			name := "wg.conf"
			if node.mode != "wg" {
				name = "awg.conf"
			}
			raw := string(mustDecodeChainAsset(t, assets[name]))
			original := importedPQGraph(t, node.config)["endpoints"].([]any)[0].(map[string]any)["private_key"].(string)
			if !strings.Contains(raw, original) {
				t.Fatal("missing original packet client fixture identity")
			}
			raw = strings.Replace(raw, original, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(221 + position)}, 32)), 1)
			assets[name] = base64.StdEncoding.EncodeToString([]byte(raw))
			var err error
			serverNode, err = NewNodeProfile(node.mode, startJSON(t, assets), node.inputs.ProfileJSON, node.inputs.Start, node.inputs.DNSBootstrap)
			if err != nil {
				t.Fatal(err)
			}
			if node.mode == "wg" {
				identity = serverNode.inputs.Files
			}
		}
		launch, err := serverNode.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
		serverSource.Nodes = append(serverSource.Nodes, launch)
		serverSource.IdentitySources = append(serverSource.IdentitySources, identity)
	}
	server, err := NewNodeChainServerPolicy(startJSON(t, serverSource))
	if err != nil {
		t.Fatal(err)
	}
	capture := nodeChainServerCaptureFixture(t, server)
	request := capture.Request.Clone()
	request.LocalPacketPublicKeys = nil
	for _, node := range localNodes[:len(localNodes)-1] {
		key, err := node.PacketClientPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, key)
	}
	request.Peer, request.Port = "10.80.0.2", 32003
	return NodeChainExecutionSource{Schema: 1, Execution: execution, LocalSource: startJSON(t, localSource), Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
}

func TestNodeChainExecutionCompilesOriginalEntryWithPositionalUoTServer(t *testing.T) {
	for _, test := range []struct {
		count int
		layer string
	}{{2, ""}, {3, ""}, {4, "aes-256-gcm"}, {4, "aes-256-gcm+xor-whitening"}, {8, ""}} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s/%s", test.count, test.layer, execution), func(t *testing.T) {
				source := nodeChainExecutionFixtureSource(t, test.count, test.layer, execution)
				policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				graph, original := importedPQGraph(t, policy.Config()), importedPQGraph(t, policy.local.Config())
				if !reflect.DeepEqual(graph["inbounds"], original["inbounds"]) || !reflect.DeepEqual(graph["endpoints"], original["endpoints"]) || !reflect.DeepEqual(graph["route"], original["route"]) {
					t.Fatal("execution changed original TUN, packet endpoints or device route policy")
				}
				local, _ := policy.ProofInventory("local")
				server, _ := policy.ProofInventory("server")
				if len(local) != test.count || len(server) != test.count || local[0] != server[0] || !reflect.DeepEqual(local, policy.local.ProofInventory()) {
					t.Fatal("entry duplicated or original prefix identities lost")
				}
				all := map[string]map[string]any{}
				for _, value := range graph["outbounds"].([]any) {
					row := value.(map[string]any)
					all[row["tag"].(string)] = row
				}
				selector := all[SelectorTag]
				if !reflect.DeepEqual(selector["outbounds"], []any{local[len(local)-1].Tag, server[len(server)-1].Tag}) || selector["interrupt_exist_connections"] != true {
					t.Fatal("selector gained another route or lost close-on-change")
				}
				want := local[len(local)-1].Tag
				if execution == "server" {
					want = server[len(server)-1].Tag
				}
				if selector["default"] != want {
					t.Fatal("requested execution was silently replaced")
				}
				for i := 1; i < len(server); i++ {
					row, user := all[server[i].Tag], source.Request.Users[i-1]
					if row["type"] != "socks" || row["version"] != "5" || row["server"] != "10.80.0.1" || row["server_port"] != float64(32003) || row["username"] != user.Username || row["password"] != user.Password || row["detour"] != local[0].Tag {
						t.Fatal("server positional route lost exact original front or entry", i, row)
					}
					if i == len(server)-1 {
						if !reflect.DeepEqual(row["network"], []any{"tcp", "udp"}) || !reflect.DeepEqual(row["udp_over_tcp"], map[string]any{"enabled": true, "version": float64(2)}) {
							t.Fatal("final path is not exact native UoT v2")
						}
					} else if row["network"] != "tcp" || row["udp_over_tcp"] != nil {
						t.Fatal("prefix gained datagram or arbitrary application routing")
					}
					unchanged := server[i]
					unchanged.Tag = local[i].Tag
					if unchanged != local[i] {
						t.Fatal("server route relabeled a different selected node")
					}
				}
				for _, value := range original["outbounds"].([]any) {
					row := value.(map[string]any)
					if row["tag"] != SelectorTag && !reflect.DeepEqual(row, all[row["tag"].(string)]) {
						t.Fatal("server proposal changed a complete local owner")
					}
				}
				for _, candidate := range []string{"local", "server"} {
					dns, err := policy.DNSCapture(candidate)
					if err != nil {
						t.Fatal(err)
					}
					proofs, _ := policy.ProofInventory(candidate)
					if dns.Execution != candidate || dns.SelectedTag != proofs[len(proofs)-1].Tag || dns.SelectorTag != SelectorTag || dns.DNS.FinalTag != SelectorTag || dns.DNS.SourceSHA256 != policy.SourceSHA256() || dns.DNS.ConfigSHA256 != policy.ConfigSHA256() || dns.DNSPolicySHA256 != source.Server.DNSPolicySHA256 {
						t.Fatal("DNS receipt lost selected path/config authority")
					}
				}
				physical, err := policy.PhysicalEgress()
				wantPhysical, _ := policy.local.PhysicalEgress()
				if err != nil || !reflect.DeepEqual(physical, wantPhysical) {
					t.Fatal("private front or application DNS became physical authority", err)
				}
				if policy.ValidateFront("10.80.0.1", 32003) != nil || policy.ValidateFront("10.80.0.3", 32003) == nil || policy.ValidateFront("10.80.0.1", 32004) == nil {
					t.Fatal("lease host or proposed port could change during adoption")
				}
				launch, err := policy.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				reopened, err := ParseNodeChainExecutionLaunchInput(launch)
				if err != nil || reopened.Config() != policy.Config() || reopened.Source() != policy.Source() {
					t.Fatal("native handoff cannot reproduce original execution graph", err)
				}
			})
		}
	}
}

func TestNodeChainExecutionRejectsChangedOriginalDiscoveryAndPins(t *testing.T) {
	base := nodeChainExecutionFixtureSource(t, 4, "", "auto")
	for name, mutate := range map[string]func(*NodeChainExecutionSource){
		"mode":                  func(s *NodeChainExecutionSource) { s.Execution = "local" },
		"missing-pool":          func(s *NodeChainExecutionSource) { s.FirstPort, s.LastPort = 0, 0 },
		"pool-too-wide":         func(s *NodeChainExecutionSource) { s.LastPort = s.FirstPort + 64 },
		"outside-captured-pool": func(s *NodeChainExecutionSource) { s.Request.Port = 26240 },
		"foreign-peer":          func(s *NodeChainExecutionSource) { s.Request.Peer = "10.80.0.3" },
		"foreign-local-packet-key": func(s *NodeChainExecutionSource) {
			key, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{191}, 32))
			s.Request.LocalPacketPublicKeys[1] = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
		},
		"missing-entry-local-pin": func(s *NodeChainExecutionSource) {
			s.Request.LocalPacketPublicKeys = s.Request.LocalPacketPublicKeys[1:]
		},
		"shared-local-server-client": func(s *NodeChainExecutionSource) {
			s.Server.Members[0].ClientPublicKey = s.Request.LocalPacketPublicKeys[1]
		},
		"foreign-entry-mode":   func(s *NodeChainExecutionSource) { s.Server.EntryMode = "awg2-strong" },
		"foreign-member-id":    func(s *NodeChainExecutionSource) { s.Server.Members[0].ProfileID = "another-profile" },
		"foreign-member-proof": func(s *NodeChainExecutionSource) { s.Server.Members[0].NodeID = strings.Repeat("b", 64) },
		"foreign-member-mode":  func(s *NodeChainExecutionSource) { s.Server.Members[0].Mode = "wg" },
		"foreign-member-layer": func(s *NodeChainExecutionSource) { s.Server.Members[0].StartLayer = "aes-256-gcm" },
		"foreign-server-peer": func(s *NodeChainExecutionSource) {
			key, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{192}, 32))
			s.Server.Members[0].ServerPublicKey = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
		},
		"foreign-selected-dns": func(s *NodeChainExecutionSource) {
			s.Server.DNSPolicySHA256 = strings.Repeat("b", 64)
			s.Request.DNSPolicySHA256 = s.Server.DNSPolicySHA256
		},
		"missing-original-identity": func(s *NodeChainExecutionSource) {
			var local NodeChainSource
			_ = json.Unmarshal([]byte(s.LocalSource), &local)
			local.IdentitySources = nil
			s.LocalSource = startJSON(t, local)
		},
		"source-over-bound": func(s *NodeChainExecutionSource) { s.LocalSource = strings.Repeat(" ", NodeChainInputLimit) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.Server = base.Server.Clone()
			changed.Request = base.Request.Clone()
			mutate(&changed)
			// Rebind structurally valid changed descriptors so this checks the
			// original client source, not merely a stale public descriptor hash.
			if digest, err := changed.Server.Digest(); err == nil {
				changed.Request.DescriptorSHA256 = digest
			}
			if _, err := NewNodeChainExecutionPolicy(startJSON(t, changed)); err == nil {
				t.Fatal("changed original execution authority passed", name)
			}
		})
	}
}

func TestNodeChainExecutionCaptureCannotAliasOrRebindNativeSource(t *testing.T) {
	policy, err := NewNodeChainExecutionPolicy(startJSON(t, nodeChainExecutionFixtureSource(t, 4, "", "auto")))
	if err != nil {
		t.Fatal(err)
	}
	request := policy.Request()
	request.Users[0].Password = "changed"
	descriptor := policy.Descriptor()
	descriptor.Members[0].ProfileID = "changed"
	front := policy.Front()
	front.Users[0].Username = "changed"
	proofs, _ := policy.ProofInventory("server")
	proofs[1].Tag = "changed"
	physical, _ := policy.PhysicalEgress()
	physical[0].Host = "changed"
	if policy.validateCapture() != nil || policy.source.Request.Users[0].Password == "changed" || policy.source.Server.Members[0].ProfileID == "changed" || policy.front.Users[0].Username == "changed" || policy.serverProofs[1].Tag == "changed" || policy.physical[0].Host == "changed" {
		t.Fatal("returned capture aliases original private owner")
	}
	if _, err := policy.ProofInventory("auto"); err == nil {
		t.Fatal("comparison label substituted an observed selected path")
	}
	launch, err := policy.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{launch + " ", strings.Replace(launch, policy.sourceSHA, strings.Repeat("a", 64), 1), strings.Replace(launch, `"kind":"native-node-chain-execution"`, `"kind":"native-node-chain"`, 1)} {
		if _, err := ParseNodeChainExecutionLaunchInput(changed); err == nil {
			t.Fatal("mutated native handoff passed canonical original reconstruction")
		}
	}
	for name, mutate := range map[string]func(*NodeChainExecutionPolicy){"graph": func(p *NodeChainExecutionPolicy) { p.config += " " }, "request": func(p *NodeChainExecutionPolicy) { p.source.Request.Users[0].Password = "changed" }, "dns": func(p *NodeChainExecutionPolicy) { p.dns.ResolverTag = "changed" }, "prefix": func(p *NodeChainExecutionPolicy) { p.serverProofs[1].Tag = "changed" }, "original-node": func(p *NodeChainExecutionPolicy) { p.local.nodes[0].profile["api_token"] = "changed" }} {
		t.Run(name, func(t *testing.T) {
			p, err := NewNodeChainExecutionPolicy(policy.Source())
			if err != nil {
				t.Fatal(err)
			}
			mutate(p)
			if _, err := p.LaunchInput(); err == nil {
				t.Fatal("mutated owner was published")
			}
		})
	}
}

func TestNodeChainExecutionSelectedDNSAndBootstrapFollowExactWinner(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
		for _, hostname := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/hostname=%v", protocol, hostname), func(t *testing.T) {
				nodes := nodeChainModeFixtureNodes(t, []string{"awg2-fast", "awg2-strong", "shadowsocks"}, []string{"aes-256-gcm", "", ""})
				identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg"}, []string{"", "", ""})
				last := nodes[len(nodes)-1]
				profile := predecessorCopy(last.profile)
				profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", protocol, "9.9.9.9", float64(5443)
				profile["dns_server_name"], profile["dns_path"] = "captured-query.example", "/original-query"
				bootstrap := ""
				if hostname {
					profile["dns_host"] = "captured-query.example"
					bootstrap = startJSON(t, map[string]any{"server": map[string]any{"type": "h3", "tag": "external-dns-bootstrap", "server": "1.1.1.1", "server_port": 5553, "detour": "proxy", "tls": map[string]any{"enabled": true, "server_name": "original-bootstrap.example"}, "path": "/original-bootstrap"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "disable_cache": true}})
				}
				var err error
				nodes[len(nodes)-1], err = NewNodeProfile(last.mode, last.inputs.Files, startJSON(t, profile), last.inputs.Start, bootstrap)
				if err != nil {
					t.Fatal(err)
				}
				// The original middle restriction must stay on the original TUN
				// even when a Server candidate uses a private proof exception.
				middle := nodes[1]
				restricted := predecessorCopy(middle.profile)
				restricted["ipv6_mode"], restricted["home_lan_access"], restricted["home_lan_cidrs"] = "off", false, []string{"10.12.0.0/16"}
				nodes[1], err = NewNodeProfile(middle.mode, middle.inputs.Files, startJSON(t, restricted), middle.inputs.Start, middle.inputs.DNSBootstrap)
				if err != nil {
					t.Fatal(err)
				}
				source := nodeChainExecutionFixtureFromNodes(t, nodes, identities, "auto")
				policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				graph, original := importedPQGraph(t, policy.Config()), importedPQGraph(t, policy.local.Config())
				if !reflect.DeepEqual(graph["inbounds"], original["inbounds"]) || !reflect.DeepEqual(graph["route"], original["route"]) {
					t.Fatal("comparison discarded middle IPv6/LAN policy")
				}
				currentDNS := map[string]map[string]any{}
				for _, value := range graph["dns"].(map[string]any)["servers"].([]any) {
					row := value.(map[string]any)
					currentDNS[row["tag"].(string)] = row
				}
				changed := 0
				for _, value := range original["dns"].(map[string]any)["servers"].([]any) {
					row := value.(map[string]any)
					expected := predecessorCopy(row)
					if row["detour"] == policy.local.FinalTag() {
						expected["detour"] = SelectorTag
						changed++
					}
					if !reflect.DeepEqual(expected, currentDNS[row["tag"].(string)]) {
						t.Fatal("selected TLS, path, query or original lower resolver changed")
					}
				}
				wantChanged := 1
				if hostname {
					wantChanged = 2
				}
				if changed != wantChanged {
					t.Fatal("selected bootstrap tree did not share the exact active final route", changed)
				}
				for _, execution := range []string{"local", "server"} {
					capture, err := policy.DNSCapture(execution)
					if err != nil {
						t.Fatal(err)
					}
					row := currentDNS[capture.DNS.ResolverTag]
					encoded, _ := json.Marshal(row)
					if externalDigest(encoded) != capture.DNS.ResolverSHA256 || row["detour"] != SelectorTag || row["type"] != protocol || capture.DNSPolicySHA256 != source.Request.DNSPolicySHA256 {
						t.Fatal("actual resolver did not match its selected native capture")
					}
				}
			})
		}
	}
}

func TestNodeChainExecutionRetainsIndependentAWGAndStandardProofIdentity(t *testing.T) {
	original := nodeChainIdentityFixture(t)
	nodes := make([]*NodeProfile, len(original.Nodes))
	for i, raw := range original.Nodes {
		var err error
		nodes[i], err = ParseNodeLaunchInput(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg", "wg"}, []string{"", "", "", ""})
	source := nodeChainExecutionFixtureFromNodes(t, nodes, identities, "auto")
	policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal("independent selected AWG identities must retain standard WG proof", err)
	}
	server, _ := policy.ProofInventory("server")
	if server[0].NodeID != nodes[0].profile["node_proof_id"] || server[1].NodeID != nodes[1].profile["node_proof_id"] || policy.Front().Host != "10.80.0.1" {
		t.Fatal("selected AWG transport replaced durable original identity")
	}
}
