package mobilemultihop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/nativecomposite"
)

// Reuse the shipping paired packet/SS fixture and actual SS service declaration.
// No independent proxy, paired identity or UDP receiver is invented by a label.
func nodeChainCONNECTFixture(t *testing.T, mode, protocol, layer, method, authentication string) NodeChainSource {
	t.Helper()
	nodes := nodeChainModeFixtureNodes(t, []string{mode, "wg", "shadowsocks"}, []string{"", "", layer})
	identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg"}, []string{"", "", ""})
	final := nodes[2]
	var assets map[string]string
	if err := exactJSON([]byte(final.inputs.Files), &assets, 16<<20); err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.Strict().DecodeString(assets["sing-box.json"])
	if err != nil {
		t.Fatal(err)
	}
	graph := externalTestRead(t, string(data))
	out := graph["outbounds"].([]any)[0].(map[string]any)
	keySize := 32
	if method == "2022-blake3-aes-128-gcm" {
		keySize = 16
	}
	out["method"], out["password"] = method, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", keySize)))
	data = []byte(startJSON(t, graph))
	assets["sing-box.json"] = base64.StdEncoding.EncodeToString(data)
	sourceHash, keyHash := sha256.Sum256(data), sha256.Sum256([]byte(out["password"].(string)))
	claim := map[string]any{
		"schema": 1, "node_id": final.profile["node_proof_id"],
		"configured_image": nativecomposite.SSServiceImage, "uot_version": 2,
		"endpoint": out["server"], "port": out["server_port"], "method": out["method"],
		"source_sha256": hex.EncodeToString(sourceHash[:]), "key_sha256": hex.EncodeToString(keyHash[:]),
	}
	assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, claim)))
	nodes[2], err = NewNodeProfile("shadowsocks", startJSON(t, assets), final.inputs.ProfileJSON, final.inputs.Start, final.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal("captured paired SS service", err)
	}
	middleGraph, capture := externalTestFixture(t, protocol, "")
	profile := capture["profile"].(map[string]any)
	profile["dns_mode"], profile["kill_switch_policy"] = "home", "always"
	profile["ipv6_mode"], profile["home_lan_access"] = "off", false
	if authentication == "none" {
		transport := externalTestFind(t, middleGraph, ExternalFinalTag)
		delete(transport, "username")
		delete(transport, "password")
		source := profile["external"].(map[string]any)[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)
		delete(source, "username")
		delete(source, "password")
	}
	member, err := NodeChainImportedCONNECTMemberInput(startJSON(t, middleGraph), startJSON(t, capture))
	if err != nil {
		t.Fatal("original CONNECT member", err)
	}
	source := nodeChainFixtureSource(t, nodes)
	source.Schema, source.Nodes[1] = 4, member
	source.IdentitySources = []string{identities[0].inputs.Files, "", identities[2].inputs.Files}
	if mode == "wg" {
		source.IdentitySources[0] = nodes[0].inputs.Files
	}
	return source
}

func nodeChainCONNECTRecord(t *testing.T, input string) (nodeChainImportedInput, map[string]any, map[string]any) {
	t.Helper()
	var record nodeChainImportedInput
	if err := json.Unmarshal([]byte(input), &record); err != nil {
		t.Fatal(err)
	}
	return record, externalTestRead(t, record.Config), externalTestRead(t, record.Capture)
}

func TestNodeChainCONNECTSourcePreservesSOCKSIntegrity(t *testing.T) {
	for _, phase := range []string{"retained", "construction"} {
		t.Run(phase, func(t *testing.T) {
			source := socksIntegrityFixture(t)
			source.pair.connectSource = &NodeChainCONNECTSource{}
			if phase == "construction" {
				source.integrity = nil
				if source.retainIntegrity() == nil {
					t.Fatal("CONNECT owner entered an ordinary SOCKS pair integrity capture")
				}
			} else if config, _, err := source.ReadValidated(); err == nil || config != "" {
				t.Fatal("CONNECT owner entered a retained ordinary SOCKS pair")
			}
		})
	}
}

func nodeChainCONNECTRewriteFinal(t *testing.T, source *NodeChainSource, change func(map[string]string, map[string]any)) error {
	t.Helper()
	final, err := ParseNodeLaunchInput(source.Nodes[2])
	if err != nil {
		t.Fatal(err)
	}
	var assets map[string]string
	if err := json.Unmarshal([]byte(final.inputs.Files), &assets); err != nil {
		t.Fatal(err)
	}
	profile := externalTestRead(t, final.inputs.ProfileJSON)
	change(assets, profile)
	replaced, err := NewNodeProfile(final.mode, startJSON(t, assets), startJSON(t, profile), final.inputs.Start, final.inputs.DNSBootstrap)
	if err != nil {
		return err
	}
	source.Nodes[2], err = replaced.LaunchInput()
	return err
}

func TestNodeChainCONNECTSourceKeepsOriginalGraph(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
				t.Run(mode+"/"+protocol+"/"+method, func(t *testing.T) {
					source := nodeChainCONNECTFixture(t, mode, protocol, "", method, "password")
					original := startJSON(t, source)
					plan, err := NewNodeChainCONNECTSource(original)
					if err != nil {
						t.Fatal(err)
					}
					config, meta, err := plan.ReadValidated()
					if err != nil || meta.Kind != "routervpn-node-chain-connect-source" || meta.Schema != 1 ||
						meta.NativeAdmission != "closed" || meta.TransportCapability != "uot-v2" || len(meta.Proofs) != 3 {
						t.Fatal("CONNECT source acquired runtime authority or lost original inventory", err)
					}
					captured, err := plan.Source()
					if err != nil || captured != original || plan.middle.input != source.Nodes[1] {
						t.Fatal("original private source changed", err)
					}
					record, originalGraph, originalCapture := nodeChainCONNECTRecord(t, source.Nodes[1])
					graph := externalTestRead(t, config)
					middle := externalTestFind(t, graph, meta.Proofs[1].Tag)
					want := predecessorCopy(externalTestFind(t, originalGraph, ExternalFinalTag))
					want["tag"], want["detour"] = meta.Proofs[1].Tag, meta.Proofs[0].Tag
					if !reflect.DeepEqual(middle, want) || record.Capture != startJSON(t, originalCapture) ||
						meta.Proofs[1].Mode != protocol || meta.Proofs[1].NodeKind != "external" ||
						meta.Proofs[1].Kind != "public-path" || meta.Proofs[1].NodeID != "" ||
						meta.Proofs[1].ProfileID != originalCapture["exit_id"] {
						t.Fatal("CONNECT TLS, credentials, exact preceding prefix or public middle proof changed")
					}
					final := externalTestFind(t, graph, meta.Proofs[2].Tag)
					if final["detour"] != meta.Proofs[1].Tag || final["method"] != method || final["network"] != nil ||
						!reflect.DeepEqual(final["udp_over_tcp"], map[string]any{"enabled": true, "version": float64(2)}) {
						t.Fatal("paired final lost independently authorized UoT-v2")
					}
					found := 0
					for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
						dns := raw.(map[string]any)
						if strings.HasPrefix(dns["tag"].(string), "routervpn-chain-1-") {
							t.Fatal("middle standalone DNS became application DNS")
						}
						if dns["tag"] == meta.DNS.ResolverTag {
							found++
							if dns["detour"] != meta.Proofs[2].Tag || dns["server"] != "10.82.0.53" || dns["type"] != "udp" {
								t.Fatal("final Home AdGuard changed or escaped exact paired UoT path")
							}
						}
					}
					physical, err := plan.pair.nodes[0].PhysicalEgress()
					if err != nil || found != 1 || !reflect.DeepEqual(meta.Physical, physical) || len(graph["inbounds"].([]any)) != 1 ||
						len(graph["endpoints"].([]any)) != 1 || meta.DNS.SourceSHA256 != meta.SourceSHA256 ||
						meta.DNS.ConfigSHA256 != meta.ConfigSHA256 || meta.ConfigSHA256 != externalDigest([]byte(config)) {
						t.Fatal("CONNECT graph introduced physical authority or lost source/DNS identity", err)
					}
					if meta.MTU.Original != 1280 || meta.MTU.Ceiling < 1280 || len(meta.MTU.Prefixes) != 3 ||
						len(meta.Devices) != 3 || meta.Devices[1].KillSwitchPolicy != "always" ||
						meta.Devices[1].IPv6Mode != "off" || meta.Devices[1].HomeLANAccess {
						t.Fatal("configured bounds or original device restrictions changed", meta)
					}
					reopened, err := NewNodeChainCONNECTSource(captured)
					if err != nil {
						t.Fatal(err)
					}
					again, receipt, err := reopened.ReadValidated()
					if err != nil || again != config || !reflect.DeepEqual(receipt, meta) || original != startJSON(t, source) {
						t.Fatal("CONNECT source recompile changed original input or output", err)
					}
					// The ordinary physical walker must still refuse UDP directly
					// through HTTP. The final's UoT is not middle UDP authority.
					graph["route"].(map[string]any)["final"] = meta.Proofs[1].Tag
					if _, err := compiledPhysicalEgressWithDesktopProof(startJSON(t, graph), []string{"udp"}, nil, meta.Proofs[1].Tag); err == nil {
						t.Fatal("CONNECT middle acquired generic UDP physical authority")
					}
				})
			}
		}
	}
}

func TestNodeChainCONNECTSourceRetainsSupportedLayersAndOptionalAuthentication(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(protocol+"/"+map[string]string{"": "off", "aes-256-gcm": "aes", "aes-256-gcm+xor-whitening": "aes-xor"}[layer], func(t *testing.T) {
				source := nodeChainCONNECTFixture(t, "awg2-strong", protocol, layer, NativeStartLayerMethod, "none")
				plan, err := NewNodeChainCONNECTSource(startJSON(t, source))
				if err != nil {
					t.Fatal("existing paired UoT layer was gratuitously narrowed", err)
				}
				config, meta, err := plan.ReadValidated()
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, config)
				middle := externalTestFind(t, graph, meta.Proofs[1].Tag)
				if middle["username"] != nil || middle["password"] != nil ||
					meta.Proofs[2].StartLayer != map[string]string{"": "off", "aes-256-gcm": "aes-256-gcm", "aes-256-gcm+xor-whitening": "aes-256-gcm+xor-whitening"}[layer] {
					t.Fatal("optional authentication or original final layer changed")
				}
				final := externalTestFind(t, graph, meta.Proofs[2].Tag)
				if !reflect.DeepEqual(final["udp_over_tcp"], map[string]any{"enabled": true, "version": float64(2)}) {
					t.Fatal("layer discarded UoT authority")
				}
			})
		}
	}
}

func TestNodeChainCONNECTSourceRejectsWrongMemberOrPath(t *testing.T) {
	for _, fault := range []string{"schema1", "schema2", "schema3", "server", "auto", "missing-node", "extra-node", "missing-first-identity", "foreign-middle-identity", "duplicate-final",
		"member-kind", "protocol-alias", "changed-server", "changed-credential", "changed-tls", "hostname", "injected-udp", "member-layer", "paired-middle", "extra-entry", "extra-execution"} {
		t.Run(fault, func(t *testing.T) {
			source := nodeChainCONNECTFixture(t, "wg", "https-connect", "", NativeStartLayerMethod, "password")
			record, graph, capture := nodeChainCONNECTRecord(t, source.Nodes[1])
			out := externalTestFind(t, graph, ExternalFinalTag)
			profile := capture["profile"].(map[string]any)
			switch fault {
			case "schema1":
				source.Schema = 1
			case "schema2":
				source.Schema = 2
			case "schema3":
				source.Schema = 3
			case "server", "auto":
				source.Execution = fault
			case "missing-node":
				source.Nodes = source.Nodes[:2]
			case "extra-node":
				source.Nodes = append(source.Nodes, source.Nodes[2])
			case "missing-first-identity":
				source.IdentitySources[0] = ""
			case "foreign-middle-identity":
				source.IdentitySources[1] = source.IdentitySources[0]
			case "duplicate-final":
				source.Nodes[2], source.IdentitySources[2] = source.Nodes[0], source.IdentitySources[0]
			case "member-kind":
				record.Kind = "routervpn-node-chain-socks-member"
			case "protocol-alias":
				capture["protocol"] = "https"
			case "changed-server":
				out["server"] = "203.0.113.199"
			case "changed-credential":
				out["password"] = "not-the-original"
			case "changed-tls":
				out["tls"].(map[string]any)["server_name"] = "not-original.example"
			case "hostname":
				out["server"] = "middle.example.test"
				profile["external"].(map[string]any)["https_connect"].(map[string]any)["host"] = out["server"]
			case "injected-udp":
				out["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
			case "member-layer":
				profile["start_layer"] = "aes-256-gcm"
			case "paired-middle":
				profile["node_proof_id"] = strings.Repeat("a", 64)
			case "extra-entry":
				capture["entry"] = map[string]any{"id": "unowned"}
			case "extra-execution":
				capture["execution"] = map[string]any{"mode": "local"}
			}
			if len(source.Nodes) > 1 {
				record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
				source.Nodes[1] = startJSON(t, record)
			}
			if plan, err := NewNodeChainCONNECTSource(startJSON(t, source)); err == nil || plan != nil {
				t.Fatal("changed CONNECT source acquired a compiled path")
			}
		})
	}
}

func TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS(t *testing.T) {
	for _, fault := range []string{"missing", "foreign-node", "wrong-key", "wrong-port", "wrong-image", "wrong-version", "stale-source", "inline-uot", "dns-substitution"} {
		t.Run(fault, func(t *testing.T) {
			source := nodeChainCONNECTFixture(t, "wg", "https-connect", "", NativeStartLayerMethod, "password")
			err := nodeChainCONNECTRewriteFinal(t, &source, func(assets map[string]string, profile map[string]any) {
				raw, _ := base64.StdEncoding.Strict().DecodeString(assets[nativecomposite.SSServiceAsset])
				claim := externalTestRead(t, string(raw))
				switch fault {
				case "missing":
					delete(assets, nativecomposite.SSServiceAsset)
					return
				case "foreign-node":
					claim["node_id"] = strings.Repeat("f", 64)
				case "wrong-key":
					claim["key_sha256"] = strings.Repeat("f", 64)
				case "wrong-port":
					claim["port"] = float64(12345)
				case "wrong-image":
					claim["configured_image"] = "foreign-service"
				case "wrong-version":
					claim["uot_version"] = float64(1)
				case "stale-source":
					claim["source_sha256"] = strings.Repeat("f", 64)
				case "dns-substitution":
					profile["dns_host"] = "203.0.113.53"
				case "inline-uot":
					data, _ := base64.StdEncoding.Strict().DecodeString(assets["sing-box.json"])
					graph := externalTestRead(t, string(data))
					graph["outbounds"].([]any)[0].(map[string]any)["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
					assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
				}
				assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, claim)))
			})
			if err != nil {
				return
			} // Original paired constructor may reject first.
			if plan, err := NewNodeChainCONNECTSource(startJSON(t, source)); err == nil || plan != nil {
				t.Fatal("missing or foreign paired UoT/DNS authority acquired CONNECT source")
			}
		})
	}
}

func nodeChainCONNECTClosureFixture(t *testing.T) ([]nodeChainGraphMember, []*externalPredecessor, []PhysicalEgress, *nodeChainCONNECTProofScope) {
	t.Helper()
	source := nodeChainCONNECTFixture(t, "wg", "https-connect", "", NativeStartLayerMethod, "password")
	middle, err := parseNodeChainCONNECTMember(source.Nodes[1])
	if err != nil {
		t.Fatal(err)
	}
	pair, err := NewNodeChain(startJSON(t, NodeChainSource{Schema: 1, Execution: "local", Nodes: []string{source.Nodes[0], source.Nodes[2]}, IdentitySources: []string{source.IdentitySources[0], source.IdentitySources[2]}}))
	if err != nil {
		t.Fatal(err)
	}
	first, err := nodeMultihopPredecessor(pair.nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	custom, err := middle.closure()
	if err != nil {
		t.Fatal(err)
	}
	final, err := nodeMultihopPredecessor(pair.nodes[1])
	if err != nil {
		t.Fatal(err)
	}
	closures := []*externalPredecessor{first, custom, final}
	members := []nodeChainGraphMember{
		{profile: pair.nodes[0].profile, source: pair.nodes[0].source, mode: pair.nodes[0].mode},
		{profile: middle.selection.Profile, source: middle.source, mode: middle.selection.Protocol, imported: true},
		{profile: pair.nodes[1].profile, source: pair.nodes[1].source, mode: pair.nodes[1].mode},
	}
	physical, err := pair.nodes[0].PhysicalEgress()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := newNodeChainCONNECTProofScope(pair, middle, closures)
	if err != nil {
		t.Fatal(err)
	}
	return members, closures, physical, scope
}

func TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact(t *testing.T) {
	for _, fault := range []string{"missing-scope", "wrong-position", "wrong-mode", "ordinary-member", "changed-member-source", "foreign-closure", "missing-final-uot", "changed-final-dns", "wrong-physical"} {
		t.Run(fault, func(t *testing.T) {
			members, closures, physical, scope := nodeChainCONNECTClosureFixture(t)
			switch fault {
			case "missing-scope":
				scope = nil
			case "wrong-position":
				members[0], members[1] = members[1], members[0]
			case "wrong-mode":
				members[1].mode = "socks5"
			case "ordinary-member":
				members[1].imported = false
			case "changed-member-source":
				members[1].source = strings.Repeat("a", 64)
			case "foreign-closure":
				copy := *closures[1]
				closures[1] = &copy
			case "missing-final-uot":
				delete(closures[2].final, "udp_over_tcp")
			case "changed-final-dns":
				closures[2].graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["server"] = "203.0.113.53"
			case "wrong-physical":
				physical[0].Host = "203.0.113.222"
			}
			if _, _, _, _, err := compileNodeChainClosuresWithCONNECT(members, closures, physical, scope); err == nil {
				t.Fatal("invalid CONNECT construction receipt acquired physical authority")
			}
		})
	}
}

func TestNodeChainCONNECTSourceDoesNotBroadenGenericAuthority(t *testing.T) {
	source := nodeChainCONNECTFixture(t, "wg", "http-connect", "", NativeStartLayerMethod, "password")
	raw := startJSON(t, source)
	plan, err := NewNodeChainCONNECTSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	if generic, err := NewNodeChain(raw); err == nil || generic != nil {
		t.Fatal("generic chain accepted CONNECT schema4")
	}
	if other, err := NewNodeChainSOCKSSource(raw); err == nil || other != nil {
		t.Fatal("SOCKS schema accepted CONNECT authority")
	}
	_, _, capture := nodeChainCONNECTRecord(t, source.Nodes[1])
	if capture["execution"] != nil {
		t.Fatal("fixture acquired remote execution authority")
	}
	config, meta, err := plan.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	// Accessors must not permit changing the private capture by mutation.
	meta.Proofs[1].ProfileID = "foreign"
	meta.Physical[0].Host = "203.0.113.9"
	meta.MTU.Prefixes[0].Ceiling = 9000
	meta.Devices[1].HomeLANAccess = true
	again, original, err := plan.ReadValidated()
	if err != nil || again != config || original.Proofs[1].ProfileID == "foreign" ||
		original.Physical[0].Host == "203.0.113.9" || original.Devices[1].HomeLANAccess {
		t.Fatal("public source receipt mutated private compiler authority")
	}
	plan.config += " "
	if _, _, err := plan.ReadValidated(); err == nil {
		t.Fatal("changed private config retained source seal")
	}
}

func TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal(t *testing.T) {
	for _, fault := range []string{"exact-final", "missing-receipt", "foreign-scope", "copied-receipt", "foreign-final-owner",
		"changed-config", "changed-receipt-config", "changed-final", "changed-receipt-final", "changed-paired-source",
		"inline-only", "direct-http-udp", "wrong-version", "unrelated-tag"} {
		t.Run(fault, func(t *testing.T) {
			members, closures, physical, scope := nodeChainCONNECTClosureFixture(t)
			config, proofs, _, _, err := compileNodeChainClosuresWithCONNECT(members, closures, physical, scope)
			if err != nil {
				t.Fatal(err)
			}
			graph := externalTestRead(t, config)
			graph["route"].(map[string]any)["final"] = proofs[2].Tag
			projected := startJSON(t, graph)
			capture, err := scope.capturePhysical(projected, proofs)
			if err != nil {
				t.Fatal(err)
			}
			final := externalTestFind(t, graph, proofs[2].Tag)
			if fault == "exact-final" {
				actual, err := scope.physicalEgress(projected, []string{"tcp", "udp"}, proofs[1].Tag, capture)
				if err != nil || !reflect.DeepEqual(actual, physical) {
					t.Fatal("captured UoT final did not preserve original TCP/UDP physical closure", err)
				}
				return
			}
			switch fault {
			case "missing-receipt":
				capture = nil
			case "foreign-scope":
				copy := *scope
				scope = &copy
			case "copied-receipt":
				copy := *capture
				capture = &copy
			case "foreign-final-owner":
				copy := *capture.final
				capture.final = &copy
			case "changed-config", "changed-receipt-config":
				graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["server"] = "203.0.113.53"
				projected = startJSON(t, graph)
				if fault == "changed-receipt-config" {
					capture.config = projected
				}
			case "changed-final":
				final["password"] = "foreign-original-key"
				projected = startJSON(t, graph)
			case "changed-receipt-final":
				capture.finalJSON += " "
			case "changed-paired-source":
				capture.final.inputs.Files += " "
			case "inline-only":
				if _, err := compiledPhysicalEgressWithDesktopProof(projected, []string{"tcp", "udp"}, nil, proofs[1].Tag); err == nil {
					t.Fatal("inline UoT alone acquired generic physical authority")
				}
				return
			case "direct-http-udp":
				p := nodeEgressProjection{
					nodes: map[string]map[string]any{}, resolvers: map[string]map[string]any{},
					active: map[string]bool{}, visited: map[string]bool{}, tuples: map[PhysicalEgress]bool{}, connect: capture,
				}
				for _, family := range []string{"outbounds", "endpoints"} {
					for _, raw := range graph[family].([]any) {
						node := raw.(map[string]any)
						p.nodes[predecessorText(node, "tag")] = node
					}
				}
				if err := p.node(proofs[1].Tag, "udp"); err == nil {
					t.Fatal("typed final receipt authorized HTTP UDP")
				}
				return
			case "wrong-version":
				final["udp_over_tcp"].(map[string]any)["version"] = float64(1)
				if _, err := capture.udpOverTCP(proofs[2].Tag, final); err == nil {
					t.Fatal("typed physical receipt accepted another UoT version")
				}
				return
			case "unrelated-tag":
				if stream, err := capture.udpOverTCP(proofs[1].Tag, externalTestFind(t, graph, proofs[1].Tag)); err != nil || stream {
					t.Fatal("final UoT receipt lent UDP conversion to its middle", err)
				}
				return
			}
			if _, err := scope.physicalEgress(projected, []string{"tcp", "udp"}, proofs[1].Tag, capture); err == nil {
				t.Fatal("changed or foreign UoT receipt acquired physical traversal")
			}
		})
	}
}
