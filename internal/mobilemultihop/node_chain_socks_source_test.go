package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func nodeChainSOCKSFixture(t *testing.T, mode, layer, authentication string) NodeChainSource {
	t.Helper()
	nodes := nodeChainModeFixtureNodes(t, []string{mode, "wg", "shadowsocks"}, []string{layer, "", layer})
	identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg"}, []string{"", "", ""})
	graph, capture := externalTestFixture(t, "socks5", "")
	profile := capture["profile"].(map[string]any)
	profile["dns_mode"], profile["kill_switch_policy"] = "home", "always"
	profile["ipv6_mode"], profile["home_lan_access"] = "off", false
	out := externalTestFind(t, graph, ExternalFinalTag)
	socks := profile["external"].(map[string]any)["socks5"].(map[string]any)
	if authentication == "none" {
		delete(out, "username")
		delete(out, "password")
		delete(socks, "username")
		delete(socks, "password")
	}
	member, err := NodeChainImportedSOCKSMemberInput(startJSON(t, graph), startJSON(t, capture))
	if err != nil {
		t.Fatal("original SOCKS source capture", err)
	}
	source := nodeChainFixtureSource(t, nodes)
	source.Schema, source.Nodes[1] = 3, member
	source.IdentitySources = []string{identities[0].inputs.Files, "", identities[2].inputs.Files}
	if mode == "wg" {
		source.IdentitySources[0] = nodes[0].inputs.Files
	}
	return source
}

func nodeChainSOCKSRecord(t *testing.T, input string) (nodeChainImportedInput, map[string]any, map[string]any) {
	t.Helper()
	var record nodeChainImportedInput
	if err := json.Unmarshal([]byte(input), &record); err != nil {
		t.Fatal(err)
	}
	return record, externalTestRead(t, record.Config), externalTestRead(t, record.Capture)
}

func TestNodeChainSOCKSSourceCompilerKeepsOriginalPath(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, authentication := range []string{"password", "none"} {
			t.Run(mode+"/"+authentication, func(t *testing.T) {
				source := nodeChainSOCKSFixture(t, mode, "", authentication)
				before := startJSON(t, source)
				plan, err := NewNodeChainSOCKSSource(before)
				if err != nil {
					t.Fatal(err)
				}
				config, meta, err := plan.ReadValidated()
				if err != nil || meta.Kind != "routervpn-node-chain-socks-source" ||
					meta.Schema != 1 || meta.NativeAdmission != "closed" || len(meta.Proofs) != 3 {
					t.Fatal("source result acquired native authority or lost its exact inventory", err, meta)
				}
				captured, err := plan.Source()
				if err != nil || captured != before || source.Nodes[1] != plan.middle.input {
					t.Fatal("complete original private source changed", err)
				}
				record, originalGraph, originalCapture := nodeChainSOCKSRecord(t, source.Nodes[1])
				original := externalTestFind(t, originalGraph, ExternalFinalTag)
				graph := externalTestRead(t, config)
				proof := meta.Proofs[1]
				middle := externalTestFind(t, graph, proof.Tag)
				want := predecessorCopy(original)
				want["tag"], want["detour"] = proof.Tag, meta.Proofs[0].Tag
				if !reflect.DeepEqual(middle, want) || proof.Mode != "socks5" ||
					proof.NodeKind != "external" || proof.Kind != "public-path" || proof.NodeID != "" ||
					proof.ProfileID != originalCapture["exit_id"] || proof.StartLayer != "off" {
					t.Fatal("SOCKS credentials, prefix or public proof identity changed")
				}
				if record.Capture != startJSON(t, originalCapture) ||
					originalCapture["profile"].(map[string]any)["dns_mode"] != "home" {
					t.Fatal("private standalone DNS provenance changed")
				}
				final := externalTestFind(t, graph, meta.Proofs[2].Tag)
				if final["detour"] != proof.Tag || meta.DNS.FinalTag != meta.Proofs[2].Tag ||
					meta.DNS.SourceSHA256 != meta.SourceSHA256 || meta.DNS.ConfigSHA256 != meta.ConfigSHA256 ||
					meta.ConfigSHA256 != externalDigest([]byte(config)) {
					t.Fatal("final graph or source receipt bypassed its middle")
				}
				selected := 0
				for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
					dns := raw.(map[string]any)
					if strings.HasPrefix(dns["tag"].(string), "routervpn-chain-1-") {
						t.Fatal("middle standalone DNS became application DNS")
					}
					if dns["tag"] == meta.DNS.ResolverTag {
						selected++
						if dns["detour"] != meta.Proofs[2].Tag || dns["server"] != "10.82.0.53" || dns["type"] != "udp" {
							t.Fatal("final Home AdGuard escaped its complete selected path")
						}
					}
				}
				physical, err := plan.pair.nodes[0].PhysicalEgress()
				if err != nil || selected != 1 || !reflect.DeepEqual(meta.Physical, physical) ||
					len(graph["inbounds"].([]any)) != 1 || len(graph["endpoints"].([]any)) != 1 {
					t.Fatal("source added physical relay authority or lost one original TUN", err)
				}
				if meta.MTU.Original != 1280 || meta.MTU.Ceiling < meta.MTU.Original ||
					len(meta.MTU.Prefixes) != 3 || len(meta.Devices) != 3 ||
					meta.Devices[1].KillSwitchPolicy != "always" || meta.Devices[1].IPv6Mode != "off" ||
					meta.Devices[1].HomeLANAccess {
					t.Fatal("configured bounds or original middle restrictions changed", meta)
				}
				ipv6, lan := false, false
				for _, raw := range graph["route"].(map[string]any)["rules"].([]any) {
					rule := raw.(map[string]any)
					if rule["action"] == "reject" && rule["ip_version"] == float64(6) {
						ipv6 = true
					}
					if rule["action"] == "reject" && rule["ip_cidr"] != nil {
						lan = true
					}
				}
				if !ipv6 || !lan {
					t.Fatal("private source restrictions were recorded but not compiled")
				}
				reopened, err := NewNodeChainSOCKSSource(captured)
				if err != nil {
					t.Fatal(err)
				}
				again, receipt, err := reopened.ReadValidated()
				if err != nil || again != config || !reflect.DeepEqual(receipt, meta) || before != startJSON(t, source) {
					t.Fatal("source compiler is not deterministic or mutated its input", err)
				}
			})
		}
	}
}

func TestNodeChainSOCKSSourcePreservesExistingOuterLayers(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			source := nodeChainSOCKSFixture(t, "awg2-strong", layer, "password")
			plan, err := NewNodeChainSOCKSSource(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			config, meta, err := plan.ReadValidated()
			if err != nil || meta.Proofs[0].StartLayer != layer ||
				meta.Proofs[1].StartLayer != "off" || meta.Proofs[2].StartLayer != layer {
				t.Fatal("independent existing packet/final layers changed", err)
			}
			graph := externalTestRead(t, config)
			middle := externalTestFind(t, graph, meta.Proofs[1].Tag)
			if middle["detour"] != meta.Proofs[0].Tag {
				t.Fatal("SOCKS bypassed its original complete preceding closure")
			}
			physical, err := plan.pair.nodes[0].PhysicalEgress()
			if err != nil || !reflect.DeepEqual(meta.Physical, physical) {
				t.Fatal("retained outer layers changed physical closure", err)
			}
		})
	}
}

func TestNodeChainSOCKSSourceRejectsUncapturedMember(t *testing.T) {
	base := nodeChainSOCKSFixture(t, "wg", "", "password")
	for _, fault := range []string{
		"member-kind", "member-schema", "noncanonical", "duplicate-field", "protocol", "profile-kind",
		"api", "proof-id", "api-token", "entry", "execution", "layer", "hostname", "mapped-ip", "zero-ip",
		"wrong-port", "wrong-user", "wrong-password", "wrong-public-ip", "socks4", "detour", "resolver",
		"udp-over-tcp", "tcp-only", "long-user", "long-password", "half-auth", "extra-outbound", "bad-mtu",
	} {
		t.Run(fault, func(t *testing.T) {
			record, graph, capture := nodeChainSOCKSRecord(t, base.Nodes[1])
			profile := capture["profile"].(map[string]any)
			out := externalTestFind(t, graph, ExternalFinalTag)
			socks := profile["external"].(map[string]any)["socks5"].(map[string]any)
			switch fault {
			case "member-kind":
				record.Kind = "routervpn-node-chain-imported-member"
			case "member-schema":
				record.Schema = 2
			case "protocol":
				capture["protocol"] = "http-connect"
			case "profile-kind":
				profile["node_kind"] = "router-vpn"
			case "api":
				profile["router_api"] = "http://10.0.0.1:8787"
			case "proof-id":
				profile["node_proof_id"] = strings.Repeat("a", 64)
			case "api-token":
				profile["api_token"] = "invented"
			case "entry":
				capture["entry_tag"] = "another-prefix"
				capture["entry"] = predecessorCopy(profile)
			case "execution":
				capture["execution"] = map[string]any{"execution": "server"}
			case "layer":
				profile["start_layer"] = "aes-256-gcm"
			case "hostname":
				out["server"], socks["host"] = "middle.invalid", "middle.invalid"
			case "mapped-ip":
				out["server"], socks["host"] = "::ffff:203.0.113.20", "::ffff:203.0.113.20"
			case "zero-ip":
				out["server"], socks["host"] = "0.0.0.0", "0.0.0.0"
			case "wrong-port":
				out["server_port"] = float64(444)
			case "wrong-user":
				out["username"] = "changed"
			case "wrong-password":
				out["password"] = "changed"
			case "wrong-public-ip":
				capture["expected_public_ip"] = "203.0.113.89"
			case "socks4":
				out["version"] = "4"
			case "detour":
				out["detour"] = "foreign-prefix"
			case "resolver":
				out["domain_resolver"] = "ambient"
			case "udp-over-tcp":
				out["udp_over_tcp"] = false
			case "tcp-only":
				out["network"] = "tcp"
			case "long-user":
				out["username"], socks["username"] = strings.Repeat("u", 256), strings.Repeat("u", 256)
			case "long-password":
				out["password"], socks["password"] = strings.Repeat("é", 128), strings.Repeat("é", 128)
			case "half-auth":
				delete(out, "password")
				delete(socks, "password")
			case "extra-outbound":
				graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": "escape"})
			case "bad-mtu":
				graph["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(9001)
			}
			record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
			input := startJSON(t, record)
			if fault == "noncanonical" {
				input += " "
			} else if fault == "duplicate-field" {
				input = strings.Replace(input, `"schema":1`, `"schema":1,"schema":1`, 1)
			}
			if _, err := parseNodeChainSOCKSMember(input); err == nil {
				t.Fatal("uncaptured SOCKS source was admitted", fault)
			}
		})
	}
}

func TestNodeChainSOCKSSourceRejectsInvalidOrder(t *testing.T) {
	base := nodeChainSOCKSFixture(t, "wg", "", "password")
	for _, fault := range []string{
		"schema1", "schema2", "schema4", "server", "auto", "two", "four", "missing-identities",
		"middle-identity", "first-identity", "final-identity", "reordered", "paired-middle", "double-middle",
		"duplicate-id", "wrong-paired-identity", "hysteria-final",
	} {
		t.Run(fault, func(t *testing.T) {
			source := base
			source.Nodes = append([]string(nil), base.Nodes...)
			source.IdentitySources = append([]string(nil), base.IdentitySources...)
			switch fault {
			case "schema1":
				source.Schema = 1
			case "schema2":
				source.Schema = 2
			case "schema4":
				source.Schema = 4
			case "server", "auto":
				source.Execution = fault
			case "two":
				source.Nodes = source.Nodes[:2]
			case "four":
				source.Nodes = append(source.Nodes, source.Nodes[0])
			case "missing-identities":
				source.IdentitySources = nil
			case "middle-identity":
				source.IdentitySources[1] = source.IdentitySources[0]
			case "first-identity":
				source.IdentitySources[0] = ""
			case "final-identity":
				source.IdentitySources[2] = ""
			case "reordered":
				source.Nodes[0], source.Nodes[1] = source.Nodes[1], source.Nodes[0]
			case "paired-middle":
				source.Nodes[1] = source.Nodes[0]
			case "double-middle":
				source.Nodes[0] = source.Nodes[1]
			case "duplicate-id":
				record, _, capture := nodeChainSOCKSRecord(t, source.Nodes[1])
				capture["exit_id"] = "chain-node-0"
				capture["profile"].(map[string]any)["id"] = "chain-node-0"
				record.Capture = startJSON(t, capture)
				source.Nodes[1] = startJSON(t, record)
			case "wrong-paired-identity":
				source.IdentitySources[2] = source.IdentitySources[0]
			case "hysteria-final":
				_, hysteria := nodeChainHysteriaFixture(t, 3, "wg", "")
				source.Nodes[2] = hysteria.Nodes[2]
			}
			if _, err := NewNodeChainSOCKSSource(startJSON(t, source)); err == nil {
				t.Fatal("unsupported SOCKS composition was admitted", fault)
			}
		})
	}
}

func TestNodeChainSOCKSSourceCannotAcquireNativeAuthority(t *testing.T) {
	source := nodeChainSOCKSFixture(t, "wg", "", "password")
	plan, err := NewNodeChainSOCKSSource(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"LaunchInput", "Run", "Ready", "BindNative", "PhysicalReadValidated", "NewMTUControllerContext"} {
		if _, ok := reflect.TypeOf(plan).MethodByName(name); ok {
			t.Fatal("source-only result exposed native authority", name)
		}
	}
	if _, ok := any(plan).(DesktopPhysicalPolicy); ok {
		t.Fatal("dormant SOCKS source acquired a desktop physical owner")
	}
	for _, schema := range []int{1, 2, 3} {
		changed := source
		changed.Schema = schema
		if _, err := NewNodeChain(startJSON(t, changed)); err == nil {
			t.Fatal("generic chain parser admitted dormant SOCKS source", schema)
		}
	}
	for _, execution := range []string{"local", "server", "auto"} {
		if _, err := NewNodeChainExecutionPreparation(startJSON(t, source), execution); err == nil {
			t.Fatal("source-only result acquired ordinary execution authority", execution)
		}
	}
	if _, err := ParseNodeChainLaunchInput(startJSON(t, source)); err == nil {
		t.Fatal("source-only result acquired launch authority")
	}
	// Socket-free candidate eligibility retains the original member compiler;
	// it does not grant any of the native authorities rejected above.
	if !NodeChainCandidateInputSupported(source.Nodes[1]) {
		t.Fatal("valid typed SOCKS member lost candidate-only eligibility")
	}
	if NodeChainCandidateInputSupported(startJSON(t, source)) ||
		NodeChainCandidateInputSupported(source.Nodes[1]+"\n{}") {
		t.Fatal("candidate eligibility admitted a whole graph or malformed member")
	}
	record, _, _ := nodeChainSOCKSRecord(t, source.Nodes[1])
	if _, err := NodeChainImportedMemberInput(record.Config, record.Capture); err == nil {
		t.Fatal("existing SS-only member constructor broadened")
	}
	original := nodeChainImportedFixture(t, "wg", "")
	if _, err := NewNodeChain(startJSON(t, original)); err != nil {
		t.Fatal("original schema2 SS path no longer compiles", err)
	}
}

func TestNodeChainSOCKSSourceRetainsSealedCapture(t *testing.T) {
	input := startJSON(t, nodeChainSOCKSFixture(t, "wg", "", "password"))
	for _, fault := range []string{"source", "config", "admission", "proof", "dns", "physical", "device", "middle", "paired"} {
		t.Run(fault, func(t *testing.T) {
			plan, err := NewNodeChainSOCKSSource(input)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "source":
				plan.sourceJSON += " "
			case "config":
				plan.config += " "
			case "admission":
				plan.metadata.NativeAdmission = "ready"
			case "proof":
				plan.metadata.Proofs[1].NodeID = strings.Repeat("a", 64)
			case "dns":
				plan.metadata.DNS.FinalTag = plan.metadata.Proofs[1].Tag
			case "physical":
				plan.metadata.Physical[0].Host = "203.0.113.20"
			case "device":
				plan.metadata.Devices[1].HomeLANAccess = true
			case "middle":
				plan.middle.selection.Profile["api_token"] = "changed"
			case "paired":
				plan.pair.nodes[0].profile["api_token"] = "changed"
			}
			if config, _, err := plan.ReadValidated(); err == nil || config != "" {
				t.Fatal("modified source result remained authoritative", fault)
			}
			if source, err := plan.Source(); err == nil || source != "" {
				t.Fatal("modified source leaked stale private capture", fault)
			}
		})
	}
	plan, err := NewNodeChainSOCKSSource(input)
	if err != nil {
		t.Fatal(err)
	}
	_, before, err := plan.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	_, copy, _ := plan.ReadValidated()
	copy.Proofs[1].Mode = "http-connect"
	copy.Physical[0].Host = "203.0.113.20"
	copy.MTU.Prefixes[0].Ceiling = 9000
	copy.Devices[1].HomeLANAccess = true
	_, after, err := plan.ReadValidated()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("returned metadata lent mutation authority", err)
	}
}

func TestNodeChainSOCKSSourceKeepsSelectedDNSAndPrivateImport(t *testing.T) {
	source := nodeChainSOCKSFixture(t, "wg", "", "password")
	node, err := ParseNodeLaunchInput(source.Nodes[2])
	if err != nil {
		t.Fatal(err)
	}
	profile := predecessorCopy(node.profile)
	profile["dns_mode"], profile["dns_protocol"] = "custom", "tcp"
	profile["dns_host"], profile["dns_port"] = "9.9.9.9", 5353
	changed, err := NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	source.Nodes[2], err = changed.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewNodeChainSOCKSSource(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	config, meta, err := plan.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	graph := externalTestRead(t, config)
	found := false
	for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
		dns := raw.(map[string]any)
		if dns["tag"] == meta.DNS.ResolverTag {
			found = dns["type"] == "tcp" && dns["server"] == "9.9.9.9" &&
				dns["server_port"] == float64(5353) && dns["detour"] == meta.Proofs[2].Tag
		}
	}
	if !found {
		t.Fatal("original selected final DNS was replaced by middle or default policy")
	}
	private, err := plan.Source()
	if err != nil || !strings.Contains(private, "selected-password-e") {
		t.Fatal("complete private source lost its original SOCKS credential", err)
	}
	public, err := json.Marshal(meta)
	if err != nil || strings.Contains(string(public), "selected-password-e") ||
		strings.Contains(string(public), "captured-chain-token-") || strings.Contains(string(public), "router_api") {
		t.Fatal("source receipt copied private credentials or pairing authority", err)
	}
}
