package mobilemultihop

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func nodeChainImportedFixture(t *testing.T, mode, layer string) NodeChainSource {
	t.Helper()
	nodes := nodeChainModeFixtureNodes(t, []string{mode, "wg", "shadowsocks"}, []string{layer, "", layer})
	ids := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg"}, []string{"", "", ""})
	config, capture, _, _ := importedEntryFixture(t, "", "")
	middle, err := NodeChainImportedMemberInput(config, capture)
	if err != nil {
		t.Fatal(err)
	}
	source := nodeChainFixtureSource(t, nodes)
	source.Schema = 2
	source.Nodes[1] = middle
	source.IdentitySources = []string{ids[0].inputs.Files, "", ids[2].inputs.Files}
	if mode == "wg" {
		source.IdentitySources[0] = nodes[0].inputs.Files
	}
	return source
}
func TestNodeChainImportedMiddleSourceAndNativeProjection(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				source := nodeChainImportedFixture(t, mode, layer)
				chain, err := NewNodeChain(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				p := chain.ProofInventory()[1]
				if p.NodeKind != "external" || p.Kind != "public-path" || p.NodeID != "" || chain.nodes[1] != nil || p.ProfileID != "saved-exit" {
					t.Fatal("external middle acquired private authority", p)
				}
				original := externalTestRead(t, chain.importedMiddle.input)
				if original["capture"] == "" || !strings.Contains(original["capture"].(string), `"dns_mode":"home"`) {
					t.Fatal("original standalone source lost")
				}
				graph := externalTestRead(t, chain.Config())
				middle := externalTestFind(t, graph, p.Tag)
				if middle["detour"] != chain.proofs[0].Tag || middle["method"] != NativeStartLayerMethod {
					t.Fatal("middle routing/source changed", middle)
				}
				final := externalTestFind(t, graph, chain.FinalTag())
				if final["detour"] != p.Tag {
					t.Fatal("final bypassed custom middle", final)
				}
				for _, row := range graph["dns"].(map[string]any)["servers"].([]any) {
					dns := row.(map[string]any)
					if strings.Contains(dns["tag"].(string), "routervpn-chain-1-") {
						t.Fatal("standalone middle DNS became application or physical policy")
					}
					if dns["tag"] == chain.DNSCapture().ResolverTag && (dns["detour"] != chain.FinalTag() || dns["server"] != "10.82.0.53") {
						t.Fatal("selected final DNS changed", dns)
					}
				}
				for _, target := range []string{"", "android", "ios", "linux", "darwin", "windows"} {
					derived := chain
					if target != "" {
						derived, err = ProjectNodeChain(chain, target, 1280)
						if err != nil {
							t.Fatal(target, err)
						}
					}
					launch, err := derived.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					reopened, err := ParseNodeChainLaunchInput(launch)
					if err != nil || reopened.Config() != derived.Config() || reopened.Metadata() != derived.Metadata() {
						t.Fatal("source replay failed", target, err)
					}
					var record nodeChainLaunchRecord
					_ = json.Unmarshal([]byte(launch), &record)
					if record.Schema != 2 || !reflect.DeepEqual(record.Nodes, source.Nodes) || !reflect.DeepEqual(record.IdentitySources, source.IdentitySources) {
						t.Fatal("original typed sources changed")
					}
				}
			})
		}
	}
}
func TestNodeChainImportedMiddleRejectsUncapturedAuthority(t *testing.T) {
	source := nodeChainImportedFixture(t, "wg", "")
	for _, fault := range []string{"schema1", "unknown-schema", "two", "four", "missing-identities", "middle-identity", "missing-first-identity", "missing-final-identity", "reorder", "paired-middle", "double-imported", "canonical-middle", "duplicate-middle-key", "fake-api", "fake-proof", "layer", "hostname", "wrong-credential", "legacy-method", "identity-chain", "changed-expected-ip", "extra-route"} {
		t.Run(fault, func(t *testing.T) {
			bad := source
			bad.Nodes = append([]string(nil), source.Nodes...)
			bad.IdentitySources = append([]string(nil), source.IdentitySources...)
			var record nodeChainImportedInput
			_ = json.Unmarshal([]byte(bad.Nodes[1]), &record)
			capture := externalTestRead(t, record.Capture)
			profile := capture["profile"].(map[string]any)
			graph := externalTestRead(t, record.Config)
			out := externalTestFind(t, graph, ExternalFinalTag)
			ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
			switch fault {
			case "schema1":
				bad.Schema = 1
			case "unknown-schema":
				bad.Schema = 3
			case "two":
				bad.Nodes = bad.Nodes[:2]
			case "four":
				bad.Nodes = append(bad.Nodes, bad.Nodes[0])
			case "missing-identities":
				bad.IdentitySources = nil
			case "middle-identity":
				bad.IdentitySources[1] = bad.IdentitySources[0]
			case "missing-first-identity":
				bad.IdentitySources[0] = ""
			case "missing-final-identity":
				bad.IdentitySources[2] = ""
			case "reorder":
				bad.Nodes[0], bad.Nodes[1] = bad.Nodes[1], bad.Nodes[0]
			case "paired-middle":
				bad.Nodes[1] = bad.Nodes[0]
			case "double-imported":
				bad.Nodes[0] = bad.Nodes[1]
			case "canonical-middle":
				bad.Nodes[1] += " "
			case "duplicate-middle-key":
				bad.Nodes[1] = strings.Replace(bad.Nodes[1], `"schema":1`, `"schema":1,"schema":1`, 1)
			default:
				switch fault {
				case "fake-api":
					profile["router_api"] = "http://10.0.0.1:8787"
					profile["api_token"] = "invented"
				case "fake-proof":
					profile["node_proof_id"] = strings.Repeat("a", 64)
				case "layer":
					profile["start_layer"] = "aes-256-gcm"
				case "hostname":
					out["server"] = "middle.invalid"
					ss["server"] = "middle.invalid"
				case "wrong-credential":
					out["password"] = "different"
				case "legacy-method":
					out["method"] = "aes-256-gcm"
					ss["method"] = "aes-256-gcm"
				case "identity-chain":
					out["password"] = out["password"].(string) + ":" + out["password"].(string)
					ss["password"] = out["password"]
				case "changed-expected-ip":
					capture["expected_public_ip"] = "198.51.100.243"
				case "extra-route":
					graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": "escape"})
				}
				record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
				bad.Nodes[1] = startJSON(t, record)
			}
			if _, err := NewNodeChain(startJSON(t, bad)); err == nil {
				t.Fatal("uncaptured custom middle accepted")
			}
		})
	}
}
func TestNodeChainImportedMiddleRequiresPublicProof(t *testing.T) {
	for _, fault := range []string{"", "middle-stopped", "wrong-public-ip", "changed-source"} {
		t.Run(fault, func(t *testing.T) {
			chain, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
			if err != nil {
				t.Fatal(err)
			}
			engine := newNodeChainTestEngine(t, chain)
			switch fault {
			case "middle-stopped":
				engine.dead = 1
			case "wrong-public-ip":
				engine.publicBody = "ip=198.51.100.7\n"
			case "changed-source":
				chain.importedMiddle.selection.Profile["node_kind"] = "router-vpn"
			}
			err = chain.Run(context.Background(), engine)
			if fault != "" {
				if err == nil || chain.Progress().Ready {
					t.Fatal("unproved middle became ready")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			progress := chain.Progress()
			if !progress.Ready || len(progress.Prefixes) != 3 || progress.Prefixes[1].Kind != "public-path" || progress.Prefixes[1].Label == "" {
				t.Fatal("public prefix lost distinction", progress)
			}
			owner := &nodeChainMeasurementFixture{chain: chain}
			service, err := chain.NewHopMeasurementContext(context.Background(), owner)
			if err != nil {
				t.Fatal(err)
			}
			if err = service.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeChainImportedMiddleDesktopPolicyRetainsPhysicalOwner(t *testing.T) {
	source := nodeChainImportedFixture(t, "wg", "")
	var member nodeChainImportedInput
	_ = json.Unmarshal([]byte(source.Nodes[1]), &member)
	capture := externalTestRead(t, member.Capture)
	profile := capture["profile"].(map[string]any)
	profile["kill_switch_policy"], profile["home_lan_access"], profile["ipv6_mode"] = "always", false, "off"
	var err error
	source.Nodes[1], err = NodeChainImportedMemberInput(member.Config, startJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	original, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux", "darwin", "windows"} {
		t.Run(target, func(t *testing.T) {
			policy, err := NewDesktopNodeChainPolicy(original, desktopNodeTestSession, target, 1280)
			if err != nil {
				t.Fatal(err)
			}
			_, meta, physical, err := policy.ReadValidated()
			chain := policy.NodeChain()
			if err != nil {
				t.Fatal(err)
			}
			if meta.KillSwitchPolicy != "always" || meta.HomeLANAccess || meta.IPv6Mode != "off" || physical.SelectedDNS.Detour != chain.FinalTag() || physical.SelectedDNS.Physical {
				t.Fatal("custom policy or final DNS ownership lost")
			}
			for _, root := range physical.PhysicalRoots {
				if !strings.HasPrefix(root.Tag, "routervpn-chain-0-") {
					t.Fatal("middle escaped original physical owner", root)
				}
			}
			launch, err := chain.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := ParseNodeChainLaunchInput(launch)
			if err != nil || reopened.Config() != chain.Config() {
				t.Fatal("physical source replay changed", err)
			}
		})
	}
	original.importedMiddle.selection.Profile["kill_switch_policy"] = "off"
	if _, err := NewDesktopNodeChainPolicy(original, desktopNodeTestSession, "linux", 1280); err == nil {
		t.Fatal("mutated imported protection acquired owner")
	}
}
