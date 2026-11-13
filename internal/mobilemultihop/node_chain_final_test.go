package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func nodeChainHysteriaFixture(t *testing.T, count int, first, prefixLayer string) ([]*NodeProfile, NodeChainSource) {
	t.Helper()
	modes, layers := make([]string, count), make([]string, count)
	for i := range modes {
		modes[i], layers[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3], prefixLayer
	}
	modes[0], modes[count-1], layers[count-1] = first, "hysteria2", ""
	nodes := nodeChainModeFixtureNodes(t, modes, layers)
	return nodes, nodeChainFixtureSource(t, nodes)
}

func TestNodeChainHysteriaFinalPreservesOriginalNativeClosure(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, count := range []int{2, 3, 8} {
			t.Run(fmt.Sprintf("%s/%d", mode, count), func(t *testing.T) {
				nodes, source := nodeChainHysteriaFixture(t, count, mode, "")
				before := startJSON(t, source)
				chain, err := NewNodeChain(before)
				if err != nil {
					t.Fatal(err)
				}
				last := nodes[count-1]
				original, err := nodeMultihopPredecessor(last)
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, chain.Config())
				actual := externalTestFind(t, graph, chain.FinalTag())
				want := predecessorCopy(original.final)
				want["tag"], want["detour"] = chain.FinalTag(), chain.proofs[count-2].Tag
				if !reflect.DeepEqual(actual, want) || actual["type"] != "hysteria2" {
					t.Fatal("ordered final changed original native Hysteria2 credentials, TLS/CA or obfuscation")
				}
				if len(graph["inbounds"].([]any)) != 1 || len(graph["endpoints"].([]any)) != count-1 ||
					len(chain.ProofInventory()) != count || chain.Progress().Ready || chain.HealthyContext(context.Background()) == nil {
					t.Fatal("capture omitted a prefix, added a TUN or invented live proof")
				}
				for i, node := range nodes {
					proof := chain.proofs[i]
					if proof.Mode != node.mode || proof.SourceSHA256 != node.SourceSHA256() ||
						proof.NodeID != node.profile["node_proof_id"] || proof.ProfileID != node.profile["id"] {
						t.Fatal("ordered source/proof identity changed", i)
					}
				}
				physical, err := chain.PhysicalEgress()
				first, firstErr := nodes[0].PhysicalEgress()
				if err != nil || firstErr != nil || !reflect.DeepEqual(physical, first) {
					t.Fatal("Hysteria2 final acquired independent physical egress", err, firstErr)
				}
				var selected map[string]any
				for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
					row := raw.(map[string]any)
					if row["tag"] == chain.DNSCapture().ResolverTag {
						selected = row
					}
				}
				if selected["server"] != last.profile["adguard_ipv4"] || selected["detour"] != chain.FinalTag() || selected["type"] != "udp" {
					t.Fatal("final selected Home AdGuard changed or bypassed the complete prefix")
				}
				if before != startJSON(t, source) || chain.MTUProfile() != startJSON(t, last.profile) {
					t.Fatal("composition replaced original source or final private MTU identity")
				}
				for _, target := range []string{"android", "ios", "linux", "windows", "darwin"} {
					projected, err := ProjectNodeChain(chain, target, 1280)
					if err != nil {
						t.Fatal(target, err)
					}
					launch, err := projected.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					reopened, err := ParseNodeChainLaunchInput(launch)
					if err != nil || reopened.Config() != projected.Config() || reopened.Metadata() != projected.Metadata() ||
						reopened.SourceSHA256() != chain.SourceSHA256() || reopened.Progress().Ready {
						t.Fatal("platform projection lost original source or acquired runtime admission", target, err)
					}
					if _, err := reopened.PlanForMTU(reopened.Config(), 1280); err != nil {
						t.Fatal("complete Hysteria2 path lost configured prefix MTU bounds", target, err)
					}
				}
			})
		}
	}
}

func TestNodeChainHysteriaFinalKeepsExplicitScope(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run("final-layer/"+layer, func(t *testing.T) {
			nodes := nodeChainModeFixtureNodes(t, []string{"wg", "hysteria2"}, []string{"", layer})
			if _, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes))); err == nil {
				t.Fatal("unimplemented Hysteria2 final layer gained ordered authority")
			}
		})
		t.Run("preserved-prefix-layer/"+layer, func(t *testing.T) {
			_, source := nodeChainHysteriaFixture(t, 3, "awg2-strong", layer)
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil || chain.proofs[0].StartLayer != layer || chain.proofs[1].StartLayer != layer || chain.proofs[2].StartLayer != "off" {
				t.Fatal("new final discarded independently captured prefix layers", err)
			}
		})
	}
	nodes, source := nodeChainHysteriaFixture(t, 3, "wg", "")
	identities := nodeChainModeFixtureNodes(t, []string{"wg", "wg", "wg"}, []string{"", "", ""})
	for _, id := range identities {
		source.IdentitySources = append(source.IdentitySources, id.inputs.Files)
	}
	if _, err := NewNodeChain(startJSON(t, source)); err != nil {
		t.Fatal("scope controls require complete valid Local identity capture", err)
	}
	for _, execution := range []string{"server", "auto"} {
		t.Run("discovery/"+execution, func(t *testing.T) {
			if _, err := NewNodeChainExecutionPreparation(startJSON(t, source), execution); err == nil {
				t.Fatal("Local Hysteria2 final gained Server/Compare preparation authority")
			}
		})
	}
	server := nodeChainServerSourceFixture(t, 3, "")
	server.Nodes[len(server.Nodes)-1] = source.Nodes[len(source.Nodes)-1]
	if _, err := NewNodeChainServerPolicy(startJSON(t, server)); err == nil {
		t.Fatal("Local Hysteria2 final gained Server suffix authority")
	}
	imported := nodeChainImportedFixture(t, "wg", "")
	imported.Nodes[2] = source.Nodes[2]
	if _, err := NewNodeChain(startJSON(t, imported)); err == nil {
		t.Fatal("Local paired final broadened imported schema 2 SS-only support")
	}
	if NodeChainCandidateInputSupported(source.Nodes[2]) {
		t.Fatal("UDP-only Hysteria2 source gained a guessed TCP candidate endpoint")
	}
	for _, fault := range []string{"type", "detour"} {
		t.Run("native-closure/"+fault, func(t *testing.T) {
			closure, err := nodeMultihopPredecessor(nodes[2])
			if err != nil || !nodeChainFinalClosure(nodes[2], closure) {
				t.Fatal("original final closure missing", err)
			}
			if fault == "type" {
				closure.final["type"] = "direct"
			} else {
				closure.final["detour"] = "unowned-wrapper"
			}
			if nodeChainFinalClosure(nodes[2], closure) {
				t.Fatal("mode label authorized a substituted native final closure")
			}
		})
	}
}

func TestNodeChainHysteriaFinalKeepsDeviceAndMTUPolicy(t *testing.T) {
	nodes, _ := nodeChainHysteriaFixture(t, 3, "awg2-fast", "")
	for i, changes := range []map[string]any{
		{"home_lan_access": false, "home_lan_cidrs": []any{"10.12.0.0/16"}},
		{"ipv6_mode": "off"},
		{"mtu_policy": "manual", "manual_mtu": float64(1280)},
	} {
		input := nodes[i].inputs
		profile := predecessorCopy(nodes[i].profile)
		for key, value := range changes {
			profile[key] = value
		}
		var err error
		nodes[i], err = NewNodeProfile(input.Mode, input.Files, startJSON(t, profile), input.Start, input.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
	}
	chain, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes)))
	if err != nil {
		t.Fatal(err)
	}
	graph := externalTestRead(t, chain.Config())
	ipv6, lan := false, false
	for _, raw := range graph["route"].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		ipv6 = ipv6 || rule["action"] == "reject" && rule["ip_version"] == float64(6)
		ranges, _ := rule["ip_cidr"].([]any)
		for _, cidr := range ranges {
			lan = lan || rule["action"] == "reject" && cidr == "10.12.0.0/16"
		}
	}
	if !ipv6 || !lan {
		t.Fatal("new final dropped a preceding node's IPv6 or LAN refusal")
	}
	if _, err := ProjectNodeChain(chain, "android", 1400); err == nil {
		t.Fatal("automatic restore replaced captured Fixed final MTU")
	}
	if _, err := chain.PlanForMTU(chain.Config(), 1400); err == nil {
		t.Fatal("native readback mismatch acquired the original MTU plan")
	}
	graph["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(1280)
	final := externalTestFind(t, graph, chain.FinalTag())
	final["detour"] = chain.proofs[0].Tag
	if _, err := chain.PlanForMTU(startJSON(t, graph), 1280); err == nil {
		t.Fatal("MTU readback dropped a captured prefix")
	}
}

func TestNodeChainHysteriaFinalChangedSourceCannotBorrowReceipt(t *testing.T) {
	nodes, source := nodeChainHysteriaFixture(t, 3, "awg2-fast", "")
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	launch, err := chain.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"password", "sni", "trust", "obfs", "endpoint", "dns", "identity", "mtu", "lan", "ipv6"} {
		t.Run(fault, func(t *testing.T) {
			last := nodes[2]
			profile := predecessorCopy(last.profile)
			var assets map[string]string
			_ = json.Unmarshal([]byte(last.inputs.Files), &assets)
			graph := externalTestRead(t, string(mustDecodeChainAsset(t, assets["sing-box.json"])))
			out := graph["outbounds"].([]any)[0].(map[string]any)
			switch fault {
			case "password":
				out["password"] = "another-original-credential"
			case "sni":
				out["tls"].(map[string]any)["server_name"] = "another-final.example"
			case "trust":
				assets["cert.pem"] = base64.StdEncoding.EncodeToString([]byte(entryCertificate(t)))
			case "obfs":
				out["obfs"].(map[string]any)["password"] = "another-original-mask"
			case "endpoint":
				out["server"], profile["endpoint"] = "198.51.100.99", "198.51.100.99"
			case "dns":
				profile["adguard_ipv4"] = "10.99.0.53"
			case "identity":
				profile["node_proof_id"] = strings.Repeat("a", 64)
			case "mtu":
				profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(1280)
			case "lan":
				profile["home_lan_access"] = false
			case "ipv6":
				profile["ipv6_mode"] = "off"
			}
			assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
			next, err := NewNodeProfile(last.mode, startJSON(t, assets), startJSON(t, profile), "", "")
			if err != nil {
				t.Fatal("valid independent changed final capture", err)
			}
			changed := source
			changed.Nodes = append([]string(nil), source.Nodes...)
			changed.Nodes[2], err = next.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := NewNodeChain(startJSON(t, changed))
			if err != nil || fresh.SourceSHA256() == chain.SourceSHA256() {
				t.Fatal("changed final reused old source", err)
			}
			var receipt nodeChainLaunchRecord
			_ = json.Unmarshal([]byte(launch), &receipt)
			receipt.NodeChainSource = changed
			if _, err := ParseNodeChainLaunchInput(startJSON(t, receipt)); err == nil {
				t.Fatal("changed final borrowed old launch/config/metadata receipt")
			}
		})
	}
}

func TestNodeChainHysteriaFinalRequiresEveryProofAndJoinedLifetime(t *testing.T) {
	// Native dial routing is doubled here; the separate encrypted peer gate is
	// required before platform adoption. HTTP/TLS identity and cleanup are real.
	for _, fault := range []string{"success", "middle-identity", "final-identity", "final-dead", "dns", "network"} {
		t.Run(fault, func(t *testing.T) {
			_, source := nodeChainHysteriaFixture(t, 3, "awg2-strong", "")
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			engine := newNodeChainTestEngine(t, chain)
			switch fault {
			case "middle-identity":
				engine.wrong = 1
			case "final-identity":
				engine.wrong = 2
			case "final-dead":
				engine.dead = 2
			case "dns":
				engine.dnsFail = true
			case "network":
				engine.changeOnDNS = true
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = chain.Run(ctx, engine)
			if fault == "success" {
				if err != nil || chain.HealthyContext(ctx) != nil || !chain.Progress().Ready {
					t.Fatal("original complete proof failed", err)
				}
				engine.mu.Lock()
				calls, dns := append([]string(nil), engine.calls...), engine.dnsCalls
				engine.mu.Unlock()
				want := append(chain.PrefixTags(), chain.PrefixTags()...)
				if !reflect.DeepEqual(calls, want) || dns != 1 {
					t.Fatal("Hysteria2 final skipped original per-prefix proof or selected DNS")
				}
			} else if err == nil || chain.Progress().Ready {
				t.Fatal("failed original path acquired readiness", fault)
			}
			cancel()
			closeCtx, finish := context.WithTimeout(context.Background(), time.Second)
			defer finish()
			if err := chain.CloseContext(closeCtx); err != nil {
				t.Fatal("exact original lifetime failed to join", err)
			}
			if chain.Progress().Ready || chain.HealthyContext(context.Background()) == nil || chain.Run(context.Background(), engine) == nil {
				t.Fatal("retired Hysteria2 path retained authority")
			}
		})
	}
}

func TestNodeChainHysteriaFinalRemainsUncontactedCandidateProvenance(t *testing.T) {
	nodes, source := nodeChainHysteriaFixture(t, 3, "awg2-fast", "")
	target, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	inventory := candidateInventoryFixture(t, "original-candidate-catalog", target)
	prepared, err := NewNodeChainCandidatePreparation(startJSON(t, source), 1, inventory)
	if err != nil {
		t.Fatal(err)
	}
	last := nodes[2]
	if len(prepared.ProofInventory()) != 2 || strings.Contains(prepared.Config(), last.profile["endpoint"].(string)) ||
		strings.Contains(prepared.Config(), `"type":"hysteria2"`) || strings.Contains(prepared.Config(), last.profile["api_token"].(string)) {
		t.Fatal("prefix-only preparation constructed or contacted saved final")
	}
	graph := externalTestRead(t, prepared.Config())
	if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
		t.Fatal("candidate purpose opened ordinary ingress")
	}
	meta := externalTestRead(t, prepared.Metadata())
	if meta["ready"] != false || meta["application_open"] != false || meta["dns_open"] != false {
		t.Fatal("saved final provenance became live proof")
	}
	round, err := ParseNodeChainCandidatePreparation(prepared.Source())
	if err != nil || round.Config() != prepared.Config() || round.OriginalSourceSHA256() != prepared.OriginalSourceSHA256() {
		t.Fatal("prefix replay lost exact original final provenance", err)
	}
}
