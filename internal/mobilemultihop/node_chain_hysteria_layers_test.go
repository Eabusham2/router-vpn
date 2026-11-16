package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The packet ceiling is an explicit fixture input, not a restored MTU or a
// relaxed timeout. Maximum independently layered paths need enough captured
// capacity to carry the unchanged conservative 1280-byte TUN.
func nodeChainHysteriaLayerFixture(t *testing.T, count int, first, prefixLayer, finalLayer string) ([]*NodeProfile, NodeChainSource) {
	t.Helper()
	modes, layers := make([]string, count), make([]string, count)
	for i := range modes {
		modes[i], layers[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3], prefixLayer
	}
	modes[0], modes[count-1], layers[count-1] = first, "hysteria2", finalLayer
	nodes := nodeChainModeFixtureNodes(t, modes, layers)
	for i, node := range nodes[:count-1] {
		var assets map[string]string
		if json.Unmarshal([]byte(node.inputs.Files), &assets) != nil {
			t.Fatal("missing original packet assets")
		}
		name := "wg.conf"
		if node.mode != "wg" {
			name = "awg.conf"
		}
		raw := string(mustDecodeChainAsset(t, assets[name]))
		if strings.Count(raw, "MTU = 2000") != 1 {
			t.Fatal("fixture lost its original configured packet ceiling")
		}
		assets[name] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(raw, "MTU = 2000", "MTU = 4096", 1)))
		var err error
		nodes[i], err = NewNodeProfile(node.mode, startJSON(t, assets), node.inputs.ProfileJSON, node.inputs.Start, node.inputs.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
	}
	return nodes, nodeChainFixtureSource(t, nodes)
}

func assertNodeChainHysteriaLayerClosure(t *testing.T, graph map[string]any, final *NodeProfile, position int, finalTag, preceding string) {
	t.Helper()
	original, err := nodeMultihopPredecessor(final)
	if err != nil || !nodeChainFinalClosure(final, original) {
		t.Fatal("original Hysteria2 final layer closure refused", err)
	}
	outerTag := nodeChainNamespace(position, final.source, "node", NativeStartLayerTag)
	wantFinal, wantOuter := predecessorCopy(original.final), predecessorCopy(original.nodes[NativeStartLayerTag])
	wantFinal["tag"], wantFinal["detour"] = finalTag, outerTag
	wantOuter["tag"] = outerTag
	if preceding != "" {
		wantOuter["detour"] = preceding
	}
	actualFinal, actualOuter := externalTestFind(t, graph, finalTag), externalTestFind(t, graph, outerTag)
	if !reflect.DeepEqual(actualFinal, wantFinal) || !reflect.DeepEqual(actualOuter, wantOuter) ||
		actualFinal["type"] != "hysteria2" || actualFinal["server"] != "127.0.0.1" ||
		actualFinal["server_port"] != original.final["server_port"] || actualOuter["server"] != final.profile["endpoint"] {
		t.Fatal("Hysteria2 final or outer layer changed captured TLS/CA/password/keys/destination or bypassed the original prefix")
	}
	if actualFinal["password"] == actualOuter["password"] || actualFinal["tls"] == nil || actualFinal["obfs"] == nil {
		t.Fatal("fixture lost independent inner credentials, trust or Salamander ownership")
	}
	for _, raw := range graph["outbounds"].([]any) {
		row := raw.(map[string]any)
		if row["tag"] == finalTag && row["detour"] == preceding {
			t.Fatal("inner Hysteria2 skipped its original final layer")
		}
	}
}

func testNodeChainHysteriaFinalLayers(t *testing.T, count int) {
	for layerIndex, finalLayer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for prefixIndex, prefixLayer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			first := []string{"wg", "awg2-fast", "awg2-strong"}[(prefixIndex+layerIndex)%3]
			name := prefixLayer
			if name == "" {
				name = "off"
			}
			t.Run(name+"/"+finalLayer, func(t *testing.T) {
				nodes, source := nodeChainHysteriaLayerFixture(t, count, first, prefixLayer, finalLayer)
				before := startJSON(t, source)
				chain, err := NewNodeChain(before)
				if err != nil {
					t.Fatal("original independently layered Hysteria2 ordered source refused", err)
				}
				graph := importedPQGraph(t, chain.Config())
				assertNodeChainHysteriaLayerClosure(t, graph, nodes[count-1], count-1, chain.FinalTag(), chain.proofs[count-2].Tag)
				if len(graph["inbounds"].([]any)) != 1 || len(graph["endpoints"].([]any)) != count-1 || len(chain.proofs) != count ||
					chain.Progress().Ready || chain.HealthyContext(context.Background()) == nil || chain.sourceJSON != before || before != startJSON(t, source) {
					t.Fatal("layered capture changed topology/source or invented native readiness")
				}
				for i, node := range nodes {
					layer := prefixLayer
					if i == count-1 {
						layer = finalLayer
					}
					if layer == "" {
						layer = "off"
					}
					proof := chain.proofs[i]
					if proof.Position != i || proof.SourceSHA256 != node.SourceSHA256() || proof.StartLayer != layer || proof.Mode != node.mode || proof.NodeID != node.profile["node_proof_id"] {
						t.Fatal("layered path replaced an original member", i)
					}
				}
				physical, err := chain.PhysicalEgress()
				firstPhysical, firstErr := nodes[0].PhysicalEgress()
				if err != nil || firstErr != nil || !reflect.DeepEqual(physical, firstPhysical) {
					t.Fatal("layered final gained physical egress", err, firstErr)
				}
				dns := chain.DNSCapture()
				selected := false
				for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
					row := raw.(map[string]any)
					if row["tag"] == dns.ResolverTag {
						selected = row["server"] == nodes[count-1].profile["adguard_ipv4"] && row["detour"] == chain.FinalTag() && row["type"] == "udp"
					}
				}
				if !selected || chain.MTUProfile() != startJSON(t, nodes[count-1].profile) {
					t.Fatal("layered final changed selected DNS or original MTU policy")
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
					if err != nil || reopened.Config() != projected.Config() || reopened.SourceSHA256() != chain.SourceSHA256() || reopened.Progress().Ready {
						t.Fatal("layered platform seal changed its original source", target, err)
					}
					if _, err := reopened.PlanForMTU(reopened.Config(), 1280); err != nil {
						t.Fatal("captured layered MTU budget refused", target, err)
					}
				}
				changed := importedPQGraph(t, chain.Config())
				externalTestFind(t, changed, chain.FinalTag())["detour"] = chain.proofs[count-2].Tag
				if _, err := chain.PlanForMTU(startJSON(t, changed), 1280); err == nil {
					t.Fatal("layer-skipping graph borrowed the original MTU plan")
				}
				if NodeChainCandidateInputSupported(source.Nodes[count-1]) {
					t.Fatal("Hysteria2 layer invented a TCP candidate transport")
				}
			})
		}
	}
}

func TestNodeChainHysteriaFinalLayers2(t *testing.T) { testNodeChainHysteriaFinalLayers(t, 2) }
func TestNodeChainHysteriaFinalLayers3(t *testing.T) { testNodeChainHysteriaFinalLayers(t, 3) }
func TestNodeChainHysteriaFinalLayers4(t *testing.T) { testNodeChainHysteriaFinalLayers(t, 4) }
func TestNodeChainHysteriaFinalLayers5(t *testing.T) { testNodeChainHysteriaFinalLayers(t, 5) }
func TestNodeChainHysteriaFinalLayers6(t *testing.T) { testNodeChainHysteriaFinalLayers(t, 6) }
func TestNodeChainHysteriaFinalLayers7(t *testing.T) { testNodeChainHysteriaFinalLayers(t, 7) }
func TestNodeChainHysteriaFinalLayers8(t *testing.T) { testNodeChainHysteriaFinalLayers(t, 8) }

func TestNodeChainHysteriaFinalLayersRejectChangedClosure(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"inner-type", "inner-host", "inner-port", "inner-password", "inner-sni", "inner-ca", "inner-mask", "inner-detour", "outer-missing", "outer-type", "outer-method", "outer-key", "outer-host", "outer-port", "outer-detour"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				nodes, _ := nodeChainHysteriaLayerFixture(t, 2, "wg", "", layer)
				last := nodes[1]
				closure, err := nodeMultihopPredecessor(last)
				if err != nil || !nodeChainFinalClosure(last, closure) {
					t.Fatal("negative fixture lacks original layered authority", err)
				}
				outer := closure.nodes[NativeStartLayerTag]
				switch fault {
				case "inner-type":
					closure.final["type"] = "direct"
				case "inner-host":
					closure.final["server"] = "198.51.100.88"
				case "inner-port":
					closure.final["server_port"] = float64(1)
				case "inner-password":
					closure.final["password"] = "foreign"
				case "inner-sni":
					closure.final["tls"].(map[string]any)["server_name"] = "foreign.example"
				case "inner-ca":
					closure.final["tls"].(map[string]any)["certificate"] = "foreign trust"
				case "inner-mask":
					closure.final["obfs"].(map[string]any)["password"] = "foreign mask"
				case "inner-detour":
					closure.final["detour"] = "foreign"
				case "outer-missing":
					delete(closure.nodes, NativeStartLayerTag)
				case "outer-type":
					outer["type"] = "direct"
				case "outer-method":
					outer["method"] = "none"
				case "outer-key":
					outer["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
				case "outer-host":
					outer["server"] = "198.51.100.88"
				case "outer-port":
					outer["server_port"] = float64(1)
				case "outer-detour":
					outer["detour"] = "foreign"
				}
				if nodeChainFinalClosure(last, closure) {
					t.Fatal("changed Hysteria2 final or outer gained original closure authority", fault)
				}
			})
		}
	}
}

func TestNodeChainHysteriaFinalLayersRejectBorrowedSource(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"password", "sni", "trust", "mask", "outer-key", "dns", "layer"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				nodes, source := nodeChainHysteriaLayerFixture(t, 3, "awg2-fast", "", layer)
				original, err := NewNodeChain(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				launch, err := original.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				last := nodes[2]
				profile := predecessorCopy(last.profile)
				var assets, outerAssets map[string]string
				if json.Unmarshal([]byte(last.inputs.Files), &assets) != nil || json.Unmarshal([]byte(last.inputs.Start), &outerAssets) != nil {
					t.Fatal("missing captured transport assets")
				}
				graph := importedPQGraph(t, string(mustDecodeChainAsset(t, assets["sing-box.json"])))
				final := graph["outbounds"].([]any)[0].(map[string]any)
				switch fault {
				case "password":
					final["password"] = "different valid Hysteria2 password"
				case "sni":
					final["tls"].(map[string]any)["server_name"] = "different-final.example"
				case "trust":
					assets["cert.pem"] = base64.StdEncoding.EncodeToString([]byte(entryCertificate(t)))
				case "mask":
					final["obfs"].(map[string]any)["password"] = "different valid mask"
				case "outer-key":
					outer := importedPQGraph(t, string(mustDecodeChainAsset(t, outerAssets["sing-box.json"])))
					outer["outbounds"].([]any)[0].(map[string]any)["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32)))
					outerAssets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, outer)))
				case "dns":
					profile["adguard_ipv4"] = "10.99.0.53"
				case "layer":
					profile["start_layer"] = "aes-256-gcm"
					if layer == "aes-256-gcm" {
						profile["start_layer"] = "aes-256-gcm+xor-whitening"
					}
				}
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
				next, err := NewNodeProfile("hysteria2", startJSON(t, assets), startJSON(t, profile), startJSON(t, outerAssets), "")
				if err != nil {
					t.Fatal("valid independent layered source refused", err)
				}
				changed := source
				changed.Nodes = append([]string(nil), source.Nodes...)
				changed.Nodes[2], err = next.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				fresh, err := NewNodeChain(startJSON(t, changed))
				if err != nil || fresh.SourceSHA256() == original.SourceSHA256() {
					t.Fatal("changed layered source borrowed original digest", err)
				}
				var sealed nodeChainLaunchRecord
				if json.Unmarshal([]byte(launch), &sealed) != nil {
					t.Fatal("original launch missing")
				}
				sealed.NodeChainSource = changed
				if _, err := ParseNodeChainLaunchInput(startJSON(t, sealed)); err == nil {
					t.Fatal("changed layered source borrowed original launch receipt")
				}
			})
		}
	}
}

func TestNodeChainHysteriaFinalLayersRequireOriginalProofLifetime(t *testing.T) {
	// HTTP identity/DNS/close code is real; encrypted native dial routing is an
	// explicit engine double here and needs the separate native layer gate.
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"success", "middle-identity", "final-identity", "final-dead", "dns", "network"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				_, source := nodeChainHysteriaLayerFixture(t, 3, "awg2-strong", "aes-256-gcm", layer)
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
						t.Fatal("original layered proof failed", err)
					}
					engine.mu.Lock()
					calls, dns := append([]string(nil), engine.calls...), engine.dnsCalls
					engine.mu.Unlock()
					if !reflect.DeepEqual(calls, append(chain.PrefixTags(), chain.PrefixTags()...)) || dns != 1 {
						t.Fatal("layered path omitted original proof or selected DNS")
					}
				} else if err == nil || chain.Progress().Ready {
					t.Fatal("failed layered native path gained readiness", fault)
				}
				cancel()
				closeCtx, finish := context.WithTimeout(context.Background(), time.Second)
				defer finish()
				if err := chain.CloseContext(closeCtx); err != nil {
					t.Fatal("layered path failed original close", err)
				}
				if chain.Progress().Ready || chain.HealthyContext(context.Background()) == nil || chain.Run(context.Background(), engine) == nil {
					t.Fatal("retired layered path retained authority")
				}
			})
		}
	}
}
