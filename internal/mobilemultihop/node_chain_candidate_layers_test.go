package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
)

func candidateLayerSourceFixture(t *testing.T, layer string) (*NodeProfile, string) {
	t.Helper()
	node := nodeChainModeFixtureNodes(t, []string{"wg", "shadowsocks"}, []string{"", layer})[1]
	profile := predecessorCopy(node.profile)
	profile["id"] = "paired-layer-candidate"
	node, err := NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	input, err := node.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	return node, input
}

func TestNodeChainCandidatePairedLayersUseOriginalTCPClosure(t *testing.T) {
	for _, layer := range []string{"", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			node, input := candidateLayerSourceFixture(t, layer)
			closure, err := nodeMultihopPredecessor(node)
			if err != nil {
				t.Fatal(err)
			}
			target, proof, err := nodeChainCandidateTarget(input)
			expected := net.JoinHostPort(predecessorText(closure.final, "server"), strconv.Itoa(int(closure.final["server_port"].(float64))))
			kind := "shadowsocks"
			if layer == "aes-256-gcm+xor-whitening" {
				kind = "routervpn-aes-xor"
			}
			if err != nil || !NodeChainCandidateInputSupported(input) || target.Address != expected || target.SourceSHA256 != node.SourceSHA256() || target.ID != node.profile["id"] || proof != node.profile["node_proof_id"] || closure.final["type"] != kind {
				t.Fatal("paired candidate lost original concrete TCP closure", layer, err)
			}
			chain := nodeChainFixture(t, 3, "")
			before, beforeConfig := chain.sourceJSON, chain.Config()
			plan, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "original-layer-catalog", input))
			if err != nil || len(plan.targets) != 1 || plan.targets[0] != target || chain.sourceJSON != before || chain.Config() != beforeConfig {
				t.Fatal("paired candidate changed original prefix or endpoint", err)
			}
			if strings.Contains(plan.Metadata(), target.Address) || strings.Contains(plan.Metadata(), predecessorText(closure.final, "password")) || strings.Contains(plan.Metadata(), "api_token") {
				t.Fatal("candidate metadata leaked a private endpoint or credential")
			}
			var assets map[string]string
			if json.Unmarshal([]byte(node.inputs.Files), &assets) != nil {
				t.Fatal("original assets")
			}
			graph := externalTestRead(t, string(mustDecodeChainAsset(t, assets["sing-box.json"])))
			out := graph["outbounds"].([]any)[0].(map[string]any)
			out["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
			assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
			changed, err := NewNodeProfile(node.mode, startJSON(t, assets), node.inputs.ProfileJSON, node.inputs.Start, node.inputs.DNSBootstrap)
			if err != nil {
				t.Fatal("well-formed different original key", err)
			}
			changedInput, err := changed.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			next, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "original-layer-catalog", changedInput))
			if err != nil || next.capture == plan.capture || next.targets[0].SourceSHA256 == target.SourceSHA256 || next.targets[0].Address != target.Address {
				t.Fatal("captured credential change failed to revoke catalog while preserving the TCP metric", err)
			}
		})
	}
}

func TestNodeChainCandidatePairedLayersRejectSourceSubstitution(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"layer-type", "unknown-layer", "xor-only", "wrong-key-size", "wrong-method", "hostname", "network", "uot", "detour"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				node, _ := candidateLayerSourceFixture(t, layer)
				record := node.inputs
				profile := predecessorCopy(node.profile)
				var files map[string]string
				_ = json.Unmarshal([]byte(record.Files), &files)
				graph := externalTestRead(t, string(mustDecodeChainAsset(t, files["sing-box.json"])))
				out := graph["outbounds"].([]any)[0].(map[string]any)
				switch fault {
				case "layer-type":
					profile["start_layer"] = true
				case "unknown-layer":
					profile["start_layer"] = "foreign"
				case "xor-only":
					profile["start_layer"] = "xor-whitening"
				case "wrong-key-size":
					out["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 16)))
				case "wrong-method":
					out["method"] = "2022-blake3-chacha20-poly1305"
				case "hostname":
					out["server"] = "candidate.invalid"
				case "network":
					out["network"] = "udp"
				case "uot":
					out["udp_over_tcp"] = true
				case "detour":
					out["detour"] = "foreign"
				}
				files["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
				changed, err := NewNodeProfile(record.Mode, startJSON(t, files), startJSON(t, profile), record.Start, record.DNSBootstrap)
				if err != nil {
					return
				}
				input, err := changed.LaunchInput()
				if err != nil {
					return
				}
				if NodeChainCandidateInputSupported(input) {
					t.Fatal("unowned layered candidate acquired a TCP endpoint", fault)
				}
			})
		}
	}
}

// The shared runtime uses actual loopback sockets but an explicit retained
// packet-engine fixture. The native peer suite separately supplies WG/AWG.
func TestNodeChainCandidatePairedLayersRunFiftyAndRetire(t *testing.T) {
	for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"complete", "captured-key-change", "failed-fiftieth"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				node, input := candidateLayerSourceFixture(t, layer)
				chain := nodeChainFixture(t, 3, "")
				plan, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "layer-runtime", input))
				if err != nil {
					t.Fatal(err)
				}
				base := newNodeChainTestEngine(t, chain)
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					for {
						c, err := listener.Accept()
						if err != nil {
							return
						}
						_ = c.Close()
					}
				}()
				t.Cleanup(func() { _ = listener.Close(); <-done })
				engine := &candidateRouteFixture{nodeChainTestEngine: base, tag: chain.proofs[0].Tag, address: plan.targets[0].Address, peer: listener.Addr().String()}
				if err := chain.Run(context.Background(), engine); err != nil {
					t.Fatal(err)
				}
				owner := &candidateOwnerFixture{nodeChainMeasurementFixture: nodeChainMeasurementFixture{chain: chain}, capture: plan.capture}
				measurement, err := plan.NewMeasurementContext(context.Background(), owner)
				if err != nil {
					t.Fatal(err)
				}
				defer measurement.Close()
				if fault == "captured-key-change" {
					var assets map[string]string
					_ = json.Unmarshal([]byte(node.inputs.Files), &assets)
					graph := externalTestRead(t, string(mustDecodeChainAsset(t, assets["sing-box.json"])))
					graph["outbounds"].([]any)[0].(map[string]any)["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32)))
					assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
					changed, e := NewNodeProfile(node.mode, startJSON(t, assets), node.inputs.ProfileJSON, node.inputs.Start, node.inputs.DNSBootstrap)
					if e != nil {
						t.Fatal(e)
					}
					changedInput, e := changed.LaunchInput()
					if e != nil {
						t.Fatal(e)
					}
					next, e := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "layer-runtime", changedInput))
					if e != nil || next.capture == plan.capture {
						t.Fatal("actual key-change control lost catalog distinction", e)
					}
					engine.before = func(context.Context) { owner.setCapture(next.capture) }
				} else if fault == "failed-fiftieth" {
					engine.before = func(context.Context) {
						if engine.count.Load() == 50 {
							_ = listener.Close()
						}
					}
				}
				request := strings.Repeat("f", 32)
				if err := measurement.Start(request, plan.targets[0].ID); err != nil {
					t.Fatal(err)
				}
				if err := measurement.Drain(request); err != nil {
					t.Fatal(err)
				}
				status := candidateStatus(t, measurement)
				switch fault {
				case "complete":
					if len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || status.Results[0].Benchmark.Distribution.Samples != 50 || status.Results[0].Benchmark.Measurement != "routed-tcp-connect" || engine.count.Load() != 50 {
						t.Fatal("layered shared runtime lost exact fifty TCP samples", status)
					}
				case "captured-key-change":
					if len(status.Results) != 0 || engine.count.Load() != 1 {
						t.Fatal("changed original key retained a score", status)
					}
					owner.setCapture(plan.capture)
					if measurement.Start(strings.Repeat("e", 32), plan.targets[0].ID) == nil {
						t.Fatal("original catalog revived after key-change observation")
					}
				case "failed-fiftieth":
					if len(status.Results) != 1 || status.Results[0].Ready || status.Results[0].Benchmark != nil || engine.count.Load() != 50 {
						t.Fatal("failed fiftieth layered candidate retained benchmark", status)
					}
				}
				if owner.active.Load() || owner.released.Load() != 1 {
					t.Fatal("layered shared runtime abandoned original MTU hold")
				}
			})
		}
	}
}
