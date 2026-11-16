package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"router-vpn/internal/nativecomposite"
	"testing"
	"time"
)

func TestNodeChainCONNECTExecutionFinalLayersRetainOriginalSource(t *testing.T) {
	for _, count := range []int{3, 4, 8} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, execution := range []string{"server", "auto"} {
					t.Run(fmt.Sprintf("%d/%s/%s/%s", count, protocol, layer, execution), func(t *testing.T) {
						original, plan := connectExecutionPrefixPlanLayerFixture(t, count, "wg", protocol, layer)
						server, err := NewNodeChainCONNECTServerPlan(startJSON(t, plan))
						if err != nil {
							t.Fatal(err)
						}
						prep, err := NewNodeChainCONNECTExecutionPreparation(original, execution)
						if err != nil {
							t.Fatal(err)
						}
						capture := nodeChainServerCaptureFixture(t, server)
						request := capture.Request.Clone()
						request.LocalPacketPublicKeys = nil
						request.LocalPacketPositions = nil
						for i, node := range original.pair.nodes[:len(original.pair.nodes)-1] {
							key, e := node.PacketClientPublicKey()
							if e != nil {
								t.Fatal(e)
							}
							request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, key)
							request.LocalPacketPositions = append(request.LocalPacketPositions, i)
						}
						request.Peer, request.Port = "10.80.0.2", 32003
						input := NodeChainExecutionSource{Schema: 4, Execution: execution, LocalSource: original.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
						policy, err := NewNodeChainCONNECTExecutionPolicy(prep, startJSON(t, input))
						if err != nil {
							t.Fatal(err)
						}
						projection, err := prep.BindExecution(policy)
						if err != nil {
							t.Fatal(err)
						}
						if prep.connect.source != original || policy.connect != prep.connect || prep.source.LocalSource != original.sourceJSON {
							t.Fatal("layered preparation replaced original source")
						}
						for _, selected := range []string{"local", "server"} {
							proofs, e := projection.ProofInventory(selected)
							if e != nil || len(proofs) != count || proofs[count-1].StartLayer != layer || proofs[count-1].NodeID != original.metadata.Proofs[count-1].NodeID {
								t.Fatal("layered execution replaced final identity", selected, e)
							}
						}
						before := externalTestFind(t, externalTestRead(t, original.config), original.metadata.Proofs[count-1].Tag)
						after := externalTestFind(t, externalTestRead(t, prep.Config()), original.metadata.Proofs[count-1].Tag)
						if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(after["udp_over_tcp"], map[string]any{"enabled": true, "version": float64(2)}) {
							t.Fatal("layered preparation changed actual final key, detour or UoT")
						}
						config, err := server.NativeConfig(capture)
						if err != nil {
							t.Fatal(err)
						}
						proofs := server.ProofInventory()
						final := externalTestFind(t, externalTestRead(t, config), proofs[len(proofs)-1].Tag)
						kind := "shadowsocks"
						if layer == "aes-256-gcm+xor-whitening" {
							kind = "routervpn-aes-xor"
						}
						if final["type"] != kind || final["password"] != before["password"] || final["method"] != before["method"] || final["detour"] != proofs[len(proofs)-2].Tag || !reflect.DeepEqual(final["udp_over_tcp"], before["udp_over_tcp"]) {
							t.Fatal("Server replaced the original authenticated layered UoT final")
						}
					})
				}
			}
		}
	}
}

// Actual shared lease, comparison and retained restoration execute. Native
// objects remain the existing explicit runtime boundary, separately verified
// by the concrete Box/owner and encrypted component witnesses.
func TestNodeChainCONNECTExecutionFinalLayersRestoreWithoutComparison(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, selected := range []string{"local", "server"} {
				t.Run(fmt.Sprintf("%d/%s/%s", count, layer, selected), func(t *testing.T) {
					f := newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionPrefixLayerFixtureSource(t, count, "auto", layer))
					if selected == "local" {
						f.engine.localDelay, f.engine.serverDelay = time.Millisecond, 200*time.Millisecond
					}
					testCONNECTPrefixExecutionRestoreKeepsWinner(t, f)
					progress := f.runtime.Progress()
					if progress.Execution != selected {
						t.Fatal("layered fixture lost intended winner", progress.Execution)
					}
					proofs, err := f.runtime.projection.ProofInventory(selected)
					if err != nil || proofs[count-1].StartLayer != layer {
						t.Fatal("retained restore lost final layer", err)
					}
				})
			}
		}
	}
}

// Full typed policy construction must retain the actual original service
// declaration. Neither a layer label nor an inline UoT option replaces it.
func TestNodeChainCONNECTServerFinalLayersRequireOriginalService(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"missing-service", "service-node", "service-source", "service-key", "service-version", "source-key", "inline-uot", "unknown-layer", "wrong-cipher"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				input := nodeChainCONNECTFixture(t, "wg", "https-connect", layer, NativeStartLayerMethod, "password")
				original, err := NewNodeChainCONNECTSource(startJSON(t, input))
				if err != nil {
					t.Fatal(err)
				}
				source := NodeChainServerSource{Schema: 4, EntryID: original.metadata.Proofs[0].ProfileID, EntryNodeID: original.metadata.Proofs[0].NodeID, EntryMode: "wg", Nodes: append([]string(nil), input.Nodes[1:]...), IdentitySources: append([]string(nil), input.IdentitySources[1:]...)}
				if _, err = NewNodeChainCONNECTServerPolicy(startJSON(t, source)); err != nil {
					t.Fatal("original layered Server policy", err)
				}
				var member map[string]any
				if json.Unmarshal([]byte(source.Nodes[1]), &member) != nil {
					t.Fatal("original final launch")
				}
				var assets map[string]string
				if json.Unmarshal([]byte(member["files"].(string)), &assets) != nil {
					t.Fatal("original final assets")
				}
				if fault == "unknown-layer" {
					var profile map[string]any
					if json.Unmarshal([]byte(member["profile_json"].(string)), &profile) != nil {
						t.Fatal("original final profile")
					}
					profile["start_layer"] = "other-layer"
					member["profile_json"] = startJSON(t, profile)
				} else if fault == "missing-service" {
					delete(assets, nativecomposite.SSServiceAsset)
				} else if fault == "source-key" || fault == "inline-uot" || fault == "wrong-cipher" {
					raw, err := base64.StdEncoding.DecodeString(assets["sing-box.json"])
					if err != nil {
						t.Fatal(err)
					}
					graph := externalTestRead(t, string(raw))
					final := externalTestFind(t, graph, "proxy")
					if fault == "source-key" {
						final["password"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
					} else if fault == "wrong-cipher" {
						final["method"] = "2022-blake3-aes-128-gcm"
					} else {
						final["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
					}
					assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
				} else {
					raw, err := base64.StdEncoding.DecodeString(assets[nativecomposite.SSServiceAsset])
					if err != nil {
						t.Fatal(err)
					}
					var service map[string]any
					if json.Unmarshal(raw, &service) != nil {
						t.Fatal("original UoT service")
					}
					if fault == "service-version" {
						service["uot_version"] = 1
					} else {
						field := map[string]string{"service-node": "node_id", "service-source": "source_sha256", "service-key": "key_sha256"}[fault]
						service[field] = fmt.Sprintf("%064x", 13)
					}
					assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, service)))
				}
				member["files"] = startJSON(t, assets)
				source.Nodes[1] = startJSON(t, member)
				if _, err = NewNodeChainCONNECTServerPolicy(startJSON(t, source)); err == nil {
					t.Fatal("layered Server borrowed changed final service authority", fault)
				}
			})
		}
	}
}

func TestNodeChainCONNECTServerFinalLayersRebuildFreshClosures(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			_, plan := connectExecutionPrefixPlanLayerFixture(t, 4, "awg2-fast", "https-connect", layer)
			policy, err := NewNodeChainCONNECTServerPlan(startJSON(t, plan))
			if err != nil {
				t.Fatal(err)
			}
			capture := nodeChainServerCaptureFixture(t, policy)
			before, err := policy.NativeConfig(capture)
			if err != nil {
				t.Fatal(err)
			}
			for range 3 {
				_, closures, err := policy.connect.members()
				if err != nil {
					t.Fatal("fresh captured layer closure", err)
				}
				if !reflect.DeepEqual(closures[len(closures)-1].final["udp_over_tcp"], map[string]any{"enabled": true, "version": float64(2)}) {
					t.Fatal("fresh closure lost original UoT-v2")
				}
				after, err := policy.NativeConfig(capture)
				if err != nil || after != before {
					t.Fatal("repeated layer read reused or replaced mutable native closure", err)
				}
			}
			// NativeConfig returns the sealed compiled graph, not the consumed
			// construction-time closure maps. Mutate that actual authority.
			graph := externalTestRead(t, before)
			final := externalTestFind(t, graph, policy.proofs[len(policy.proofs)-1].Tag)
			final["password"] = "foreign-key"
			policy.config = startJSON(t, graph)
			if _, err = policy.NativeConfig(capture); err == nil {
				t.Fatal("changed final native config borrowed original service")
			}
			policy.config = before
			if after, err := policy.NativeConfig(capture); err != nil || after != before {
				t.Fatal("original final closure could not be reobserved", err)
			}
		})
	}
}
