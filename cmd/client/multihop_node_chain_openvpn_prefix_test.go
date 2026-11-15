package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

func desktopOpenVPNPrefixCaptureFixture(t *testing.T, prefixes int, mode, network, layer string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	if prefixes < 1 || prefixes > 6 {
		t.Fatal("OpenVPN fixture lost its original bounded packet prefix")
	}
	a, nodes := desktopNodeChainCaptureFixture(t, prefixes+2)
	modes := make([]string, len(nodes))
	for i := range modes {
		modes[i] = mode
	}
	modes[prefixes], modes[prefixes+1] = "wg", "shadowsocks"
	installOrderedAWGAssets(t, a, nodes, modes, layer)
	installDesktopOrderedOpenVPN(t, a, nodes, network)
	if prefixes > 1 {
		// This positive source explicitly requests a compatible fixed capacity.
		// The original trio still uses 1500; a separate long-path case below
		// requires rejection when that larger fixed value cannot fit.
		middle := &a.profiles.Profiles[prefixes]
		middle.ManualMTU = 1280
		middle.External.OpenVPN.Config = strings.Replace(middle.External.OpenVPN.Config, "tun-mtu 1500\n", "tun-mtu 1280\n", 1)
	}
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch = false
		a.profiles.Profiles[i].KillSwitchPolicy = "off"
	}
	a.profiles.Profiles[prefixes].KillSwitchPolicy = "always"
	return a, nodes
}

func TestDesktopOrderedOpenVPNPacketPrefixes(t *testing.T) {
	for prefixes := 1; prefixes <= 6; prefixes++ {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			for _, network := range []string{"tcp", "udp"} {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, network, prefixes), func(t *testing.T) {
					a, nodes := desktopOpenVPNPrefixCaptureFixture(t, prefixes, mode, network, "off")
					original := cloneRouterProfileStore(a.profiles)
					capture := captureNodeChainTest(t, a, nodes)
					proofs := capture.chain.ProofInventory()
					if len(proofs) != len(nodes) || len(capture.members) != len(nodes) {
						t.Fatal("OpenVPN capture dropped an original paired prefix")
					}
					var wire mobilemultihop.NodeChainSource
					if json.Unmarshal([]byte(capture.input), &wire) != nil || wire.Schema != 5 || len(wire.Nodes) != len(nodes) || len(wire.IdentitySources) != len(nodes) {
						t.Fatal("OpenVPN capture lost original schema-five source inventory")
					}
					for i, proof := range proofs {
						if i == prefixes {
							if wire.IdentitySources[i] != "" || proof.NodeID != "" || proof.Mode != "openvpn" || proof.StartLayer != "off" {
								t.Fatal("OpenVPN penultimate borrowed paired identity or layer", i)
							}
						} else if wire.IdentitySources[i] == "" || proof.NodeID != original.Profiles[i].NodeProofID || proof.Mode != nodes[i].Mode {
							t.Fatal("OpenVPN capture substituted a paired prefix or final", i)
						}
					}
					middle, err := capture.chain.OpenVPNMiddleCapture()
					if err != nil || middle.Tag != proofs[prefixes].Tag || middle.SourceSHA256 == "" || middle.Remote.Network != network || middle.Remote.Host != original.Profiles[prefixes].Endpoint || middle.ConfiguredMTU < 1280 {
						t.Fatal("OpenVPN native observation lost its original dynamic endpoint", err, middle)
					}
					final := original.Profiles[prefixes+1]
					for _, target := range []string{"linux", "windows", "darwin"} {
						policy, err := mobilemultihop.NewDesktopNodeChainPolicy(capture.chain, strings.Repeat("a", 32), target, 0)
						if err != nil {
							t.Fatal(target, err)
						}
						config, meta, physical, err := policy.ReadValidated()
						if err != nil || len(meta.Prefixes) != len(nodes) || meta.Prefixes[prefixes].Mode != "openvpn" || meta.KillSwitchPolicy != "always" || meta.ProfileID != final.ID || meta.NodeID != final.NodeProofID || meta.FinalTag != proofs[prefixes+1].Tag || len(physical.PhysicalRoots) != 1 || physical.PhysicalRoots[0].Tag != proofs[0].Tag {
							t.Fatal("OpenVPN desktop projection replaced original policy or physical/final owner", target, err)
						}
						var graph map[string]any
						if json.Unmarshal([]byte(config), &graph) != nil {
							t.Fatal("OpenVPN desktop projection lost its native graph")
						}
						endpoint := desktopImportedGraphNode(t, graph, middle.Tag)
						if endpoint["type"] != "openvpn-client" || endpoint["detour"] != proofs[prefixes-1].Tag || endpoint["server"] != middle.Remote.Host || endpoint["network"] != network || endpoint["system"] != false {
							t.Fatal("OpenVPN endpoint bypassed its original last packet prefix", endpoint)
						}
						launch, err := policy.ReadValidatedLaunch()
						if err != nil {
							t.Fatal(err)
						}
						replayed, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(launch.Input)
						if err != nil || replayed.Config() != config {
							t.Fatal("native launch reopened a different complete OpenVPN path", target, err)
						}
						_, replayedMeta, _, err := replayed.ReadValidated()
						if err != nil || !reflect.DeepEqual(replayedMeta.Prefixes, meta.Prefixes) {
							t.Fatal("native launch reopened different OpenVPN member proofs", target, err)
						}
					}
					if !reflect.DeepEqual(original, a.profiles) {
						t.Fatal("OpenVPN capture rewrote original stored credentials or policies")
					}
					for i := 0; i < prefixes; i++ {
						changed := cloneRouterProfileStore(original)
						changed.Profiles[i].APIToken += "-replacement"
						if capture.validate(context.Background(), final, changed.Profiles) == nil {
							t.Fatal("OpenVPN capture adopted a replacement paired prefix", i)
						}
					}
				})
			}
		}
	}
}

func TestDesktopOrderedOpenVPNPrefixSavedAndMeasuredPositions(t *testing.T) {
	for _, prefixes := range []int{2, 6} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("%s/%d", network, prefixes), func(t *testing.T) {
				a, nodes := desktopOpenVPNPrefixCaptureFixture(t, prefixes, "wg", network, "off")
				desktopCONNECTSelectPublicHandler(t, a) // Existing dispatcher boundary; no installed native acceptance.
				originalMiddle := common.CloneRouterProfile(a.profiles.Profiles[prefixes])
				final := a.profiles.Profiles[prefixes+1]
				id := saveOrderedConnectionFixture(t, a, nodes)
				store, err := loadConnectionProfileStore(a)
				if err != nil || len(store.Profiles) != 1 || store.Profiles[0].ID != id || len(store.Profiles[0].NodeChain) != len(nodes) || validateSavedNodeChain(store.Profiles[0]) != nil {
					t.Fatal("saved OpenVPN path lost its complete original members", err)
				}
				raw, err := os.ReadFile(connectionProfileStorePath(a))
				if err != nil || strings.Contains(string(raw), originalMiddle.External.OpenVPN.Password) || strings.Contains(string(raw), originalMiddle.External.OpenVPN.Config) {
					t.Fatal("saved OpenVPN path copied private credentials", err)
				}
				original := cloneRouterProfileStore(a.profiles)
				updated := postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{
					"id": id, "name": "Updated original OpenVPN path", "mode": "shadowsocks",
					"multihop_enabled": true, "multihop_execution": "local", "multihop_nodes": nodes,
				})
				store, err = loadConnectionProfileStore(a)
				if updated.Code != http.StatusOK || err != nil || len(store.Profiles) != 1 || store.Profiles[0].Name != "Updated original OpenVPN path" || len(store.Profiles[0].NodeChain) != len(nodes) {
					t.Fatal("Update lost the complete OpenVPN profile", updated.Code, updated.Body.String(), err)
				}
				for i := range a.profiles.Profiles {
					a.profiles.Profiles[i].DNSPort, a.profiles.Profiles[i].MTUPolicy, a.profiles.Profiles[i].ManualMTU = 5353, "manual", 1400
				}
				loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
				if loaded.Code != http.StatusOK || a.state.Connected || a.cmd != nil {
					t.Fatal("Load did not restore the complete disconnected OpenVPN profile", loaded.Code, loaded.Body.String())
				}
				for i, profile := range a.profiles.Profiles {
					before := original.Profiles[i]
					if profile.DNSPort != before.DNSPort || profile.MTUPolicy != before.MTUPolicy || profile.ManualMTU != before.ManualMTU || profile.APIToken != before.APIToken || profile.NodeProofID != before.NodeProofID || !reflect.DeepEqual(profile.External, before.External) {
						t.Fatal("Load substituted an original member's policy or private source", i)
					}
				}
				if !reflect.DeepEqual(a.profiles.Profiles[prefixes+1].MultihopNodes, nodes) {
					t.Fatal("Load truncated or reordered the captured OpenVPN path")
				}
				// Load transactionally publishes the current linked control. Startup
				// must capture that owner, not the pre-Load local value above.
				final = a.profiles.Profiles[prefixes+1]
				capture, err := captureStartupNodeChain(a, final, a.profiles.Profiles, nil)
				if err != nil {
					t.Fatal(err)
				}
				last := startupSelection{Base: capture.selection.Base, ProfileToken: startupExternalProfileToken(final), RouterID: final.ID, RuntimeMode: "shadowsocks", LogicalMode: "multihop", UpdatedAt: time.Now().UTC(), NodeChain: capture.receipt(), PathKind: startupNodeChainPathKind}
				if validateStartupNodeChainSelection(last) != nil || last.NodeChain.Schema != 5 || last.NodeChain.Nodes[prefixes].NodeKind != "external" || last.NodeChain.Nodes[1].NodeKind == "external" {
					t.Fatal("Last OpenVPN receipt lost the captured dynamic penultimate")
				}
				status := hopmeasure.Status{Complete: true, Drained: true, Stage: "complete"}
				for i, member := range capture.selection.Nodes {
					role, kind := "intermediate", "private-node"
					if i == 0 {
						role = "entry"
					}
					if i == prefixes+1 {
						role = "exit"
					}
					if i == prefixes {
						kind = "public-path"
					}
					status.Results = append(status.Results, hopmeasure.Result{ID: member.Profile.ID, Role: role, Kind: kind, Ready: true, Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 3}, Download: &hopmeasure.Transfer{Bytes: 65536, Seconds: 0.5, Mbps: 1.048576}, Upload: &hopmeasure.Transfer{Bytes: 65536, Seconds: 1, Mbps: 0.524288}})
				}
				rows, err := desktopNodeChainMeasurementRows(status, capture.selection.Nodes, 65536)
				if err != nil || len(rows) != len(nodes) || !strings.Contains(rows[prefixes].Latency.Proof, "original openvpn transport") || strings.Contains(rows[prefixes].Latency.Proof, "SS2022") {
					t.Fatal("OpenVPN measurement relabelled its original position or transport", err)
				}
				for _, fault := range []string{"position", "missing-source", "foreign-family"} {
					raw, _ := json.Marshal(last)
					var changed startupSelection
					if json.Unmarshal(raw, &changed) != nil {
						t.Fatal("test receipt failed to reopen")
					}
					switch fault {
					case "position":
						changed.NodeChain.Nodes[1], changed.NodeChain.Nodes[prefixes] = changed.NodeChain.Nodes[prefixes], changed.NodeChain.Nodes[1]
					case "missing-source":
						changed.NodeChain.Nodes[prefixes].Sources = nil
					case "foreign-family":
						changed.NodeChain.Schema = 2
					}
					if validateStartupNodeChainSelection(changed) == nil {
						t.Fatal("changed OpenVPN startup authority was accepted", fault)
					}
				}
				status.Results[prefixes].Kind = "private-node"
				if _, err := desktopNodeChainMeasurementRows(status, capture.selection.Nodes, 65536); err == nil {
					t.Fatal("OpenVPN measurement borrowed private paired proof")
				}
				a.profiles.Profiles[prefixes].External.OpenVPN.Password += "-replacement"
				response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
				if response.Code == http.StatusOK {
					t.Fatal("saved longer OpenVPN path adopted a replacement private source")
				}
				beforeDelete := cloneRouterProfileStore(a.profiles)
				deleted := postSetup(t, a, "/api/connection-profile/setup/delete", map[string]any{"id": id})
				store, err = loadConnectionProfileStore(a)
				if deleted.Code != http.StatusOK || err != nil || len(store.Profiles) != 0 || !reflect.DeepEqual(a.profiles, beforeDelete) {
					t.Fatal("Delete changed linked private sources or retained the saved path", deleted.Code, err)
				}
			})
		}
	}
}

func TestDesktopOrderedOpenVPNPrefixFixedMTURefusesOverflow(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		for _, prefixes := range []int{5, 6} {
			t.Run(fmt.Sprintf("%s/%d", mode, prefixes), func(t *testing.T) {
				a, nodes := desktopOpenVPNPrefixCaptureFixture(t, prefixes, mode, "udp", "off")
				middle := &a.profiles.Profiles[prefixes]
				middle.ManualMTU = 1500
				middle.External.OpenVPN.Config = strings.Replace(middle.External.OpenVPN.Config, "tun-mtu 1280\n", "tun-mtu 1500\n", 1)
				before := cloneRouterProfileStore(a.profiles)
				_, err := captureDesktopNodeChain(context.Background(), clientRoot(a), a.profiles.Profiles[prefixes+1], a.profiles.Profiles, nodes, "local", nil)
				if err == nil || !strings.Contains(err.Error(), "fixed OpenVPN exit MTU does not fit its captured packet entry") || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("oversized fixed OpenVPN capacity was accepted, replaced or misdiagnosed", err)
				}
			})
		}
	}
}

func TestDesktopOrderedOpenVPNPrefixStartLayers(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				a, nodes := desktopOpenVPNPrefixCaptureFixture(t, 2, mode, "tcp", layer)
				capture := captureNodeChainTest(t, a, nodes)
				proofs := capture.chain.ProofInventory()
				for _, i := range []int{0, 1, 3} {
					if proofs[i].StartLayer != layer {
						t.Fatal("OpenVPN path lost the original paired Start Layer", i)
					}
				}
				if proofs[2].StartLayer != "off" || proofs[2].Mode != "openvpn" {
					t.Fatal("OpenVPN middle acquired another member's layer")
				}
			})
		}
	}
}
