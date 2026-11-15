package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

func desktopImportedPrefixFixture(t *testing.T, prefixes int, mode, method string, keyBytes int, endpoint, layer string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, prefixes+2)
	// Use the explicit saved Home resolver. Profile Save canonically resolves
	// an empty Home host to this address; the CRUD oracle below compares the
	// original selected policy without treating that normalization as drift.
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].DNSHost = a.profiles.Profiles[i].AdGuardIPv4
	}
	modes := make([]string, len(nodes))
	for i := range modes {
		modes[i] = mode
	}
	modes[prefixes], modes[prefixes+1] = "wg", "shadowsocks"
	installOrderedAWGAssets(t, a, nodes, modes, layer)
	installDesktopOrderedImportedCipher(t, a, nodes, method, keyBytes)
	p := &a.profiles.Profiles[prefixes]
	p.Endpoint, p.External.Shadowsocks.Server = endpoint, endpoint
	p.HomeLANAccess, p.IPv6Mode, p.KillSwitchPolicy = false, "on", "always"
	if _, err := netip.ParseAddr(endpoint); err != nil {
		p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "custom", "tcp", "10.81.0.53", 5353
		p.DNSServerName, p.DNSPath = "", ""
	}
	if err := common.NormalizeRouterProfile(p); err != nil {
		t.Fatal(err)
	}
	return a, nodes
}

func TestDesktopOrderedImportedPacketPrefixes(t *testing.T) {
	methods := []struct {
		name string
		key  int
	}{{"2022-blake3-aes-128-gcm", 16}, {"2022-blake3-aes-256-gcm", 32}, {"2022-blake3-chacha20-poly1305", 32}}
	// The shared compiler exhaustively covers method/mode/form/length. These
	// integrated desktop cases cross each length with each paired mode while
	// rotating all three imported methods and IPv4/IPv6/hostname sources.
	endpoints := []string{"203.0.113.81", "2001:db8::81", "Middle.Example.Test"}
	for lengthIndex, prefixes := range []int{1, 2, 6} {
		for modeIndex, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			method := methods[(lengthIndex+modeIndex)%len(methods)]
			endpoint := endpoints[(2*lengthIndex+modeIndex)%len(endpoints)]
			t.Run(fmt.Sprintf("%s/%s/%d/%s", mode, method.name, prefixes, endpoint), func(t *testing.T) {
				a, nodes := desktopImportedPrefixFixture(t, prefixes, mode, method.name, method.key, endpoint, "off")
				original := cloneRouterProfileStore(a.profiles)
				final := original.Profiles[prefixes+1]
				lookups := 0
				capture, err := captureDesktopNodeChain(context.Background(), clientRoot(a), final, a.profiles.Profiles, nodes, "local", func(context.Context, string) ([]netip.Addr, error) {
					lookups++
					return nil, errors.New("ordinary-network bootstrap forbidden")
				})
				if err != nil || lookups != 0 || !reflect.DeepEqual(original, a.profiles) {
					t.Fatal("imported prefix capture changed private sources or used ambient DNS", err, lookups)
				}
				var source mobilemultihop.NodeChainSource
				proofs := capture.chain.ProofInventory()
				if json.Unmarshal([]byte(capture.input), &source) != nil || source.Schema != 2 || len(source.Nodes) != len(nodes) || len(source.IdentitySources) != len(nodes) || len(proofs) != len(nodes) {
					t.Fatal("SS capture lost schema two or complete member inventory")
				}
				for i, proof := range proofs {
					if proof.ProfileID != nodes[i].ID || proof.Mode != nodes[i].Mode {
						t.Fatal("imported path substituted a member or transport", i)
					}
					if i == prefixes {
						if proof.NodeID != "" || source.IdentitySources[i] != "" || proof.StartLayer != "off" {
							t.Fatal("imported SS borrowed paired identity or Start Layer")
						}
					} else if proof.NodeID != original.Profiles[i].NodeProofID || source.IdentitySources[i] == "" {
						t.Fatal("paired prefix lost its original private identity", i)
					}
				}
				for _, target := range []string{"linux", "windows", "darwin"} {
					policy, err := mobilemultihop.NewDesktopNodeChainPolicy(capture.chain, strings.Repeat("a", 32), target, 0)
					if err != nil {
						t.Fatal(target, err)
					}
					config, meta, physical, err := policy.ReadValidated()
					if err != nil || len(meta.Prefixes) != len(nodes) || meta.ProfileID != final.ID || meta.NodeID != final.NodeProofID || meta.FinalTag != proofs[prefixes+1].Tag || meta.KillSwitchPolicy != "always" || len(physical.PhysicalRoots) != 1 || physical.PhysicalRoots[0].Tag != proofs[0].Tag {
						t.Fatal("imported SS projection lost complete member policy or physical owner", target, err)
					}
					var graph map[string]any
					if json.Unmarshal([]byte(config), &graph) != nil {
						t.Fatal("missing actual native SS graph")
					}
					middle := desktopImportedGraphNode(t, graph, proofs[prefixes].Tag)
					if middle["type"] != "shadowsocks" || middle["server"] != endpoint || middle["method"] != method.name || middle["password"] != original.Profiles[prefixes].External.Shadowsocks.Password || middle["detour"] != proofs[prefixes-1].Tag {
						t.Fatal("SS transport bypassed last paired prefix or changed private source", target)
					}
					transportDNS, finalDNS := 0, 0
					query, hostname := middle["domain_resolver"].(map[string]any)
					for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
						dns := raw.(map[string]any)
						if hostname && dns["tag"] == query["server"] {
							transportDNS++
							if dns["type"] != "tcp" || dns["server"] != "10.81.0.53" || dns["server_port"] != float64(5353) || dns["detour"] != proofs[prefixes-1].Tag {
								t.Fatal("hostname DNS escaped saved resolver or last packet prefix")
							}
						}
						if dns["tag"] == capture.chain.DNSCapture().ResolverTag {
							finalDNS++
							if dns["server"] != final.AdGuardIPv4 || dns["type"] != "udp" || dns["detour"] != proofs[prefixes+1].Tag {
								t.Fatal("transport DNS replaced final Home AdGuard policy")
							}
						}
					}
					_, literalErr := netip.ParseAddr(endpoint)
					if finalDNS != 1 || literalErr != nil && (!hostname || transportDNS != 1) || literalErr == nil && transportDNS != 0 {
						t.Fatal("native graph lost separate exact transport and application DNS")
					}
					launch, err := policy.ReadValidatedLaunch()
					if err != nil {
						t.Fatal(err)
					}
					retained, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(launch.Input)
					if err != nil || retained.Config() != config {
						t.Fatal("native launch reopened a different complete imported path", target, err)
					}
				}
				for i := 0; i < prefixes; i++ {
					changed := cloneRouterProfileStore(original)
					changed.Profiles[i].APIToken += "-replacement"
					if capture.validate(context.Background(), final, changed.Profiles) == nil {
						t.Fatal("capture adopted a replacement original prefix", i)
					}
				}
			})
		}
	}
}

func TestDesktopOrderedImportedPrefixSavedAndMeasuredPositions(t *testing.T) {
	for _, prefixes := range []int{2, 6} {
		for _, endpoint := range []string{"203.0.113.81", "Middle.Example.Test"} {
			t.Run(fmt.Sprintf("%d/%s", prefixes, endpoint), func(t *testing.T) {
				a, nodes := desktopImportedPrefixFixture(t, prefixes, "wg", "2022-blake3-aes-256-gcm", 32, endpoint, "off")
				desktopCONNECTSelectPublicHandler(t, a) // Actual dispatcher; installed native boundary remains explicit.
				original := cloneRouterProfileStore(a.profiles)
				id := saveOrderedConnectionFixture(t, a, nodes)
				store, err := loadConnectionProfileStore(a)
				if err != nil || len(store.Profiles) != 1 || len(store.Profiles[0].NodeChain) != len(nodes) || validateSavedNodeChain(store.Profiles[0]) != nil {
					t.Fatal("saved SS path lost complete original members", err)
				}
				raw, err := os.ReadFile(connectionProfileStorePath(a))
				if err != nil || strings.Contains(string(raw), original.Profiles[prefixes].External.Shadowsocks.Password) || strings.Contains(string(raw), "private-api-") {
					t.Fatal("saved SS profile copied private credentials", err)
				}
				updated := postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": id, "name": "Updated original SS path", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": "local", "multihop_nodes": nodes})
				if updated.Code != http.StatusOK {
					t.Fatal("SS profile Update failed", updated.Code, updated.Body.String())
				}
				for i := range a.profiles.Profiles {
					a.profiles.Profiles[i].DNSPort, a.profiles.Profiles[i].ManualMTU = 5354, 1400
				}
				loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
				if loaded.Code != http.StatusOK || a.state.Connected || a.cmd != nil {
					t.Fatal("SS profile Load did not restore disconnected original sources", loaded.Code, loaded.Body.String())
				}
				for i, p := range a.profiles.Profiles {
					before := original.Profiles[i]
					if p.DNSPort != before.DNSPort || p.DNSHost != before.DNSHost || p.DNSProtocol != before.DNSProtocol || p.ManualMTU != before.ManualMTU || p.APIToken != before.APIToken || p.NodeProofID != before.NodeProofID || !reflect.DeepEqual(p.External, before.External) {
						t.Fatal("SS profile Load substituted original policy or private credentials", i)
					}
				}
				final := a.profiles.Profiles[prefixes+1]
				capture, err := captureStartupNodeChain(a, final, a.profiles.Profiles, nil)
				if err != nil {
					t.Fatal(err)
				}
				last := startupSelection{Base: capture.selection.Base, ProfileToken: startupExternalProfileToken(final), RouterID: final.ID, RuntimeMode: "shadowsocks", LogicalMode: "multihop", UpdatedAt: time.Now().UTC(), NodeChain: capture.receipt(), PathKind: startupNodeChainPathKind}
				if validateStartupNodeChainSelection(last) != nil || last.NodeChain.Schema != 2 || last.NodeChain.Nodes[prefixes].NodeKind != "external" || last.NodeChain.Nodes[1].NodeKind == "external" {
					t.Fatal("Last SS receipt lost exact dynamic penultimate")
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
				if err != nil || len(rows) != len(nodes) || !strings.Contains(rows[prefixes].Speed.Proof, "public benchmark") || strings.Contains(rows[prefixes].Speed.Proof, "authenticated bytes") {
					t.Fatal("SS measurement mislabeled captured public position", err)
				}
				status.Results[prefixes].Kind = "private-node"
				if _, err := desktopNodeChainMeasurementRows(status, capture.selection.Nodes, 65536); err == nil {
					t.Fatal("imported SS measurement borrowed paired proof")
				}
				for _, fault := range []string{"position", "missing-source", "foreign-family", "server", "auto"} {
					raw, _ := json.Marshal(last)
					var changed startupSelection
					if json.Unmarshal(raw, &changed) != nil {
						t.Fatal("SS receipt did not round trip")
					}
					switch fault {
					case "position":
						changed.NodeChain.Nodes[1], changed.NodeChain.Nodes[prefixes] = changed.NodeChain.Nodes[prefixes], changed.NodeChain.Nodes[1]
					case "missing-source":
						changed.NodeChain.Nodes[prefixes].Sources = nil
					case "foreign-family":
						changed.NodeChain.Schema = 5
					case "server", "auto":
						changed.NodeChain.Execution = fault
					}
					if validateStartupNodeChainSelection(changed) == nil {
						t.Fatal("SS Last accepted changed authority", fault)
					}
				}
				for _, execution := range []string{"server", "auto"} {
					if _, err := captureDesktopNodeChain(context.Background(), clientRoot(a), final, a.profiles.Profiles, nodes, execution, nil); err == nil {
						t.Fatal("long SS capture acquired unsupported desktop execution", execution)
					}
				}
				a.profiles.Profiles[prefixes].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
				beforeFailedLoad := cloneRouterProfileStore(a.profiles)
				if response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id}); response.Code == http.StatusOK || !reflect.DeepEqual(beforeFailedLoad, a.profiles) {
					t.Fatal("saved SS path adopted replaced credential or partially changed members")
				}
				deleted := postSetup(t, a, "/api/connection-profile/setup/delete", map[string]any{"id": id})
				store, err = loadConnectionProfileStore(a)
				if deleted.Code != http.StatusOK || err != nil || len(store.Profiles) != 0 || !reflect.DeepEqual(beforeFailedLoad, a.profiles) {
					t.Fatal("SS profile Delete changed original linked sources", err)
				}
			})
		}
	}
}

func TestDesktopOrderedImportedPrefixStartLayers(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				a, nodes := desktopImportedPrefixFixture(t, 2, mode, "2022-blake3-aes-256-gcm", 32, "203.0.113.81", layer)
				capture := captureNodeChainTest(t, a, nodes)
				for i, proof := range capture.chain.ProofInventory() {
					want := layer
					if i == 2 {
						want = "off"
					}
					if proof.StartLayer != want {
						t.Fatal("imported SS path changed original independent layer", i)
					}
				}
			})
		}
	}
}
