package mobilemultihop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/hopmeasure"
)

func nodeChainImportedSSPrefixFixture(t *testing.T, count int, mode, method string, hostname bool) NodeChainSource {
	t.Helper()
	original := nodeChainImportedFixture(t, mode, "")
	if hostname {
		original = nodeChainHostnameFixture(t, mode, method)
	} else {
		var member nodeChainImportedInput
		if json.Unmarshal([]byte(original.Nodes[1]), &member) != nil {
			t.Fatal("original member missing")
		}
		graph, capture := externalTestRead(t, member.Config), externalTestRead(t, member.Capture)
		size := 32
		if method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{81}, size))
		out := externalTestFind(t, graph, ExternalFinalTag)
		ss := capture["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
		out["method"], out["password"], ss["method"], ss["password"] = method, key, method, key
		var err error
		original.Nodes[1], err = NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture))
		if err != nil {
			t.Fatal(err)
		}
	}
	if count == 1 {
		return original
	}
	source := nodeChainSOCKSPrefixFixture(t, count, mode, "", "password")
	source.Schema, source.Nodes[count] = 2, original.Nodes[1]
	return source
}

func TestNodeChainImportedSSCompletePacketPrefixes(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, form := range []string{"literal", "hostname"} {
			for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
				for count := 1; count <= 6; count++ {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", mode, form, method, count), func(t *testing.T) {
						source := nodeChainImportedSSPrefixFixture(t, count, mode, method, form == "hostname")
						chain, err := NewNodeChain(startJSON(t, source))
						if err != nil {
							t.Fatal(err)
						}
						if len(chain.proofs) != count+2 || len(chain.physical) != 1 || chain.importedMiddle.input != source.Nodes[count] || chain.nodes[count] != nil {
							t.Fatal("original imported inventory changed")
						}
						graph := externalTestRead(t, chain.Config())
						for i, proof := range chain.proofs {
							out := externalTestFind(t, graph, proof.Tag)
							if proof.Position != i || i > 0 && out["detour"] != chain.proofs[i-1].Tag {
								t.Fatal("original prefix bypassed", i)
							}
							if i < count && proof.Mode != mode {
								t.Fatal("paired prefix family changed", i)
							}
						}
						middle := externalTestFind(t, graph, chain.proofs[count].Tag)
						if middle["method"] != method || chain.dns.FinalTag != chain.proofs[count+1].Tag {
							t.Fatal("method or final DNS replaced")
						}
						tag, _, err := chain.PublicMeasurementCapture()
						if err != nil || tag != chain.proofs[count].Tag {
							t.Fatal("wrong public position", err)
						}
						if form == "hostname" {
							if chain.importedMiddle.policy != nil || middle["server"] != "middle.example.test" {
								t.Fatal("hostname acquired standalone authority")
							}
							query := middle["domain_resolver"].(map[string]any)
							matches := 0
							for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
								dns := raw.(map[string]any)
								if dns["tag"] == query["server"] {
									matches++
									if dns["type"] != "tcp" || dns["server"] != "10.81.0.53" || dns["server_port"] != float64(5353) || dns["detour"] != chain.proofs[count-1].Tag {
										t.Fatal("hostname resolver bypassed original last prefix", dns)
									}
								}
							}
							if matches != 1 || query["server"] == chain.dns.ResolverTag {
								t.Fatal("transport and application DNS conflated")
							}
						}
						plan, err := chain.MTUPlan()
						if err != nil || len(plan.Prefixes) != count+2 || plan.Ceiling < 1280 {
							t.Fatal("complete MTU envelope lost", err)
						}

						for _, refusedMTU := range []int{plan.Ceiling + 1, 1279} {
							candidate := externalTestRead(t, chain.Config())
							candidate["inbounds"].([]any)[0].(map[string]any)["mtu"] = refusedMTU
							if _, err := chain.PlanForMTU(startJSON(t, candidate), refusedMTU); err == nil {
								t.Fatal("captured SS MTU bounds weakened", refusedMTU)
							}
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
							replay, err := ParseNodeChainLaunchInput(launch)
							if err != nil || replay.Config() != projected.Config() || replay.Metadata() != projected.Metadata() {
								t.Fatal("captured projection/replay changed", target, err)
							}
						}
						for _, target := range []string{"linux", "windows", "darwin"} {
							policy, err := NewDesktopNodeChainPolicy(chain, strings.Repeat("a", 32), target, 1280)
							if err != nil {
								t.Fatal(target, err)
							}
							_, meta, physical, err := policy.ReadValidated()
							if err != nil || len(meta.Prefixes) != count+2 || len(physical.PhysicalRoots) != 1 || meta.NodeID != chain.proofs[count+1].NodeID {
								t.Fatal("original desktop policy lost", target, err)
							}
						}
					})
				}
			}
		}
	}
}

func TestNodeChainImportedSSPrefixOriginalPointers(t *testing.T) {
	for _, fault := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "whole", "policy", "hostname", "omitted", "reordered"} {
		t.Run(fault, func(t *testing.T) {
			chain, err := NewNodeChain(startJSON(t, nodeChainImportedSSPrefixFixture(t, 6, "wg", NativeStartLayerMethod, fault == "hostname")))
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "whole":
				chain = nodeChainOwnershipCopy(chain)
			case "policy":
				copy := *chain.importedMiddle.policy
				chain.importedMiddle.policy = &copy
			case "hostname":
				copy := *chain.importedMiddle.hostname
				chain.importedMiddle.hostname = &copy
			case "omitted":
				chain.nodes = append(chain.nodes[:2], chain.nodes[3:]...)
			case "reordered":
				chain.nodes[1], chain.nodes[3] = chain.nodes[3], chain.nodes[1]
			default:
				var position int
				fmt.Sscan(fault, &position)
				if position == 6 {
					copy := *chain.importedMiddle
					chain.importedMiddle = &copy
				} else {
					copy := *chain.nodes[position]
					chain.nodes[position] = &copy
				}
			}
			if chain.validateCapture() == nil {
				t.Fatal("equivalent foreign imported SS path owner accepted")
			}
		})
	}
}

func TestNodeChainImportedSSPrefixPurposeBoundary(t *testing.T) {
	// This original paired candidate is outside every tested packet prefix.
	// Reusing the three-node fixture's final identity would make the longer
	// cases fail on duplicate identity before exercising their purpose boundary.
	input, err := nodeChainFixtureNodes(t, 8, "")[7].LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	inventory := candidateInventoryFixture(t, "original-inventory", input)
	unpaired, _ := candidateSourceFixture(t, "external", NativeStartLayerMethod)
	unpairedInventory := candidateInventoryFixture(t, "unpaired-inventory", unpaired)
	for count := 1; count <= 6; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			source := nodeChainImportedSSPrefixFixture(t, count, "wg", NativeStartLayerMethod, false)
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			for _, purpose := range []string{"server", "auto"} {
				preparation, err := NewNodeChainExecutionPreparation(startJSON(t, source), purpose)
				if err != nil {
					t.Fatal("original literal imported prefix execution refused", purpose, count, err)
				}
				proofs := preparation.ProofInventory()
				if preparation.Execution() != purpose || preparation.LocalSource() != startJSON(t, source) || preparation.LocalSourceSHA256() != chain.SourceSHA256() ||
					len(proofs) != count+2 || !reflect.DeepEqual(proofs, chain.ProofInventory()) {
					t.Fatal("execution preparation lost original source or complete ordered proofs", purpose, count)
				}
				for position, proof := range proofs {
					if proof.Position != position || (proof.Kind == "public-path") != (position == count) || (proof.NodeID == "") != (position == count) {
						t.Fatal("execution preparation moved original public or private identity", purpose, count, position)
					}
				}
				hostname := nodeChainImportedSSPrefixFixture(t, count, "wg", NativeStartLayerMethod, true)
				hostnameJSON := startJSON(t, hostname)
				hostnameChain, err := NewNodeChain(hostnameJSON)
				if err != nil {
					t.Fatal("original hostname packet-prefix source refused", purpose, count, err)
				}
				hostnamePreparation, err := NewNodeChainExecutionPreparation(hostnameJSON, purpose)
				if count == 1 {
					if err == nil || hostnamePreparation != nil {
						t.Fatal("hostname without a retained Server packet prefix gained execution authority", purpose, count)
					}
				} else {
					if err != nil {
						t.Fatal("original hostname packet-prefix execution refused", purpose, count, err)
					}
					hostnameProofs := hostnamePreparation.ProofInventory()
					if hostnamePreparation.Execution() != purpose || hostnamePreparation.LocalSource() != hostnameJSON ||
						hostnamePreparation.LocalSourceSHA256() != hostnameChain.SourceSHA256() ||
						len(hostnameProofs) != count+2 || !reflect.DeepEqual(hostnameProofs, hostnameChain.ProofInventory()) ||
						hostnamePreparation.local.importedMiddle.input != hostname.Nodes[count] ||
						hostnamePreparation.local.importedMiddle.policy != nil || hostnamePreparation.importedPublic == nil ||
						!hostnamePreparation.importedPublic.current(hostnamePreparation) {
						t.Fatal("hostname execution lost its original source or complete ordered proof owner", purpose, count)
					}
					finalHost := predecessorText(hostnameChain.nodes[count+1].profile, "adguard_ipv4")
					nodeChainRequireHostnamePrefixDNS(t, hostnamePreparation.Config(), hostnameProofs[count].Tag, hostnameProofs[count-1].Tag, NativeStartLayerMethod, finalHost)
				}
				for _, fault := range []string{"implicit", "ambient", "udp", "resolver-hostname", "missing-port"} {
					// Each refusal keeps the original encrypted member and changes only
					// its captured DNS policy; no ambient resolver may fill the gap.
					var invalid NodeChainSource
					if json.Unmarshal([]byte(hostnameJSON), &invalid) != nil {
						t.Fatal("original hostname source missing")
					}
					var member nodeChainImportedInput
					if json.Unmarshal([]byte(invalid.Nodes[count]), &member) != nil {
						t.Fatal("original hostname import missing")
					}
					capture := externalTestRead(t, member.Capture)
					profile := capture["profile"].(map[string]any)
					switch fault {
					case "implicit":
						delete(profile, "dns_mode")
					case "ambient":
						profile["dns_mode"] = "home"
					case "udp":
						profile["dns_protocol"] = "udp"
					case "resolver-hostname":
						profile["dns_host"] = "unbound.example.test"
					case "missing-port":
						delete(profile, "dns_port")
					}
					member.Capture = startJSON(t, capture)
					invalid.Nodes[count] = startJSON(t, member)
					if invalidPreparation, err := NewNodeChainExecutionPreparation(startJSON(t, invalid), purpose); err == nil || invalidPreparation != nil {
						t.Fatal("hostname execution accepted implicit or invalid captured DNS", purpose, count, fault)
					}
				}
			}
			_, err = chain.NewCandidatePlan(0, inventory)
			if err != nil {
				t.Fatal("captured packet prefix lost connected candidate planning", count, err)
			}
			prepared, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
			if err != nil || prepared.OriginalSourceSHA256() != chain.SourceSHA256() ||
				prepared.PrefixPosition() != 0 || !reflect.DeepEqual(prepared.ProofInventory(), chain.proofs[:1]) {
				t.Fatal("closed packet-prefix preparation changed its original source", count, err)
			}
			response, err := chain.NewCandidatePlan(count, inventory)
			if err != nil || response.measurement != hopmeasure.CandidatePrivateResponseMeasurement || response.prefix != chain.proofs[count] ||
				len(response.responses) != 1 || chain.CandidatePrefixMeasurement(count-1) != hopmeasure.CandidateTCPMeasurement {
				t.Fatal("qualified original imported prefix lost its separate private-response metric", count, err)
			}
			closed, err := NewNodeChainCandidatePreparation(startJSON(t, source), count, inventory)
			if err != nil || closed.OriginalSourceSHA256() != chain.SourceSHA256() || closed.PrefixPosition() != count ||
				!reflect.DeepEqual(closed.ProofInventory(), chain.proofs[:count+1]) || len(closed.ImportedPrefixProofs()) != 1 ||
				len(closed.mtu.Prefixes) != count+1 || closed.candidates.measurement != hopmeasure.CandidatePrivateResponseMeasurement {
				t.Fatal("closed imported response lost its complete original prefix and MTU ownership", count, err)
			}
			graph, metadata := externalTestRead(t, closed.Config()), externalTestRead(t, closed.Metadata())
			if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || metadata["ready"] != false ||
				metadata["application_open"] != false || metadata["dns_open"] != false || strings.Contains(closed.Config(), chain.proofs[count+1].Tag) {
				t.Fatal("closed imported response opened ingress or constructed the saved final", count)
			}
			if value, err := chain.NewCandidatePlan(count, unpairedInventory); err == nil || value != nil {
				t.Fatal("unpaired imported target acquired authenticated response authority", count)
			}
			if value, err := NewNodeChainCandidatePreparation(startJSON(t, source), count, unpairedInventory); err == nil || value != nil {
				t.Fatal("unpaired imported target acquired closed response authority", count)
			}
			if value, err := chain.NewCandidatePlan(count+1, inventory); err == nil || value != nil {
				t.Fatal("saved final stream acquired candidate planning", count)
			}
			if value, err := NewNodeChainCandidatePreparation(startJSON(t, source), count+1, inventory); err == nil || value != nil {
				t.Fatal("saved final stream acquired closed candidate preparation", count)
			}
			replay, err := chain.LaunchInput()
			var replaySource NodeChainSource
			if err != nil || json.Unmarshal([]byte(replay), &replaySource) != nil || !reflect.DeepEqual(replaySource, source) {
				t.Fatal("source bytes or captured references changed", err)
			}
		})
	}
}

func TestNodeChainImportedSSPrefixSourceRefusals(t *testing.T) {
	for _, fault := range []string{"nine-nodes", "missing-prefix", "reordered-identities", "foreign-prefix-mode", "second-import", "middle-first", "middle-final", "middle-identity", "missing-final-identity", "legacy-method", "wrong-key-length", "changed-profile-key", "start-layer", "hostname-ambient", "hostname-udp", "hostname-resolver-hostname"} {
		t.Run(fault, func(t *testing.T) {
			source := nodeChainImportedSSPrefixFixture(t, 6, "wg", NativeStartLayerMethod, strings.HasPrefix(fault, "hostname-"))
			switch fault {
			case "nine-nodes":
				source.Nodes = append(source.Nodes[:1], append([]string{source.Nodes[0]}, source.Nodes[1:]...)...)
				source.IdentitySources = append(source.IdentitySources[:1], append([]string{source.IdentitySources[0]}, source.IdentitySources[1:]...)...)
			case "missing-prefix":
				source.Nodes = append(source.Nodes[:2], source.Nodes[3:]...)
			case "reordered-identities":
				source.IdentitySources[1], source.IdentitySources[3] = source.IdentitySources[3], source.IdentitySources[1]
			case "foreign-prefix-mode":
				source.Nodes[2] = source.Nodes[7]
				source.IdentitySources[2] = source.IdentitySources[7]
			case "second-import":
				source.Nodes[2] = source.Nodes[6]
				source.IdentitySources[2] = ""
			case "middle-first":
				source.Nodes[0], source.Nodes[6] = source.Nodes[6], source.Nodes[0]
				source.IdentitySources[0], source.IdentitySources[6] = source.IdentitySources[6], source.IdentitySources[0]
			case "middle-final":
				source.Nodes[7], source.Nodes[6] = source.Nodes[6], source.Nodes[7]
				source.IdentitySources[7], source.IdentitySources[6] = source.IdentitySources[6], source.IdentitySources[7]
			case "middle-identity":
				source.IdentitySources[6] = source.IdentitySources[0]
			case "missing-final-identity":
				source.IdentitySources[7] = ""
			default:
				var member nodeChainImportedInput
				if json.Unmarshal([]byte(source.Nodes[6]), &member) != nil {
					t.Fatal("original member absent")
				}
				graph, capture := externalTestRead(t, member.Config), externalTestRead(t, member.Capture)
				row := externalTestFind(t, graph, ExternalFinalTag)
				profile := capture["profile"].(map[string]any)
				ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
				switch fault {
				case "legacy-method":
					row["method"], ss["method"] = "aes-256-gcm", "aes-256-gcm"
				case "wrong-key-length":
					row["password"], ss["password"] = base64.StdEncoding.EncodeToString([]byte("short")), base64.StdEncoding.EncodeToString([]byte("short"))
				case "changed-profile-key":
					ss["password"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{95}, 32))
				case "start-layer":
					profile["start_layer"] = "aes-256-gcm"
				case "hostname-ambient":
					profile["dns_mode"] = "home"
				case "hostname-udp":
					profile["dns_protocol"] = "udp"
				case "hostname-resolver-hostname":
					profile["dns_host"] = "unbound.example.test"
				}
				member.Config, member.Capture = startJSON(t, graph), startJSON(t, capture)
				source.Nodes[6] = startJSON(t, member)
			}
			if _, err := NewNodeChain(startJSON(t, source)); err == nil {
				t.Fatal("malformed long imported SS source accepted", fault)
			}
		})
	}
}
