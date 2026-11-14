package mobilemultihop

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
)

func candidateCONNECTFixture(t *testing.T, protocol string) string {
	t.Helper()
	graph, capture := externalTestFixture(t, protocol, "")
	profile := capture["profile"].(map[string]any)
	profile["id"], capture["exit_id"] = "original-connect-candidate", "original-connect-candidate"
	input, err := NodeChainImportedCONNECTMemberInput(startJSON(t, graph), startJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func TestNodeChainCONNECTCandidateSealsOriginalTransport(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			t.Run(mode+"/"+protocol, func(t *testing.T) {
				nodes := nodeChainModeFixtureNodes(t, []string{mode, mode, "shadowsocks"}, []string{"", "", ""})
				chain, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes)))
				if err != nil {
					t.Fatal(err)
				}
				input := candidateCONNECTFixture(t, protocol)
				member, err := parseNodeChainCONNECTMember(input)
				if err != nil {
					t.Fatal(err)
				}
				closure, err := member.closure()
				if err != nil {
					t.Fatal(err)
				}
				expected := net.JoinHostPort(closure.final["server"].(string), strconv.Itoa(int(closure.final["server_port"].(float64))))
				beforeSource, beforeConfig := chain.SourceSHA256(), chain.Config()
				if !NodeChainCandidateInputSupported(input) {
					t.Fatal("original CONNECT candidate source rejected")
				}
				for _, position := range []int{0, 1} {
					inventory := candidateInventoryFixture(t, "original-connect-catalog", input)
					plan, err := chain.NewCandidatePlan(position, inventory)
					if err != nil {
						t.Fatal(err)
					}
					if plan.chain != chain || plan.prefix != chain.proofs[position] || len(plan.targets) != 1 || plan.targets[0].ID != member.selection.ExitID || plan.targets[0].SourceSHA256 != member.source || plan.targets[0].Address != expected {
						t.Fatal("CONNECT timing substituted original typed source or endpoint")
					}
					for _, secret := range []string{expected, predecessorText(closure.final, "username"), predecessorText(closure.final, "password")} {
						if secret != "" && strings.Contains(plan.Metadata(), secret) {
							t.Fatal("candidate metadata leaked private CONNECT source")
						}
					}
					record, graph, capture := nodeChainCONNECTRecord(t, input)
					out := externalTestFind(t, graph, ExternalFinalTag)
					transport := capture["profile"].(map[string]any)["external"].(map[string]any)[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)
					out["password"], transport["password"] = "changed-original-password", "changed-original-password"
					record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
					changed, err := chain.NewCandidatePlan(position, candidateInventoryFixture(t, "original-connect-catalog", startJSON(t, record)))
					if err != nil || changed.capture == plan.capture || changed.targets[0].SourceSHA256 == plan.targets[0].SourceSHA256 || changed.targets[0].Address != expected {
						t.Fatal("changed CONNECT credentials reused original capture", err)
					}
					plan.targets[0].Address = "127.0.0.1:80"
					if plan.validate() == nil || plan.Metadata() != "" {
						t.Fatal("mutated CONNECT target retained sealed authority")
					}
				}
				if chain.SourceSHA256() != beforeSource || chain.Config() != beforeConfig {
					t.Fatal("CONNECT candidate changed original path")
				}
				if _, err := chain.NewCandidatePlan(2, candidateInventoryFixture(t, "original-connect-catalog", input)); err == nil {
					t.Fatal("CONNECT candidate admitted lazy final prefix")
				}
				if _, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "original-connect-catalog", input, input)); err == nil {
					t.Fatal("duplicate CONNECT candidate admitted")
				}
				prep, err := NewNodeChainCandidatePreparation(chain.sourceJSON, 1, candidateInventoryFixture(t, "original-connect-catalog", input))
				if err != nil || !prep.AllowsDial(chain.proofs[1].Tag, expected) || prep.AllowsDial(chain.proofs[0].Tag, expected) {
					t.Fatal("closed preparation lost exact CONNECT target and prefix", err)
				}
			})
		}
	}
}

func TestNodeChainCONNECTCandidateKeepsTypedSourceRefusals(t *testing.T) {
	chain := nodeChainFixture(t, 3, "")
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, fault := range []string{"kind", "schema", "unknown-field", "hostname", "zero-port", "layer", "paired-identity", "foreign-entry", "endpoint-mismatch", "username-mismatch", "password-mismatch", "udp", "detour", "tls-mismatch"} {
			t.Run(protocol+"/"+fault, func(t *testing.T) {
				input := candidateCONNECTFixture(t, protocol)
				record, graph, capture := nodeChainCONNECTRecord(t, input)
				out := externalTestFind(t, graph, ExternalFinalTag)
				profile := capture["profile"].(map[string]any)
				transport := profile["external"].(map[string]any)[strings.ReplaceAll(protocol, "-", "_")].(map[string]any)
				switch fault {
				case "kind":
					record.Kind = "routervpn-node-chain-imported-member"
				case "schema":
					record.Schema = 2
				case "hostname":
					out["server"], transport["host"], profile["endpoint"] = "candidate.invalid", "candidate.invalid", "candidate.invalid"
				case "zero-port":
					out["server_port"], transport["port"] = 0, 0
				case "layer":
					profile["start_layer"] = "aes-256-gcm"
				case "paired-identity":
					profile["node_proof_id"] = strings.Repeat("a", 64)
				case "foreign-entry":
					capture["entry_tag"] = "borrowed-prefix"
				case "endpoint-mismatch":
					out["server"] = "192.0.2.99"
				case "username-mismatch":
					out["username"] = "changed-user"
				case "password-mismatch":
					out["password"] = "changed-secret"
				case "udp":
					out["udp_over_tcp"] = true
				case "detour":
					out["detour"] = "borrowed-prefix"
				case "tls-mismatch":
					out["tls"] = map[string]any{"enabled": true, "server_name": "another.invalid", "insecure": true}
				}
				record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
				input = startJSON(t, record)
				if fault == "unknown-field" {
					input = strings.TrimSuffix(input, "}") + `,"address":"127.0.0.1:80"}`
				}
				if NodeChainCandidateInputSupported(input) {
					t.Fatal("invalid CONNECT candidate input admitted")
				}
				if _, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "original-connect-catalog", input)); err == nil {
					t.Fatal("invalid CONNECT candidate acquired original prefix")
				}
				if _, err := NewNodeChainCandidatePreparation(chain.sourceJSON, 0, candidateInventoryFixture(t, "original-connect-catalog", input)); err == nil {
					t.Fatal("invalid CONNECT candidate acquired temporary preparation")
				}
			})
		}
	}
}

func TestNodeChainCONNECTCandidateRejectsDuplicatePrefixID(t *testing.T) {
	chain := nodeChainFixture(t, 3, "")
	input := candidateCONNECTFixture(t, "http-connect")
	record, graph, capture := nodeChainCONNECTRecord(t, input)
	capture["exit_id"], capture["profile"].(map[string]any)["id"] = chain.proofs[0].ProfileID, chain.proofs[0].ProfileID
	record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
	if !NodeChainCandidateInputSupported(startJSON(t, record)) {
		t.Fatal("fixture must be valid typed CONNECT input before prefix exclusion")
	}
	if _, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "original-connect-catalog", startJSON(t, record))); err == nil {
		t.Fatal("CONNECT candidate duplicated prefix identity")
	}
	// A host cannot provide a public target list instead of the original source.
	var metadata map[string]any
	if json.Unmarshal([]byte(chain.Metadata()), &metadata) != nil {
		t.Fatal("original metadata")
	}
	if NodeChainCandidateInputSupported(startJSON(t, metadata)) {
		t.Fatal("metadata substituted for original CONNECT source")
	}
}
