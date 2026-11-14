package mobilemultihop

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
)

func candidateSOCKSFixture(t *testing.T, authentication string) string {
	t.Helper()
	graph, capture := externalTestFixture(t, "socks5", "")
	profile := capture["profile"].(map[string]any)
	profile["id"], capture["exit_id"] = "original-socks-candidate", "original-socks-candidate"
	if authentication == "none" {
		out := externalTestFind(t, graph, ExternalFinalTag)
		transport := profile["external"].(map[string]any)["socks5"].(map[string]any)
		delete(out, "username")
		delete(out, "password")
		delete(transport, "username")
		delete(transport, "password")
	}
	input, err := NodeChainImportedSOCKSMemberInput(startJSON(t, graph), startJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func TestNodeChainSOCKSCandidateSealsOriginalTransport(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, authentication := range []string{"password", "none"} {
			t.Run(mode+"/"+authentication, func(t *testing.T) {
				nodes := nodeChainModeFixtureNodes(t, []string{mode, mode, "shadowsocks"}, []string{"", "", ""})
				chain, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes)))
				if err != nil {
					t.Fatal(err)
				}
				input := candidateSOCKSFixture(t, authentication)
				member, err := parseNodeChainSOCKSMember(input)
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
					t.Fatal("original SOCKS candidate source rejected")
				}
				for _, position := range []int{0, 1} {
					inventory := candidateInventoryFixture(t, "original-socks-catalog", input)
					plan, err := chain.NewCandidatePlan(position, inventory)
					if err != nil {
						t.Fatal(err)
					}
					if plan.chain != chain || plan.prefix != chain.proofs[position] || len(plan.targets) != 1 || plan.targets[0].ID != member.selection.ExitID || plan.targets[0].SourceSHA256 != member.source || plan.targets[0].Address != expected {
						t.Fatal("SOCKS timing substituted original typed source or endpoint")
					}
					for _, secret := range []string{expected, predecessorText(closure.final, "username"), predecessorText(closure.final, "password")} {
						if secret != "" && strings.Contains(plan.Metadata(), secret) {
							t.Fatal("candidate metadata leaked private SOCKS source")
						}
					}
					record, graph, capture := nodeChainSOCKSRecord(t, input)
					out := externalTestFind(t, graph, ExternalFinalTag)
					transport := capture["profile"].(map[string]any)["external"].(map[string]any)["socks5"].(map[string]any)
					out["username"], transport["username"] = "changed-user", "changed-user"
					out["password"], transport["password"] = "changed-original-password", "changed-original-password"
					record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
					changed, err := chain.NewCandidatePlan(position, candidateInventoryFixture(t, "original-socks-catalog", startJSON(t, record)))
					if err != nil || changed.capture == plan.capture || changed.targets[0].SourceSHA256 == plan.targets[0].SourceSHA256 || changed.targets[0].Address != expected {
						t.Fatal("changed SOCKS credentials reused original capture", err)
					}
					plan.targets[0].Address = "127.0.0.1:80"
					if plan.validate() == nil || plan.Metadata() != "" {
						t.Fatal("mutated SOCKS target retained sealed authority")
					}
				}
				if chain.SourceSHA256() != beforeSource || chain.Config() != beforeConfig {
					t.Fatal("SOCKS candidate changed original path")
				}
				if _, err := chain.NewCandidatePlan(2, candidateInventoryFixture(t, "original-socks-catalog", input)); err == nil {
					t.Fatal("SOCKS candidate admitted lazy final prefix")
				}
				if _, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "original-socks-catalog", input, input)); err == nil {
					t.Fatal("duplicate SOCKS candidate admitted")
				}
				prep, err := NewNodeChainCandidatePreparation(chain.sourceJSON, 1, candidateInventoryFixture(t, "original-socks-catalog", input))
				if err != nil || !prep.AllowsDial(chain.proofs[1].Tag, expected) || prep.AllowsDial(chain.proofs[0].Tag, expected) {
					t.Fatal("closed preparation lost exact SOCKS target and prefix", err)
				}
			})
		}
	}
}

func TestNodeChainSOCKSCandidateKeepsTypedSourceRefusals(t *testing.T) {
	chain := nodeChainFixture(t, 3, "")
	for _, authentication := range []string{"password", "none"} {
		for _, fault := range []string{"kind", "schema", "unknown-field", "hostname", "zero-port", "layer", "paired-identity", "foreign-entry", "endpoint-mismatch", "username-mismatch", "password-mismatch", "udp", "detour", "version", "network", "credential-pair", "credential-bound", "unknown-transport"} {
			t.Run(authentication+"/"+fault, func(t *testing.T) {
				input := candidateSOCKSFixture(t, authentication)
				record, graph, capture := nodeChainSOCKSRecord(t, input)
				out := externalTestFind(t, graph, ExternalFinalTag)
				profile := capture["profile"].(map[string]any)
				transport := profile["external"].(map[string]any)["socks5"].(map[string]any)
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
				case "version":
					out["version"] = "4"
				case "network":
					out["network"] = "udp"
				case "credential-pair":
					out["username"], transport["username"] = "unpaired-user", "unpaired-user"
					delete(out, "password")
					delete(transport, "password")
				case "credential-bound":
					out["username"], transport["username"] = strings.Repeat("u", 256), strings.Repeat("u", 256)
					out["password"], transport["password"] = "secret", "secret"
				case "unknown-transport":
					capture["protocol"] = "hysteria2"
				}
				record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
				input = startJSON(t, record)
				if fault == "unknown-field" {
					input = strings.TrimSuffix(input, "}") + `,"address":"127.0.0.1:80"}`
				}
				if NodeChainCandidateInputSupported(input) {
					t.Fatal("invalid SOCKS candidate input admitted")
				}
				if _, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "original-socks-catalog", input)); err == nil {
					t.Fatal("invalid SOCKS candidate acquired original prefix")
				}
				if _, err := NewNodeChainCandidatePreparation(chain.sourceJSON, 0, candidateInventoryFixture(t, "original-socks-catalog", input)); err == nil {
					t.Fatal("invalid SOCKS candidate acquired temporary preparation")
				}
			})
		}
	}
}

func TestNodeChainSOCKSCandidateRejectsDuplicatePrefixID(t *testing.T) {
	chain := nodeChainFixture(t, 3, "")
	input := candidateSOCKSFixture(t, "password")
	record, graph, capture := nodeChainSOCKSRecord(t, input)
	capture["exit_id"], capture["profile"].(map[string]any)["id"] = chain.proofs[0].ProfileID, chain.proofs[0].ProfileID
	record.Config, record.Capture = startJSON(t, graph), startJSON(t, capture)
	if !NodeChainCandidateInputSupported(startJSON(t, record)) {
		t.Fatal("fixture must be valid typed SOCKS input before prefix exclusion")
	}
	if _, err := chain.NewCandidatePlan(0, candidateInventoryFixture(t, "original-socks-catalog", startJSON(t, record))); err == nil {
		t.Fatal("SOCKS candidate duplicated prefix identity")
	}
	// A host cannot provide a public target list instead of the original source.
	var metadata map[string]any
	if json.Unmarshal([]byte(chain.Metadata()), &metadata) != nil {
		t.Fatal("original metadata")
	}
	if NodeChainCandidateInputSupported(startJSON(t, metadata)) {
		t.Fatal("metadata substituted for original SOCKS source")
	}
}
