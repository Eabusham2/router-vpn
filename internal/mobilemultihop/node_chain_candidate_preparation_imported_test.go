package mobilemultihop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func candidatePreparationImportedSource(t *testing.T, count int, mode, method string, hostname bool) (NodeChainSource, string) {
	t.Helper()
	source := nodeChainImportedSSPrefixFixture(t, count, mode, method, hostname)
	// Keep this saved SS fixture credential distinct from every original
	// packet peer key. The general hostname fixture's repeated 'h' key also
	// equals packet node 3's PSK, which cannot prove SS credential absence.
	var member nodeChainImportedInput
	if err := json.Unmarshal([]byte(source.Nodes[count]), &member); err != nil {
		t.Fatal(err)
	}
	graph, capture := externalTestRead(t, member.Config), externalTestRead(t, member.Capture)
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{225}, size))
	externalTestFind(t, graph, ExternalFinalTag)["password"] = key
	capture["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)["password"] = key
	var err error
	source.Nodes[count], err = NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture))
	if err != nil {
		t.Fatal("independent saved imported credential rejected", err)
	}
	target, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	return source, candidateInventoryFixture(t, "original-imported-ss-candidate-catalog", target)
}

func TestNodeChainCandidatePreparationImportedSSKeepsOnlyPacketPrefixes(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, hostname := range []bool{false, true} {
			for index, count := range []int{1, 2, 6} {
				method := []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}[index]
				t.Run(fmt.Sprintf("%s/hostname-%t/%d", mode, hostname, count+2), func(t *testing.T) {
					source, inventory := candidatePreparationImportedSource(t, count, mode, method, hostname)
					for position := 0; position < count; position++ {
						p, err := NewNodeChainCandidatePreparation(startJSON(t, source), position, inventory)
						if err != nil {
							t.Fatal("saved imported SS suffix prevented independent packet prefix", err)
						}
						graph, saved := externalTestRead(t, p.Config()), externalTestRead(t, p.original.Config())
						if !reflect.DeepEqual(graph["inbounds"], saved["inbounds"]) || !reflect.DeepEqual(graph["route"].(map[string]any)["rules"], saved["route"].(map[string]any)["rules"]) {
							t.Fatal("saved imported path device protections changed")
						}
						if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || !reflect.DeepEqual(p.proofs, p.original.proofs[:position+1]) {
							t.Fatal("imported prefix preparation changed proof membership or opened application ingress")
						}
						for _, proof := range p.original.proofs[position+1:] {
							if strings.Contains(p.Config(), proof.Tag) {
								t.Fatal("unselected imported suffix acquired runnable authority", proof.Position)
							}
						}
						middle, err := p.original.importedMiddle.closure()
						if err != nil || strings.Contains(p.Config(), predecessorText(middle.final, "server")) || strings.Contains(p.Config(), predecessorText(middle.final, "password")) {
							t.Fatal("saved imported transport or its resolver became a prefix dependency", err)
						}
						if hostname {
							// A paired prefix may use the same resolver address. The
							// imported dependency belongs to its captured namespaced
							// transport tag, which must not enter this prepared graph.
							fullMiddle := externalTestFind(t, saved, p.original.proofs[count].Tag)
							query, ok := fullMiddle["domain_resolver"].(map[string]any)
							resolver := predecessorText(query, "server")
							if !ok || resolver == "" || strings.Contains(p.Config(), resolver) {
								t.Fatal("saved imported resolver owner entered packet prefix preparation")
							}
						}
						metadata := externalTestRead(t, p.Metadata())
						if metadata["ready"] != false || metadata["application_open"] != false || metadata["dns_open"] != false || metadata["mtu_measurement"] != "configured-bounds-only" {
							t.Fatal("imported source preparation fabricated live traffic authority")
						}
						physical, err := p.PhysicalEgress()
						if err != nil || !nodeChainSamePhysical(physical, p.original.physical) {
							t.Fatal("imported saved path physical egress changed", err)
						}
						mtu, err := p.MTUPlan()
						if err != nil || len(mtu.Prefixes) != position+1 || mtu.Original > mtu.Ceiling {
							t.Fatal("imported prefix configured MTU lost original membership", err)
						}
						replay, err := ParseNodeChainCandidatePreparation(p.Source())
						if err != nil || replay.Config() != p.Config() || replay.CaptureSHA256() != p.CaptureSHA256() || replay.OriginalSourceSHA256() != p.original.SourceSHA256() {
							t.Fatal("imported prefix private source did not round trip", err)
						}
					}
					for _, position := range []int{-1, count, count + 1, count + 2} {
						if _, err := NewNodeChainCandidatePreparation(startJSON(t, source), position, inventory); err == nil {
							t.Fatal("imported middle, final or foreign position became a packet prefix", position)
						}
					}
				})
			}
		}
	}
}

func TestNodeChainCandidatePreparationImportedSSProvenanceAndOwners(t *testing.T) {
	for _, hostname := range []bool{false, true} {
		t.Run(fmt.Sprintf("hostname-%t", hostname), func(t *testing.T) {
			source, inventory := candidatePreparationImportedSource(t, 2, "wg", "2022-blake3-aes-128-gcm", hostname)
			original, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
			if err != nil {
				t.Fatal(err)
			}
			other, _ := candidatePreparationImportedSource(t, 2, "wg", "2022-blake3-aes-256-gcm", hostname)
			// Only the uncontacted imported source changes. Paired credentials,
			// device policy and final Save source remain the exact originals.
			source.Nodes[2] = other.Nodes[2]
			changed, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
			if err != nil {
				t.Fatal(err)
			}
			if changed.Config() != original.Config() || changed.SourceSHA256() == original.SourceSHA256() || changed.CaptureSHA256() == original.CaptureSHA256() || changed.OriginalSourceSHA256() == original.OriginalSourceSHA256() {
				t.Fatal("uncontacted imported provenance was ignored or became executable")
			}
			if hostname && NodeChainCandidateInputSupported(source.Nodes[2]) {
				t.Fatal("saved hostname imported source bypassed exact literal candidate eligibility")
			}
			for _, fault := range []string{"middle-copy", "owner-copy", "prefix-copy", "middle-input", "proof"} {
				p, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "middle-copy":
					copied := *p.original.importedMiddle
					p.original.importedMiddle = &copied
				case "owner-copy":
					copied := *p.original.importedOwners
					p.original.importedOwners = &copied
				case "prefix-copy":
					copied := *p.original.nodes[1]
					p.original.nodes[1] = &copied
				case "middle-input":
					p.original.importedMiddle.input += " "
				case "proof":
					p.original.proofs[2].SourceSHA256 = strings.Repeat("f", 64)
				}
				if p.Config() != "" || p.Source() != "" || p.Metadata() != "" {
					t.Fatal("changed saved imported capture retained prefix authority", fault)
				}
			}
			malformed := source
			malformed.Nodes = append([]string(nil), source.Nodes...)
			malformed.IdentitySources = append([]string(nil), source.IdentitySources...)
			malformed.IdentitySources[1] = malformed.IdentitySources[0]
			if _, err := NewNodeChainCandidatePreparation(startJSON(t, malformed), 0, inventory); err == nil {
				t.Fatal("unselected invalid paired identity escaped complete source validation")
			}
		})
	}
}

func TestNodeChainCandidatePreparationIdentityReadIsFresh(t *testing.T) {
	source, inventory := candidatePreparationImportedSource(t, 2, "wg", "2022-blake3-aes-256-gcm", true)
	input := startJSON(t, source)
	for _, fault := range []string{"nil", "original-nil", "candidates-nil", "candidate-chain-nil", "candidate-substitution", "original-member", "original-source", "original-config", "unselected-proof", "candidate-target", "candidate-seal", "source-hash", "config-hash", "prepared-config", "prepared-seal", "prepared-proof", "prepared-mtu"} {
		t.Run(fault, func(t *testing.T) {
			p, err := NewNodeChainCandidatePreparation(input, 1, inventory)
			if err != nil {
				t.Fatal(err)
			}
			originalSource, originalConfig, err := p.ReadIdentityValidated()
			if err != nil || originalSource == "" || originalConfig == "" || originalSource != p.SourceSHA256() || originalConfig != p.ConfigSHA256() {
				t.Fatal("fresh preparation identity changed its original hashes", err)
			}
			switch fault {
			case "nil":
				p = nil
			case "original-nil":
				p.original = nil
			case "candidates-nil":
				p.candidates = nil
			case "candidate-chain-nil":
				p.candidates.chain = nil
			case "candidate-substitution":
				other, err := NewNodeChainCandidatePreparation(input, 1, inventory)
				if err != nil || other.candidates.validate() != nil || other.candidates.seal != p.candidates.seal || other.original == p.original {
					t.Fatal("independent equal-valued candidate fixture is invalid", err)
				}
				p.candidates = other.candidates
			case "original-member":
				copied := *p.original.nodes[0]
				p.original.nodes[0] = &copied
			case "original-source":
				p.original.sourceJSON += " "
			case "original-config":
				p.original.config += " "
			case "unselected-proof":
				p.original.proofs[len(p.original.proofs)-1].SourceSHA256 = strings.Repeat("f", 64)
			case "candidate-target":
				p.candidates.targets[0].Address = "192.0.2.99:443"
			case "candidate-seal":
				p.candidates.seal = "changed"
			case "source-hash":
				p.sourceSHA = strings.Repeat("a", 64)
			case "config-hash":
				p.configSHA = strings.Repeat("b", 64)
			case "prepared-config":
				p.config += " "
			case "prepared-seal":
				p.seal = "changed"
			case "prepared-proof":
				p.proofs[0].Tag = "other"
			case "prepared-mtu":
				p.mtu.Prefixes[0].Ceiling--
			}
			gotSource, gotConfig, err := p.ReadIdentityValidated()
			if err == nil || gotSource != "" || gotConfig != "" {
				t.Fatal("changed preparation retained grouped identity or disclosed a partial result", fault, err)
			}
		})
	}
}

func TestNodeChainCandidatePreparationImportedSSRuntimeFiftyAndRetirement(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, hostname := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/hostname-%t", mode, hostname), func(t *testing.T) {
				source, inventory := candidatePreparationImportedSource(t, 6, mode, "2022-blake3-aes-256-gcm", hostname)
				p, err := NewNodeChainCandidatePreparation(startJSON(t, source), 5, inventory)
				if err != nil {
					t.Fatal(err)
				}
				runtime, owner := candidatePreparationRuntimeFromSource(t, p)
				if err := runtime.StartContext(t.Context()); err != nil {
					t.Fatal("unreachable saved imported SS prevented packet prefix proofs", err)
				}
				progress := runtime.Progress()
				if !progress.Prepared || progress.ApplicationOpen || progress.DNSOpen || len(progress.Prefixes) != 6 {
					t.Fatal("prepared imported prefix became a complete connection", progress)
				}
				measurement, err := runtime.NewMeasurementContext(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer measurement.Close()
				request := strings.Repeat("e", 32)
				deadline := time.Now().Add(hopmeasure.RequestTimeout)
				if err := measurement.Start(request, p.candidates.targets[0].ID); err != nil {
					t.Fatal(err)
				}
				for {
					if err := measurement.Drain(request); err == nil {
						break
					}
					if !time.Now().Before(deadline) {
						t.Fatal("original imported prefix fifty exceeded its request budget", measurement.StatusJSON())
					}
				}
				status := candidateStatus(t, measurement)
				if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || owner.count.Load() != 50 || status.PrefixPosition != 5 || status.Measurement != "routed-tcp-connect" {
					t.Fatal("imported packet prefix lost actual fifty TCP connections", status, owner.count.Load())
				}
				if owner.lease.active.Load() || owner.lease.released.Load() != 1 {
					t.Fatal("imported prefix measurement lost its original retirement hold")
				}
				if err := runtime.CloseContext(context.Background()); err != nil {
					t.Fatal(err)
				}
				base := owner.nodeChainTestEngine
				base.mu.Lock()
				calls, dns := append([]string(nil), base.calls...), base.dnsCalls
				base.mu.Unlock()
				if len(calls) < len(p.proofs) || dns != 0 || owner.lease.active.Load() || owner.lease.released.Load() != 1 {
					t.Fatal("imported prefix work reached suffix/DNS or lost its hold", calls, dns)
				}
				for i, tag := range calls {
					if tag != p.proofs[i%len(p.proofs)].Tag {
						t.Fatal("imported prefix re-proof contacted foreign or reordered source", calls)
					}
				}
				if runtime.Progress().Prepared || runtime.HealthyContext(t.Context()) == nil {
					t.Fatal("retired imported prefix retained authority")
				}
			})
		}
	}
}
