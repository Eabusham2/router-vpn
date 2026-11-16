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

func candidateSuffixInventory(t *testing.T) string {
	t.Helper()
	target, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	return candidateInventoryFixture(t, "captured-suffix-catalog", target)
}

func assertCandidateSuffixExcluded(t *testing.T, p *NodeChainCandidatePreparation, original *NodeChain, position int) {
	t.Helper()
	if p.validate() != nil || p.original != original || p.candidates.chain != original || p.position != position ||
		!reflect.DeepEqual(p.proofs, original.proofs[:position+1]) || !nodeChainSamePhysical(p.physical, original.physical) {
		t.Fatal("closed prefix lost its exact complete source owner")
	}
	graph, saved := externalTestRead(t, p.Config()), externalTestRead(t, original.Config())
	if !reflect.DeepEqual(graph["inbounds"], saved["inbounds"]) ||
		!reflect.DeepEqual(graph["route"].(map[string]any)["rules"], saved["route"].(map[string]any)["rules"]) ||
		graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
		t.Fatal("saved prefix changed its original TUN, protection or closed ingress")
	}
	for i, proof := range original.proofs {
		if i <= position {
			if externalTestFind(t, graph, proof.Tag)["type"] != nodeChainPrefixType(proof.Mode) {
				t.Fatal("selected original packet member was not constructed", i)
			}
		} else if strings.Contains(p.Config(), proof.Tag) {
			t.Fatal("unselected saved suffix acquired native construction", i)
		}
		if node := original.nodes[i]; node != nil {
			api := predecessorText(node.profile, "router_api")
			token := predecessorText(node.profile, "api_token")
			if strings.Contains(p.Metadata(), api) || strings.Contains(p.Metadata(), token) {
				t.Fatal("candidate metadata leaked original private proof")
			}
		}
	}
	if p.AllowsDial(original.proofs[len(original.proofs)-1].Tag, "1.1.1.1:443") ||
		p.AllowsDial(p.proofs[position].Tag, "1.1.1.1:443") {
		t.Fatal("prefix gained saved final or arbitrary public dial authority")
	}
	meta := externalTestRead(t, p.Metadata())
	if meta["application_open"] != false || meta["dns_open"] != false || meta["ready"] != false {
		t.Fatal("source-only preparation published connection authority")
	}
}

func TestNodeChainCandidatePreparationImportedSavedPrefixes(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for count := 1; count <= 6; count++ {
			t.Run(fmt.Sprintf("%s/%d", mode, count), func(t *testing.T) {
				source := nodeChainImportedSSPrefixFixture(t, count, mode, NativeStartLayerMethod, count%2 == 0)
				input, inventory := startJSON(t, source), candidateSuffixInventory(t)
				for position := 0; position < count; position++ {
					p, err := NewNodeChainCandidatePreparation(input, position, inventory)
					if err != nil {
						t.Fatal("captured longer SS suffix blocked selected packet prefix", position, err)
					}
					assertCandidateSuffixExcluded(t, p, p.original, position)
					if p.original.sourceJSON != input {
						t.Fatal("generic prefix changed complete saved source family")
					}
					replay, err := ParseNodeChainCandidatePreparation(p.Source())
					if err != nil || replay.Config() != p.Config() || replay.CaptureSHA256() != p.CaptureSHA256() {
						t.Fatal("generic prefix replay replaced its captured graph", err)
					}
					connected, err := p.original.NewCandidatePlan(position, inventory)
					if err != nil || connected.chain != p.original || connected.prefix != p.original.proofs[position] {
						t.Fatal("connected planning lost complete original source", err)
					}
					owner := &candidateOwnerFixture{nodeChainMeasurementFixture: nodeChainMeasurementFixture{chain: p.original}, capture: connected.capture}
					if service, err := connected.NewMeasurementContext(t.Context(), owner); err == nil || service != nil {
						t.Fatal("closed prefix provenance acquired an unproved complete path")
					}
				}
				for _, position := range []int{count, count + 1} {
					if _, err := NewNodeChainCandidatePreparation(input, position, inventory); err == nil {
						t.Fatal("lazy imported/final stream acquired packet timing", position)
					}
				}
			})
		}
	}
}

func TestNodeChainCandidatePreparationImportedSuffixKeepsProvenance(t *testing.T) {
	source := nodeChainImportedSSPrefixFixture(t, 2, "wg", NativeStartLayerMethod, true)
	inventory := candidateSuffixInventory(t)
	original, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the original complete-path protection and DNS policies. Replacing a
	// literal helper with a hostname helper would also change kill/LAN/IPv6
	// settings, which the closed prefix must preserve rather than discard.
	var imported nodeChainImportedInput
	if json.Unmarshal([]byte(source.Nodes[2]), &imported) != nil {
		t.Fatal("missing original imported source")
	}
	graph, capture := externalTestRead(t, imported.Config), externalTestRead(t, imported.Capture)
	profile := capture["profile"].(map[string]any)
	transport := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
	outbound := externalTestFind(t, graph, ExternalFinalTag)
	endpoint := "changed-middle.example.test"
	credential := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	profile["endpoint"], transport["server"], outbound["server"] = endpoint, endpoint, endpoint
	transport["password"], outbound["password"] = credential, credential
	source.Nodes[2], err = NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, capture))
	if err != nil {
		t.Fatal("changed original imported source", err)
	}
	changed, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Config() != original.Config() || changed.SourceSHA256() == original.SourceSHA256() || changed.CaptureSHA256() == original.CaptureSHA256() || changed.OriginalSourceSHA256() == original.OriginalSourceSHA256() {
		t.Fatal("uncontacted imported source lost provenance or entered runnable prefix")
	}
	if strings.Contains(changed.Config(), endpoint) || strings.Contains(changed.Config(), credential) {
		t.Fatal("uncontacted imported endpoint or credential entered runnable prefix")
	}
	copy := *changed.original.importedMiddle
	changed.original.importedMiddle = &copy
	if changed.Config() != "" || changed.Source() != "" || changed.Metadata() != "" {
		t.Fatal("copied original imported owner retained prefix authority")
	}
}

// The native route is doubled; private authenticated HTTP and all fifty TCP
// connections run on real listeners. The original suffix is unreachable.
func TestNodeChainCandidatePreparationImportedPrefixRunsFifty(t *testing.T) {
	for _, count := range []int{2, 6} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			p, err := NewNodeChainCandidatePreparation(startJSON(t, nodeChainImportedSSPrefixFixture(t, count, "wg", NativeStartLayerMethod, true)), count-1, candidateSuffixInventory(t))
			if err != nil {
				t.Fatal(err)
			}
			runtime, owner := candidatePreparationRuntimeFromSource(t, p)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if _, err := runtime.NewMeasurementContext(ctx); err == nil {
				t.Fatal("unproved imported saved prefix acquired measurement")
			}
			if err := runtime.StartContext(ctx); err != nil {
				t.Fatal("unreachable saved imported suffix blocked original prefix", err)
			}
			service, err := runtime.NewMeasurementContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			request := strings.Repeat("a", 32)
			if err := service.Start(request, p.candidates.targets[0].ID); err != nil {
				t.Fatal(err)
			}
			for {
				if err := ctx.Err(); err != nil {
					t.Fatal("original candidate worker exceeded its bounded context", err)
				}
				if err := service.Drain(request); err == nil {
					break
				}
				t.Log("original candidate worker remains owned", owner.count.Load())
			}
			status := candidateStatus(t, service)
			if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || owner.count.Load() != 50 || status.PrefixPosition != count-1 || owner.lease.active.Load() || owner.lease.released.Load() != 1 {
				t.Fatal("saved imported prefix lost complete fifty or original activity", status)
			}
			if err := runtime.CloseContext(ctx); err != nil {
				t.Fatal("original prefix proof worker did not join", err)
			}
			base := owner.nodeChainTestEngine
			base.mu.Lock()
			calls, dns := append([]string(nil), base.calls...), base.dnsCalls
			base.mu.Unlock()
			if len(calls) < count || dns != 0 {
				t.Fatal("captured packet proofs or closed DNS changed", calls, dns)
			}
			for i, tag := range calls {
				if tag != p.proofs[i%count].Tag {
					t.Fatal("reproof contacted foreign or reordered suffix", calls)
				}
			}
			if runtime.Progress().Prepared || runtime.HealthyContext(t.Context()) == nil || p.original.HealthyContext(t.Context()) == nil {
				t.Fatal("retired prefix or complete saved connection acquired live authority")
			}
		})
	}
}
