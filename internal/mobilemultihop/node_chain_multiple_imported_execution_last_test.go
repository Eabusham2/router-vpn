package mobilemultihop

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The native adoption boundary is explicit: only the original tag's actual
// endpoint is copied to its newly authenticated projection tag. In particular,
// independent public positions never collapse to a single public route.
func multipleImportedExecutionAdoptLastFixture(t *testing.T, f *nodeChainExecutionRuntimeFixture, plan NodeChainExecutionLastPlan) *NodeChainExecutionProjection {
	t.Helper()
	projection, err := plan.Projection()
	if err != nil {
		t.Fatal(err)
	}
	e := f.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	previous := e.projection
	for _, execution := range []string{"local", "server"} {
		before, err := previous.ProofInventory(execution)
		if err != nil {
			t.Fatal(err)
		}
		after, err := projection.ProofInventory(execution)
		if err != nil || len(before) != len(after) {
			t.Fatal("changed adopted inventory", err)
		}
		for i, proof := range before {
			host := "1.1.1.1:443"
			if !previous.policy.importedPublicAt(i) {
				api, err := privateAPI(predecessorText(previous.policy.local.nodes[i].profile, "router_api"))
				if err != nil {
					t.Fatal(err)
				}
				host = api.Host
			}
			peer := e.peers[proof.Tag+"/"+host]
			if peer == "" {
				t.Fatal("missing original proof endpoint", i)
			}
			e.peers[after[i].Tag+"/"+host] = peer
		}
	}
	e.projection = projection
	e.identity.SourceSHA256, e.identity.ConfigSHA256 = projection.SourceSHA256(), projection.ConfigSHA256()
	return projection
}

func TestNodeChainMultipleImportedExecutionLastFreshDiscovery(t *testing.T) {
	for _, index := range []int{1, 2, 5} {
		layout := multipleImportedServerLayouts[index]
		for _, winner := range []string{"local", "server"} {
			t.Run(layout.name+"/"+winner, func(t *testing.T) {
				old, last, ctx := nodeChainExecutionLastFixtureFromSource(t, winner, multipleImportedExecutionRuntimeFixture(t, layout, "auto"))
				original := old.runtime.projection.policy
				file := filepath.Join(t.TempDir(), "last.json")
				if err := os.WriteFile(file, []byte(last.JSON()), 0600); err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range []string{"api_token", "password", "private_key", "owner_id", "acquire_expires_at", "proof_at", original.Request().SessionID, original.Request().Users[0].Password} {
					if strings.Contains(last.JSON(), forbidden) {
						t.Fatal("persisted live or private authority", forbidden)
					}
				}
				if err := old.runtime.CloseContext(ctx); err != nil {
					t.Fatal(err)
				}
				old.engine.mu.Lock()
				old.engine.alive = false
				old.engine.mu.Unlock()
				prep, err := ParseNodeChainMultipleImportedExecutionPreparation(old.runtime.projection.preparation.Source())
				if err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				last, err = ParseNodeChainExecutionLast(string(raw), prep)
				if err != nil || last.Execution() != winner || last.record.Descriptor.Schema != 6 {
					t.Fatal("lost durable original choice", err)
				}
				fresh := newNodeChainExecutionRuntimeFixtureFromPreparation(t, original.source, prep)
				engine := &socksExecutionDiscoveryEngine{nodeChainExecutionRuntimeEngine: fresh.engine, preparation: prep}
				owner, err := NewNodeChainExecutionDiscoveryOwner(prep, engine)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := owner.Close(context.Background()); err != nil {
						t.Error(err)
					}
				})
				if _, err := owner.PlanLastContext(ctx, last); err == nil {
					t.Fatal("Last bypassed fresh discovery")
				}
				if _, err := owner.Discover(ctx); err != nil {
					t.Fatal(err)
				}
				plan, err := owner.PlanLastContext(ctx, last)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := NewNodeChainExecutionLastRuntime(ctx, plan, fresh.engine); err == nil {
					t.Fatal("Last bypassed discovery join")
				}
				if err := owner.Close(ctx); err != nil {
					t.Fatal(err)
				}
				projection := multipleImportedExecutionAdoptLastFixture(t, fresh, plan)
				request := projection.policy.Request()
				if request.SessionID == original.Request().SessionID || reflect.DeepEqual(request.Users, original.Request().Users) || request.Port != original.Request().Port {
					t.Fatal("Last borrowed old credentials or replanned original listener")
				}
				runtime, err := NewNodeChainExecutionLastRuntime(ctx, plan, fresh.engine)
				if err != nil {
					t.Fatal(err)
				}
				runtime.testTLS, fresh.runtime = fresh.trust, runtime
				if _, err := NewNodeChainExecutionLastRuntime(ctx, plan, fresh.engine); err == nil {
					t.Fatal("Last plan reused")
				}
				if err := runtime.Run(ctx); err != nil {
					t.Fatal(err)
				}
				assertMultipleImportedExecutionProgress(t, fresh)
				progress := runtime.Progress()
				if progress.Execution != winner || progress.Comparison.Target != last.Target() || len(progress.Comparison.Measurements) != 0 || progress.Comparison.Final == nil {
					t.Fatal("Last compared or reused stale proof", progress)
				}
				proofs, _ := projection.ProofInventory(winner)
				fresh.engine.mu.Lock()
				publicCalls := append([]string(nil), fresh.engine.publicCalls...)
				dnsCalls := append([]string(nil), fresh.engine.dnsCalls...)
				selections := append([]string(nil), fresh.engine.selections...)
				fresh.engine.mu.Unlock()
				for _, position := range layout.positions {
					want, found := proofs[len(proofs)-1].Tag+"/"+proofs[position].ProfileID, false
					for _, call := range publicCalls {
						if call == want {
							found = true
						}
					}
					if !found {
						t.Fatal("saved Last skipped an independent public proof", position)
					}
				}
				if len(dnsCalls) == 0 || len(selections) != 1 || selections[0] != proofs[len(proofs)-1].Tag {
					t.Fatal("Last changed selected DNS or trial inventory", dnsCalls, selections)
				}
				if _, err := runtime.CaptureLastContext(ctx); err != nil {
					t.Fatal("fresh Last cannot be retained", err)
				}
				if err := runtime.CloseContext(ctx); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedExecutionLastInventoryRefusals(t *testing.T) {
	f, original, ctx := nodeChainExecutionLastFixtureFromSource(t, "server", multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[2], "auto"))
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing-public", "reordered-public", "public-source", "public-position", "public-IP", "packet-key", "selected-DNS", "original-source", "original-input", "saved-choice"} {
		t.Run(fault, func(t *testing.T) {
			last := original
			last.record.Descriptor = last.record.Descriptor.Clone()
			switch fault {
			case "missing-public":
				last.record.Descriptor.Members = append(last.record.Descriptor.Members[:0], last.record.Descriptor.Members[1:]...)
			case "reordered-public":
				last.record.Descriptor.Members[0], last.record.Descriptor.Members[2] = last.record.Descriptor.Members[2], last.record.Descriptor.Members[0]
			case "public-source":
				last.record.Descriptor.Members[0].SourceSHA256 = strings.Repeat("a", 64)
			case "public-position":
				last.record.Descriptor.Members[0].Position++
			case "public-IP":
				last.record.Descriptor.Members[2].ExpectedPublicIP = "198.51.100.247"
			case "packet-key":
				last.record.Descriptor.Members[1].ServerPublicKey = strings.Repeat("b", 64)
			case "selected-DNS":
				last.record.Descriptor.DNSPolicySHA256 = strings.Repeat("c", 64)
				last.record.DNSPolicySHA256 = last.record.Descriptor.DNSPolicySHA256
			case "original-source":
				last.record.LocalSourceSHA256 = strings.Repeat("d", 64)
			case "original-input":
				last.record.LocalInputSHA256 = strings.Repeat("e", 64)
			case "saved-choice":
				last.record.Execution = "auto"
			}
			last.record.DescriptorSHA256, _ = last.record.Descriptor.Digest()
			last.record.Digest = nodeChainExecutionLastDigest(last.record)
			raw, err := json.Marshal(last.record)
			if err != nil {
				t.Fatal(err)
			}
			prep, err := ParseNodeChainMultipleImportedExecutionPreparation(f.runtime.projection.preparation.Source())
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseNodeChainExecutionLast(string(raw), prep)
			if err != nil {
				return
			}
			// Syntactically valid saved metadata still cannot replace the entry's
			// freshly authenticated descriptor or any original public position.
			fresh := newNodeChainExecutionRuntimeFixtureFromPreparation(t, f.runtime.projection.policy.source, prep)
			e := &socksExecutionDiscoveryEngine{nodeChainExecutionRuntimeEngine: fresh.engine, preparation: prep}
			owner, err := NewNodeChainExecutionDiscoveryOwner(prep, e)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close(context.Background())
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if _, err := owner.Discover(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.PlanLastContext(ctx, parsed); err == nil {
				t.Fatal("saved metadata replaced original authenticated inventory", fault)
			}
		})
	}
}
