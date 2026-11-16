package mobilemultihop

import (
	"context"
	"encoding/json"
	"router-vpn/internal/routechoice"
	"strings"
	"testing"
	"time"
)

func desktopSOCKSExecutionFixtureSource(t *testing.T, execution string) NodeChainExecutionSource {
	t.Helper()
	_, _, source := socksExecutionFixture(t, "wg", "password", execution)
	return source
}

func desktopSOCKSExecutionProjectionFixture(t *testing.T, target, setting string) (*DesktopNodeChainSOCKSPolicy, *NodeChainExecutionPreparation, *NodeChainExecutionProjection) {
	t.Helper()
	source := desktopSOCKSExecutionFixtureSource(t, setting)
	original, err := NewNodeChainSOCKSSource(source.LocalSource)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewDesktopNodeChainSOCKSPolicy(original, strings.Repeat("e", 32), target, 0)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewDesktopNodeChainSOCKSExecutionPreparation(policy, setting)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := NewNodeChainSOCKSExecutionPolicy(prep, startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := prep.BindExecution(execution)
	if err != nil {
		t.Fatal(err)
	}
	return policy, prep, projection
}

func desktopSOCKSExecutionReadyFixture(t *testing.T, target, setting, selected string) (*NodeChainExecutionProjection, DesktopNodeChainSOCKSExecutionReadyRecord, string) {
	t.Helper()
	_, prep, p := desktopSOCKSExecutionProjectionFixture(t, target, setting)
	physical, _ := p.SOCKSDesktopPhysicalPolicy()
	_, meta, capture, err := physical.PhysicalReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := p.ProofInventory(selected)
	if err != nil {
		t.Fatal(err)
	}
	choice := routechoice.Candidate{Execution: routechoice.Execution(selected), Transport: "ordered-node-chain", EntryID: proofs[0].ProfileID, ExitID: proofs[len(proofs)-1].ProfileID}
	score, err := routechoice.Score(choice, 2*time.Millisecond, 4*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	progress := NodeChainExecutionProgress{NodeChainProgress: NodeChainProgress{Stage: "selected", Complete: true, Ready: true, Execution: selected, DNSProven: true, PublicProven: true}, Comparison: routechoice.Result{Target: Targets[0], Winner: &choice, Final: &score}}
	for _, proof := range proofs {
		progress.Prefixes = append(progress.Prefixes, NodeChainPrefixProgress{Position: proof.Position, ProfileID: proof.ProfileID, ResponseMS: 1.5, Proven: true})
	}
	transfer := strings.Repeat("c", 64)
	name := "router-vpn"
	if target == "darwin" {
		name = "utun9"
	}
	return p, DesktopNodeChainSOCKSExecutionReadyRecord{Schema: 1, Kind: "routervpn-node-chain-socks-execution-ready-v1", SourceSHA256: meta.SourceSHA256, PreparationSourceSHA256: prep.SourceSHA256(), PreparationConfigSHA256: prep.ConfigSHA256(), TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, Identity: NodeChainIdentity{EngineID: "original-box", SessionID: meta.SessionID, NetworkID: "original-network", SourceSHA256: p.SourceSHA256(), ConfigSHA256: p.ConfigSHA256()}, SelectionEpoch: 3, Generation: 1, Reader: 1, InterfaceName: name, InterfaceIndex: 9, MTU: 1280, ObservedAt: time.Now().UnixMilli(), Progress: progress}, transfer
}
func TestDesktopSOCKSExecutionCanonicalRecords(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, selected := range []string{"local", "server"} {
			t.Run(target+"-"+selected, func(t *testing.T) {
				p, r, transfer := desktopSOCKSExecutionReadyFixture(t, target, "auto", selected)
				adoption, err := NewDesktopNodeChainSOCKSExecutionAdoptionRecord(p, r.Identity, transfer)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(adoption)
				q, id, err := ParseDesktopNodeChainSOCKSExecutionAdoptionRecord(raw, p.preparation, transfer)
				if err != nil || id != r.Identity || q.preparation != p.preparation || q.Config() != p.Config() {
					t.Fatal("adoption lost original construction", err)
				}
				if _, _, err = ParseDesktopNodeChainExecutionAdoptionRecord(raw, p.preparation, transfer); err == nil {
					t.Fatal("generic adoption opened")
				}
				ready, err := CanonicalDesktopNodeChainSOCKSExecutionReadyRecord(r, p, transfer)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = ParseDesktopNodeChainSOCKSExecutionAdoptedReadyRecord(ready, q, id, transfer); err != nil {
					t.Fatal(err)
				}
				if _, err = ParseDesktopNodeChainExecutionReadyRecord(ready, p, transfer); err == nil {
					t.Fatal("generic heartbeat opened")
				}
				for _, fault := range []string{"transfer", "identity", "noncanonical", "kind", "dns", "epoch", "proof", "score"} {
					t.Run(fault, func(t *testing.T) {
						changed := append([]byte(nil), ready...)
						identity := id
						token := transfer
						var x DesktopNodeChainSOCKSExecutionReadyRecord
						json.Unmarshal(changed, &x)
						switch fault {
						case "transfer":
							token = strings.Repeat("d", 64)
						case "identity":
							identity.EngineID = "foreign"
						case "noncanonical":
							changed = append(changed, '\n')
						case "kind":
							x.Kind = "routervpn-node-chain-execution-ready-v1"
						case "dns":
							x.DNSConfigSHA256 = strings.Repeat("d", 64)
						case "epoch":
							x.SelectionEpoch = 0
						case "proof":
							x.Progress.Prefixes[1].Proven = false
						case "score":
							x.Progress.Comparison.Final.ScoreMS = nil
						}
						if fault != "noncanonical" {
							changed, _ = json.Marshal(x)
						}
						if _, err := ParseDesktopNodeChainSOCKSExecutionAdoptedReadyRecord(changed, q, identity, token); err == nil {
							t.Fatal("foreign or incomplete selected receipt accepted")
						}
					})
				}
			})
		}
	}
}

// Source restoration only: native proof, TUN and lease authority are never
// fabricated by a saved record. Runtime tests exercise the actual reproof path.
func TestDesktopSOCKSExecutionSavedChoiceBinding(t *testing.T) {
	original, prep, p := desktopSOCKSExecutionProjectionFixture(t, "darwin", "auto")
	source := p.policy.source
	digest, err := source.Server.Digest()
	if err != nil {
		t.Fatal(err)
	}
	last := NodeChainExecutionLast{record: nodeChainExecutionLastRecord{Schema: 1, LocalSourceSHA256: prep.LocalSourceSHA256(), LocalInputSHA256: externalDigest([]byte(prep.LocalSource())), Setting: p.Execution(), Execution: "server", Target: Targets[0], Descriptor: source.Server, DescriptorSHA256: digest, DNSPolicySHA256: source.Request.DNSPolicySHA256, EntryHost: p.policy.front.Host, Peer: source.Request.Peer, FirstPort: source.FirstPort, LastPort: source.LastPort, Port: source.Request.Port, DesktopTargetOS: "darwin"}}
	last.record.Digest = nodeChainExecutionLastDigest(last.record)
	raw, _ := json.Marshal(last.record)
	last.raw = string(raw)
	if err = last.ValidateSOCKSDesktopProjection(p); err != nil {
		t.Fatal(err)
	}
	if last.ValidateDesktopProjection(p) == nil {
		t.Fatal("typed last borrowed paired projection")
	}
	fresh, err := NewDesktopNodeChainSOCKSPolicy(original.original, strings.Repeat("f", 32), "darwin", 1280)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewDesktopNodeChainSOCKSExecutionLastPreparation(fresh, "auto", last.JSON())
	if err != nil {
		t.Fatal("fresh session/MTU source restore", err)
	}
	saved, ok, err := restored.SOCKSDesktopLast()
	if err != nil || !ok || saved.JSON() != last.JSON() {
		t.Fatal("saved choice changed", err)
	}
	parsed, err := ParseDesktopNodeChainSOCKSExecutionPreparation(restored.Source())
	if err != nil || parsed.Config() != restored.Config() {
		t.Fatal("saved child source", err)
	}
	if _, _, err = restored.DesktopLast(); err == nil {
		t.Fatal("paired Last opened")
	}
	for _, fault := range []string{"target", "choice", "source", "setting"} {
		t.Run(fault, func(t *testing.T) {
			changed := last.record
			switch fault {
			case "target":
				changed.DesktopTargetOS = "linux"
			case "choice":
				changed.Execution = "auto"
			case "source":
				changed.LocalInputSHA256 = strings.Repeat("f", 64)
			case "setting":
				changed.Setting = "server"
			}
			changed.Digest = nodeChainExecutionLastDigest(changed)
			raw, _ := json.Marshal(changed)
			if _, err := NewDesktopNodeChainSOCKSExecutionLastPreparation(fresh, "auto", string(raw)); err == nil {
				t.Fatal("foreign saved choice accepted")
			}
		})
	}
}

type desktopSOCKSForeignPhysicalWrapper struct{ DesktopPhysicalPolicy }

func TestDesktopSOCKSExecutionConcreteAdapters(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			_, prep, _ := desktopSOCKSExecutionFixture(t, "wg", "password", target, "auto")
			physical, err := prep.SOCKSDesktopPhysicalPolicy()
			if err != nil {
				t.Fatal(err)
			}
			config, meta, capture, err := ReadDesktopPhysicalPolicy(physical)
			if err != nil || config != prep.Config() {
				t.Fatal("sealed physical read", err)
			}
			cover, digest, err := ReadDesktopPhysicalCoverPolicy(physical)
			if err != nil {
				t.Fatal("sealed cover", err)
			}
			name := "router-vpn"
			if target == "darwin" {
				name = "utun9"
			}
			transfer := strings.Repeat("c", 64)
			record := DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: name, InterfaceIndex: 9, MTU: capture.ConfiguredMTU, ProvedAt: 1, DNSMilliseconds: 1, CoverServices: len(cover), CoverSHA256: digest}
			if _, err := CanonicalDesktopNodeReadyRecord(record, physical, transfer); err != nil {
				t.Fatal("sealed native readiness", err)
			}
			for _, bad := range []DesktopPhysicalPolicy{desktopSOCKSForeignPhysicalWrapper{physical}, func() DesktopPhysicalPolicy { copy := *physical; return &copy }()} {
				if _, _, _, err := ReadDesktopPhysicalPolicy(bad); err == nil {
					t.Fatal("foreign physical wrapper read")
				}
				if _, _, err := ReadDesktopPhysicalCoverPolicy(bad); err == nil {
					t.Fatal("foreign cover wrapper read")
				}
				if _, err := CanonicalDesktopNodeReadyRecord(record, bad, transfer); err == nil {
					t.Fatal("foreign wrapper readiness")
				}
			}
			record.DNSConfigSHA256 = strings.Repeat("f", 64)
			if _, err := CanonicalDesktopNodeReadyRecord(record, physical, transfer); err == nil {
				t.Fatal("foreign DNS readiness")
			}
		})
	}
}

// Shipping HTTP/TLS administration, Manager leases and Last choice proof run;
// the inherited engine explicitly models native routing, DNS and worker state.
func TestDesktopSOCKSExecutionLastRuntimeReproof(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixtureFromSource(t, desktopSOCKSExecutionFixtureSource(t, "auto"))
	source := f.runtime.projection.policy.source
	original, err := NewNodeChainSOCKSSource(source.LocalSource)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewDesktopNodeChainSOCKSPolicy(original, strings.Repeat("b", 32), "linux", 0)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewDesktopNodeChainSOCKSExecutionPreparation(policy, "auto")
	if err != nil {
		t.Fatal(err)
	}
	execution, err := NewNodeChainSOCKSExecutionPolicy(prep, startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := prep.BindExecution(execution)
	if err != nil {
		t.Fatal(err)
	}
	f.engine.projection = projection
	f.engine.identity = NodeChainIdentity{"desktop-box", strings.Repeat("b", 32), "network", projection.SourceSHA256(), projection.ConfigSHA256()}
	f.runtime, err = NewNodeChainExecutionRuntime(projection, f.engine)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.testTLS = f.trust
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = f.runtime.Run(ctx); err != nil {
		t.Fatal("original desktop proof", err)
	}
	last, err := f.runtime.CaptureSOCKSDesktopLastContext(ctx)
	if err != nil {
		t.Fatal("captured desktop Last", err)
	}
	oldSession := projection.policy.Request().SessionID
	if err = f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewDesktopNodeChainSOCKSPolicy(original, strings.Repeat("d", 32), "linux", 1280)
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewDesktopNodeChainSOCKSExecutionLastPreparation(fresh, "auto", last.JSON())
	if err != nil {
		t.Fatal(err)
	}
	nextPolicy, err := NewNodeChainSOCKSExecutionPolicy(next, startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	nextProjection, err := next.BindExecution(nextPolicy)
	if err != nil {
		t.Fatal(err)
	}
	engine := cloneNodeChainExecutionRuntimeEngine(f.engine)
	engine.projection = nextProjection
	engine.identity = NodeChainIdentity{"fresh-box", strings.Repeat("d", 32), "fresh-network", next.SourceSHA256(), next.ConfigSHA256()}
	owner, err := NewNodeChainExecutionDiscoveryOwner(next, engine)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	if _, err = owner.Discover(ctx); err != nil {
		t.Fatal("fresh discovery", err)
	}
	plan, err := owner.PlanLastContext(ctx, last)
	if err != nil {
		t.Fatal("fresh saved plan", err)
	}
	if err = owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	nextProjection, err = plan.Projection()
	if err != nil {
		t.Fatal(err)
	}
	if nextProjection.policy.Request().SessionID == oldSession {
		t.Fatal("reused retired lease identity")
	}
	// Remap only the explicit fixture dial table to fresh compiled tags; the
	// same original HTTP/TLS peer handlers and private identities remain captured.
	for _, selected := range []string{"local", "server"} {
		oldProofs, _ := engine.projection.ProofInventory(selected)
		newProofs, _ := nextProjection.ProofInventory(selected)
		for i, proof := range oldProofs {
			for key, value := range engine.peers {
				if strings.HasPrefix(key, proof.Tag+"/") {
					engine.peers[newProofs[i].Tag+strings.TrimPrefix(key, proof.Tag)] = value
				}
			}
		}
	}
	engine.projection = nextProjection
	engine.identity.SourceSHA256 = nextProjection.SourceSHA256()
	engine.identity.ConfigSHA256 = nextProjection.ConfigSHA256()
	runtime, err := NewNodeChainExecutionLastRuntime(ctx, plan, engine)
	if err != nil {
		t.Fatal(err)
	}
	runtime.testTLS = f.trust
	defer runtime.CloseContext(context.Background())
	if err = runtime.Run(ctx); err != nil {
		t.Fatal("fresh saved proof", err)
	}
	progress := runtime.Progress()
	if !progress.Ready || progress.Execution != last.Execution() || progress.Comparison.Target != last.Target() || len(progress.Comparison.Measurements) != 0 || len(engine.selections) != 1 || len(engine.dnsCalls) == 0 {
		t.Fatal("saved choice reranked or lost selected proof", progress)
	}
	again, err := runtime.CaptureSOCKSDesktopLastContext(ctx)
	if err != nil || again.JSON() != last.JSON() {
		t.Fatal("saved bindings changed", err)
	}
}
