package mobilemultihop

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func multipleCandidateFixture(t *testing.T, layout nodeChainImportedLayout, mode string, position int) (*NodeChainCandidatePreparation, string) {
	t.Helper()
	source := nodeChainMultipleImportedFixture(t, layout, mode, "aes-256-gcm+xor-whitening")
	input, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	inventory := candidateInventoryFixture(t, "complete-imported-catalog-1", input)
	p, err := NewNodeChainMultipleImportedCandidatePreparation(startJSON(t, source), position, inventory)
	if err != nil {
		t.Fatal("original multiple-import source could not prepare its packet prefix", err)
	}
	return p, inventory
}

func TestNodeChainMultipleImportedCandidatePreparationSource(t *testing.T) {
	layouts := append(append([]nodeChainImportedLayout(nil), nodeChainImportedLayouts...),
		nodeChainImportedLayout{"maximum-imported-before-packet", 8, []int{1, 2, 3, 4, 5}})
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layout := range layouts {
			for position := 0; position < layout.count-1; position++ {
				imported := false
				for _, value := range layout.positions {
					imported = imported || value == position
				}
				if imported {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/%d", mode, layout.name, position), func(t *testing.T) {
					p, inventory := multipleCandidateFixture(t, layout, mode, position)
					if !p.IsMultipleImported() || p.multipleOriginal == nil || p.candidates.multiple != p.multipleOriginal ||
						p.multipleOriginal.original != p.original || p.multipleOriginal.registry != p.original.importedNodes ||
						len(p.original.proofs) != layout.count || len(p.proofs) != position+1 || !reflect.DeepEqual(p.proofs, p.original.proofs[:position+1]) {
						t.Fatal("prefix preparation discarded original source or positional authority")
					}
					if _, err := NewNodeChainCandidatePreparation(p.original.sourceJSON, position, inventory); err == nil {
						t.Fatal("generic preparation borrowed schema-six authority")
					}
					if _, err := p.original.NewCandidatePlan(position, inventory); err == nil {
						t.Fatal("generic connected candidate plan borrowed schema-six authority")
					}
					plan, err := p.original.NewMultipleImportedCandidatePlan(position, inventory)
					if err != nil || plan.CaptureSHA256() != p.candidates.CaptureSHA256() {
						t.Fatal("distinct connected plan changed its complete original capture", err)
					}
					for _, parse := range []func(string) (*NodeChainCandidatePreparation, error){ParseNodeChainMultipleImportedCandidatePreparation, ParseNodeChainCandidatePreparationCapture} {
						reopened, err := parse(p.Source())
						if err != nil || reopened.Config() != p.Config() || reopened.SourceSHA256() != p.SourceSHA256() ||
							reopened.OriginalSourceSHA256() != p.original.SourceSHA256() || reopened.CaptureSHA256() != p.CaptureSHA256() {
							t.Fatal("typed preparation replay changed original source or prefix", err)
						}
					}
					if _, err := ParseNodeChainCandidatePreparation(p.Source()); err == nil {
						t.Fatal("ordinary preparation parser accepted a distinct typed envelope")
					}
					metadata := externalTestRead(t, p.Metadata())
					if metadata["ready"] != false || metadata["application_open"] != false || metadata["dns_open"] != false ||
						metadata["mtu_measurement"] != "configured-bounds-only" {
						t.Fatal("source-only preparation fabricated connection or measurement")
					}
					public := p.ImportedPrefixProofs()
					want := 0
					for _, imported := range layout.positions {
						if imported <= position {
							want++
							proof := p.original.proofs[imported]
							if !p.AllowsDial(proof.Tag, "1.1.1.1:443") || p.AllowsDial(proof.Tag, "1.0.0.1:443") || proof.NodeID != "" {
								t.Fatal("public prefix acquired a private identity or arbitrary proof address")
							}
						} else if p.AllowsDial(p.original.proofs[imported].Tag, "1.1.1.1:443") {
							t.Fatal("unselected public suffix became executable")
						}
					}
					if len(public) != want {
						t.Fatal("runnable public proof inventory lost its original positions")
					}
					if len(public) > 0 {
						public[0].Tag = "foreign"
						if p.ImportedPrefixProofs()[0].Tag == "foreign" {
							t.Fatal("public metadata mutated retained owner")
						}
					}
					physical, err := p.PhysicalEgress()
					if err != nil || !nodeChainSamePhysical(physical, p.original.physical) {
						t.Fatal("candidate prefix acquired unrelated physical egress", err)
					}
				})
			}
		}
	}
}

func TestNodeChainMultipleImportedCandidatePreparationRefusals(t *testing.T) {
	layout := nodeChainImportedLayout{"complete", 6, []int{1, 3}}
	for _, fault := range []string{"scope-copy", "registry-copy", "member-copy", "policy-copy", "source", "proof", "plan-scope", "plan-copy", "kind", "extra-field", "source-schema", "public-prefix", "final-prefix"} {
		t.Run(fault, func(t *testing.T) {
			p, inventory := multipleCandidateFixture(t, layout, "wg", 4)
			switch fault {
			case "scope-copy":
				copy := *p.multipleOriginal
				p.multipleOriginal, p.candidates.multiple = &copy, &copy
			case "registry-copy":
				copy := *p.original.importedNodes
				p.original.importedNodes = &copy
			case "member-copy":
				copy := *p.original.importedNodes.members[1]
				p.original.importedNodes.members[1] = &copy
			case "policy-copy":
				copy := *p.original.importedNodes.members[1].policy
				p.original.importedNodes.members[1].policy = &copy
			case "source":
				p.original.sourceJSON += " "
			case "proof":
				p.proofs[1].SourceSHA256 = strings.Repeat("a", 64)
			case "plan-scope":
				p.candidates.multiple = nil
			case "plan-copy":
				other, _ := multipleCandidateFixture(t, layout, "wg", 4)
				p.candidates = other.candidates
			case "kind", "extra-field":
				record := externalTestRead(t, p.Source())
				if fault == "kind" {
					record["kind"] = "routervpn-node-chain-candidate-preparation"
				} else {
					record["application_open"] = false
				}
				if _, err := ParseNodeChainCandidatePreparationCapture(startJSON(t, record)); err == nil {
					t.Fatal("changed envelope retained typed authority")
				}
				return
			case "source-schema":
				ordinary := nodeChainFixture(t, 3, "")
				if _, err := NewNodeChainMultipleImportedCandidatePreparation(ordinary.sourceJSON, 0, inventory); err == nil {
					t.Fatal("ordinary source acquired distinct multiple-import scope")
				}
				return
			case "public-prefix", "final-prefix":
				position := 1
				if fault == "final-prefix" {
					position = 5
				}
				if _, err := NewNodeChainMultipleImportedCandidatePreparation(p.original.sourceJSON, position, inventory); err == nil {
					t.Fatal("lazy stream acquired destination TCP-handshake timing")
				}
				return
			}
			if p.Source() != "" || p.Config() != "" || p.Metadata() != "" || p.IsMultipleImported() || p.AllowsDial("foreign", "1.1.1.1:443") {
				t.Fatal("changed original ownership retained source or native dial authority")
			}
		})
	}
}

func TestNodeChainMultipleImportedCandidatePreparationDesktop(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, position := range []int{0, 2, 4} {
			t.Run(fmt.Sprintf("%s/%d", target, position), func(t *testing.T) {
				original, _ := multipleCandidateFixture(t, nodeChainImportedLayout{"complete", 6, []int{1, 3}}, "awg2-strong", position)
				policy, err := NewDesktopNodeCandidatePreparationPolicy(original, strings.Repeat("c", 32), target, 0)
				if err != nil || policy.Validate() != nil || policy.Metadata().OriginalSourceSHA256 != original.OriginalSourceSHA256() ||
					policy.Metadata().ApplicationOpen || policy.Metadata().DNSOpen || !policy.Preparation().IsMultipleImported() ||
					len(policy.Metadata().Prefixes) != position+1 {
					t.Fatal("desktop physical owner lost complete typed source or closed prefix", err)
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedCandidatePreparationRuntime(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, size := range []int{6, 8} {
			t.Run(fmt.Sprintf("%s/%d", mode, size), func(t *testing.T) {
				positions := []int{1, 3}
				if size == 8 {
					positions = []int{1, 2, 3, 4, 5}
				}
				p, _ := multipleCandidateFixture(t, nodeChainImportedLayout{"complete", size, positions}, mode, size-2)
				r, owner := candidatePreparationRuntimeFromSource(t, p)
				r.testTLS = p.original.runtime.testTLS
				if err := r.StartContext(context.Background()); err != nil {
					t.Fatal("original public and private prefix proofs did not prepare", err)
				}
				progress := r.Progress()
				if !progress.Prepared || progress.ApplicationOpen || progress.DNSOpen || len(progress.Prefixes) != size-1 {
					t.Fatal("temporary prefix lost its proof inventory or opened ingress", progress)
				}
				for position, row := range progress.Prefixes {
					public := p.original.importedSSMemberAt(position) != nil
					if row.Position != position || row.ProfileID != p.proofs[position].ProfileID || !row.Proven ||
						public && (row.Kind != "public-path" || row.Label == "") || !public && (row.Kind != "" || row.Label != "") {
						t.Fatal("prepared prefix relabelled an original public or private proof", position, row)
					}
				}
				service, err := r.NewMeasurementContext(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				request := strings.Repeat("d", 32)
				if err := service.Start(request, p.candidates.targets[0].ID); err != nil {
					t.Fatal(err)
				}
				if err := service.Drain(request); err != nil {
					t.Fatal(err)
				}
				status := candidateStatus(t, service)
				if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 ||
					!status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 ||
					owner.count.Load() != 50 || status.Measurement != "routed-tcp-connect" || status.PrefixPosition != size-2 || status.CaptureSHA256 != p.capture {
					t.Fatal("complete imported candidate receipt changed fifty samples or timing meaning", status, owner.count.Load())
				}
				owner.nodeChainTestEngine.mu.Lock()
				calls, dns := append([]string(nil), owner.calls...), owner.dnsCalls
				owner.nodeChainTestEngine.mu.Unlock()
				seen := map[string]bool{}
				for _, tag := range calls {
					allowed := false
					for _, proof := range p.proofs {
						allowed = allowed || proof.Tag == tag
					}
					if !allowed {
						t.Fatal("preparation contacted unselected saved suffix", tag)
					}
					seen[tag] = true
				}
				if len(seen) != size-1 || dns != 0 || owner.lease.active.Load() || owner.lease.released.Load() != 1 {
					t.Fatal("prefix proofs, closed DNS or joined measurement ownership changed", calls, dns)
				}
				if err := r.CloseContext(context.Background()); err != nil || r.Progress().Prepared || p.original.HealthyContext(context.Background()) == nil {
					t.Fatal("temporary measurement became connected authority or failed retirement", err)
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedCandidatePreparationProofRefusals(t *testing.T) {
	for _, fault := range []string{"public-first", "public-second", "public-swap", "tls", "private-after-import", "application-open", "dns-open", "registry-copy"} {
		t.Run(fault, func(t *testing.T) {
			p, _ := multipleCandidateFixture(t, nodeChainImportedLayout{"complete", 6, []int{1, 3}}, "wg", 4)
			r, owner := candidatePreparationRuntimeFromSource(t, p)
			r.testTLS = p.original.runtime.testTLS
			switch fault {
			case "public-first":
				owner.publicBodies[p.proofs[1].Tag] = "ip=203.0.113.166\n"
			case "public-second":
				owner.publicBodies[p.proofs[3].Tag] = "ip=203.0.113.166\n"
			case "public-swap":
				a, b := p.proofs[1].Tag, p.proofs[3].Tag
				owner.publicPeers[a], owner.publicPeers[b] = owner.publicPeers[b], owner.publicPeers[a]
			case "tls":
				r.testTLS = nil
			case "private-after-import":
				owner.wrong = 2
			case "application-open":
				owner.application = true
			case "dns-open":
				owner.dns = true
			case "registry-copy":
				copy := *p.original.importedNodes
				p.original.importedNodes = &copy
			}
			if err := r.StartContext(context.Background()); err == nil || r.Progress().Prepared || owner.count.Load() != 0 {
				t.Fatal("wrong original prefix or open ingress produced candidate readiness", fault, err)
			}
			if _, err := r.NewMeasurementContext(context.Background()); err == nil {
				t.Fatal("failed original prefix proof retained a measurement service")
			}
		})
	}
}

// The encrypted route/interface boundary is doubled. The complete original
// private HTTP, imported public TLS, selected DNS and fifty TCP connections
// execute. This is separate from temporary closed-prefix preparation above.
func multipleConnectedCandidateFixture(t *testing.T, size int, mode string) (*NodeChainCandidatePlan, *candidateOwnerFixture, *candidateRouteFixture) {
	t.Helper()
	positions := []int{1, 3}
	if size == 8 {
		positions = []int{1, 2, 3, 4, 5}
	}
	p, inventory := multipleCandidateFixture(t, nodeChainImportedLayout{"complete", size, positions}, mode, size-2)
	plan, err := p.original.NewMultipleImportedCandidatePlan(size-2, inventory)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	engine := &candidateRouteFixture{nodeChainTestEngine: newNodeChainTestEngine(t, plan.chain),
		tag: plan.prefix.Tag, address: plan.targets[0].Address, peer: listener.Addr().String()}
	owner := &candidateOwnerFixture{nodeChainMeasurementFixture: nodeChainMeasurementFixture{chain: plan.chain}, capture: plan.capture}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := plan.chain.CloseContext(ctx); err != nil {
			t.Error("complete original candidate owner did not retire", err)
		}
	})
	return plan, owner, engine
}

func TestNodeChainMultipleImportedCandidateConnectedFifty(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, size := range []int{6, 8} {
			t.Run(fmt.Sprintf("%s/%d", mode, size), func(t *testing.T) {
				plan, owner, engine := multipleConnectedCandidateFixture(t, size, mode)
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				if err := plan.chain.Run(ctx, engine); err != nil {
					t.Fatal("complete imported path did not prove before candidate measurement", err)
				}
				progress := plan.chain.Progress()
				if !progress.Ready || !progress.Complete || !progress.DNSProven || !progress.PublicProven || len(progress.Prefixes) != size {
					t.Fatal("candidate acquired incomplete connected authority", progress)
				}
				service, err := plan.NewMeasurementContext(ctx, owner)
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				request := strings.Repeat("b", 32)
				if err := service.StartContext(ctx, request, plan.targets[0].ID); err != nil {
					t.Fatal(err)
				}
				if err := service.Drain(request); err != nil {
					t.Fatal(err)
				}
				status := candidateStatus(t, service)
				if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 || !status.Results[0].Ready ||
					status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || status.Results[0].Benchmark.Distribution.Samples != 50 ||
					engine.count.Load() != 50 || status.CaptureSHA256 != plan.capture || status.PrefixPosition != size-2 || status.Measurement != "routed-tcp-connect" {
					t.Fatal("connected original prefix changed its complete fifty or measurement meaning", status)
				}
				if owner.active.Load() || owner.released.Load() != 1 || owner.checks.Load() < 50 || plan.chain.runtime.engine != engine || !plan.chain.Progress().Ready {
					t.Fatal("candidate measurement replaced or retired the connected route")
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedCandidateConnectedRefusals(t *testing.T) {
	for _, fault := range []string{"not-started", "public-first", "public-second", "private-after-import", "paired-final", "selected-dns", "equal-ready-replacement", "catalog", "retired"} {
		t.Run(fault, func(t *testing.T) {
			plan, owner, engine := multipleConnectedCandidateFixture(t, 6, "wg")
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			switch fault {
			case "public-first":
				engine.publicBodies[plan.chain.proofs[1].Tag] = "ip=203.0.113.166\n"
			case "public-second":
				engine.publicBodies[plan.chain.proofs[3].Tag] = "ip=203.0.113.166\n"
			case "private-after-import":
				engine.wrong = 4
			case "paired-final":
				engine.wrong = 5
			case "selected-dns":
				engine.dnsFail = true
			}
			if fault != "not-started" {
				err := plan.chain.Run(ctx, engine)
				valid := fault == "equal-ready-replacement" || fault == "catalog" || fault == "retired"
				if (err == nil) != valid || plan.chain.Progress().Ready != valid {
					t.Fatal("original complete proof precondition changed", fault, err)
				}
			}
			if fault == "equal-ready-replacement" {
				replacement, replacementOwner, replacementEngine := multipleConnectedCandidateFixture(t, 6, "wg")
				if replacement.chain.SourceSHA256() != plan.chain.SourceSHA256() || replacement.chain.ConfigSHA256() != plan.chain.ConfigSHA256() ||
					replacement.chain == plan.chain || replacement.chain.Run(ctx, replacementEngine) != nil || !replacement.chain.Progress().Ready {
					t.Fatal("equal but separately owned Ready path precondition failed")
				}
				replacementOwner.setCapture(plan.capture)
				owner = replacementOwner
			}
			if fault == "catalog" || fault == "retired" {
				service, err := plan.NewMeasurementContext(ctx, owner)
				if err != nil {
					t.Fatal("valid original candidate precondition failed", err)
				}
				defer service.Close()
				if fault == "catalog" {
					owner.setCapture(strings.Repeat("f", 64))
				} else if err := plan.chain.CloseContext(ctx); err != nil {
					t.Fatal(err)
				}
				request := strings.Repeat("c", 32)
				if err := service.StartContext(ctx, request, plan.targets[0].ID); err == nil {
					_ = service.Drain(request)
					t.Fatal("changed connected owner retained candidate admission")
				}
				owner.setCapture(plan.capture)
				if err := service.StartContext(ctx, strings.Repeat("d", 32), plan.targets[0].ID); err == nil {
					_ = service.Drain(strings.Repeat("d", 32))
					t.Fatal("restored values revived a revoked measurement owner")
				}
			} else if service, err := plan.NewMeasurementContext(ctx, owner); err == nil || service != nil {
				t.Fatal("incomplete or separately owned source acquired connected candidates", fault)
			}
			if owner.active.Load() || engine.count.Load() != 0 {
				t.Fatal("failed connected authority dispatched candidate work", fault)
			}
		})
	}
}
