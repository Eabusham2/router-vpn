package mobilemultihop

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func TestNodeChainCandidateConnectedImportedSources(t *testing.T) {
	methods := []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}
	for m, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for count := 1; count <= 6; count++ {
			t.Run(fmt.Sprintf("%s/%d", mode, count), func(t *testing.T) {
				input := startJSON(t, nodeChainImportedSSPrefixFixture(t, count, mode, methods[(count+m)%len(methods)], count%2 == 0))
				chain, err := NewNodeChain(input)
				if err != nil {
					t.Fatal(err)
				}
				target, address := candidateSourceFixture(t, "external", methods[m])
				inventory := candidateInventoryFixture(t, "original-connected-imported-catalog", target)
				before := chain.config
				for position := 0; position < count; position++ {
					plan, err := chain.NewCandidatePlan(position, inventory)
					if err != nil || plan.chain != chain || plan.prefix != chain.proofs[position] || plan.targets[0].Address != address || chain.config != before || chain.sourceJSON != input {
						t.Fatal("connected candidate changed its original complete path or global position", position, err)
					}
					owner := &candidateOwnerFixture{nodeChainMeasurementFixture: nodeChainMeasurementFixture{chain: chain}, capture: plan.capture}
					if service, err := plan.NewMeasurementContext(t.Context(), owner); err == nil || service != nil || owner.active.Load() {
						t.Fatal("source plan granted a route before the complete chain was ready")
					}
				}
				for _, position := range []int{-1, count, count + 1, count + 2} {
					if plan, err := chain.NewCandidatePlan(position, inventory); err == nil || plan != nil {
						t.Fatal("imported or final stream acquired packet-prefix timing", position)
					}
				}
				original := chain.importedMiddle
				copied := *original
				chain.importedMiddle = &copied
				if plan, err := chain.NewCandidatePlan(0, inventory); err == nil || plan != nil {
					t.Fatal("equal-valued copied imported owner acquired connected candidate planning")
				}
				chain.importedMiddle = original
			})
		}
	}
}

// The route is explicitly doubled here. Complete private HTTP/TLS proof and
// all candidate TCP connections execute. The separate native gate retains the
// actual encrypted WG/AWG prefix and independently proves the full SS suffix.
func connectedImportedCandidateFixture(t *testing.T, count int) (*NodeChainCandidatePlan, *candidateOwnerFixture, *candidateRouteFixture) {
	t.Helper()
	chain, err := NewNodeChain(startJSON(t, nodeChainImportedSSPrefixFixture(t, count, "wg", NativeStartLayerMethod, false)))
	if err != nil {
		t.Fatal(err)
	}
	input, address := candidateSourceFixture(t, "external", NativeStartLayerMethod)
	plan, err := chain.NewCandidatePlan(count-1, candidateInventoryFixture(t, "connected-imported-original-epoch", input))
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
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	engine := &candidateRouteFixture{nodeChainTestEngine: newNodeChainTestEngine(t, chain), tag: chain.proofs[count-1].Tag, address: address, peer: listener.Addr().String()}
	owner := &candidateOwnerFixture{nodeChainMeasurementFixture: nodeChainMeasurementFixture{chain: chain}, capture: plan.capture}
	return plan, owner, engine
}

func TestNodeChainCandidateConnectedImportedRequiresCompleteReady(t *testing.T) {
	for _, count := range []int{2, 6} {
		for _, fault := range []string{"not-started", "private-prefix", "paired-final", "selected-dns", "public-proof"} {
			t.Run(fmt.Sprintf("%d/%s", count, fault), func(t *testing.T) {
				plan, owner, engine := connectedImportedCandidateFixture(t, count)
				switch fault {
				case "private-prefix":
					engine.wrong = count - 1
				case "paired-final":
					engine.wrong = count + 1
				case "selected-dns":
					engine.dnsFail = true
				case "public-proof":
					engine.publicBody = "ip=203.0.113.99\n"
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				if fault != "not-started" {
					if err := plan.chain.Run(ctx, engine); err == nil || plan.chain.Progress().Ready {
						t.Fatal("failed complete imported path acquired Ready", fault)
					}
				}
				if service, err := plan.NewMeasurementContext(ctx, owner); err == nil || service != nil || engine.count.Load() != 0 || owner.active.Load() {
					t.Fatal("earlier valid prefix bypassed complete path readiness", fault)
				}
			})
		}
	}
}

func TestNodeChainCandidateConnectedImportedRunsOriginalFifty(t *testing.T) {
	for _, count := range []int{2, 6} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			plan, owner, engine := connectedImportedCandidateFixture(t, count)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			if err := plan.chain.Run(ctx, engine); err != nil {
				t.Fatal(err)
			}
			progress := plan.chain.Progress()
			if !progress.Ready || !progress.Complete || !progress.DNSProven || !progress.PublicProven || len(progress.Prefixes) != count+2 {
				t.Fatal("complete original source not proved", progress)
			}
			original, reader, identity := plan.chain, plan.chain.runtime.engine, plan.chain.runtime.identity
			service, err := plan.NewMeasurementContext(ctx, owner)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := service.Close(); err != nil {
					t.Error(err)
				}
			})
			request := strings.Repeat("a", 32)
			if err := service.StartContext(ctx, request, plan.targets[0].ID); err != nil {
				t.Fatal(err)
			}
			if err := service.Drain(request); err != nil {
				t.Fatal(err)
			}
			status := candidateStatus(t, service)
			if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || status.Results[0].Benchmark.Distribution.Samples != 50 || engine.count.Load() != 50 {
				t.Fatal("connected original path lost fifty completed candidate connections", status)
			}
			if status.PrefixPosition != count-1 || status.CaptureSHA256 != plan.capture || status.CandidateSourceSHA256 != plan.targets[0].SourceSHA256 || owner.active.Load() || owner.released.Load() != 1 || owner.checks.Load() < 50 || plan.chain != original || original.runtime.engine != reader || original.runtime.identity != identity {
				t.Fatal("candidate measurement replaced its original complete path or activity owner")
			}
		})
	}
}

func TestNodeChainCandidateConnectedImportedRejectsOwnerDrift(t *testing.T) {
	for _, field := range []string{"SourceSHA256", "ConfigSHA256", "EngineID", "SessionID", "NetworkID", "reader", "catalog", "ready", "proof-generation", "retired"} {
		t.Run(field, func(t *testing.T) {
			plan, owner, engine := connectedImportedCandidateFixture(t, 2)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if err := plan.chain.Run(ctx, engine); err != nil {
				t.Fatal(err)
			}
			service, err := plan.NewMeasurementContext(ctx, owner)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := service.Close(); err != nil {
					t.Error(err)
				}
			})
			engine.mu.Lock()
			identity := engine.identity
			engine.mu.Unlock()
			switch field {
			case "reader":
				plan.chain.runtime.mu.Lock()
				plan.chain.runtime.engine = &candidateRouteFixture{nodeChainTestEngine: engine.nodeChainTestEngine, tag: engine.tag, address: engine.address, peer: engine.peer}
				plan.chain.runtime.mu.Unlock()
			case "catalog":
				owner.setCapture(strings.Repeat("f", 64))
			case "ready":
				plan.chain.runtime.mu.Lock()
				plan.chain.runtime.progress.Ready, plan.chain.runtime.progress.Complete = false, false
				plan.chain.runtime.mu.Unlock()
			case "proof-generation":
				plan.chain.runtime.generation.Store(2)
			case "retired":
				if err := plan.chain.CloseContext(ctx); err != nil {
					t.Fatal(err)
				}
			default:
				engine.mu.Lock()
				reflect.ValueOf(&engine.identity).Elem().FieldByName(field).SetString("replacement")
				engine.mu.Unlock()
			}
			if err := service.StartContext(ctx, strings.Repeat("b", 32), plan.targets[0].ID); err == nil {
				_ = service.Drain(strings.Repeat("b", 32))
				t.Fatal("changed complete path retained candidate capability", field)
			}
			engine.mu.Lock()
			engine.identity = identity
			engine.mu.Unlock()
			owner.setCapture(plan.capture)
			if err := service.StartContext(ctx, strings.Repeat("c", 32), plan.targets[0].ID); err == nil {
				_ = service.Drain(strings.Repeat("c", 32))
				t.Fatal("restored values revived a revoked connected measurement", field)
			}
			var status hopmeasure.CandidateStatus
			if json.Unmarshal([]byte(service.StatusJSON()), &status) != nil || len(status.Results) != 0 || engine.count.Load() != 0 || owner.active.Load() {
				t.Fatal("stale owner dispatched or retained candidate results", status)
			}
		})
	}
}
