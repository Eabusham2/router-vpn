package mobilemultihop

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"router-vpn/internal/hopmeasure"
	"strings"
	"sync"
	"testing"
	"time"
)

func typedCandidatePreparationSource(t *testing.T, family string, count int) (NodeChainSource, string) {
	t.Helper()
	var source NodeChainSource
	switch family {
	case "socks":
		source = nodeChainSOCKSPrefixFixture(t, count-2, "wg", "", "password")
	case "http", "https":
		source = nodeChainCONNECTPrefixFixture(t, count-2, "wg", family+"-connect", "", "2022-blake3-aes-256-gcm", "password")
	default:
		t.Fatal("unknown typed candidate fixture family")
	}
	target, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	return source, candidateInventoryFixture(t, "original-typed-prefix-catalog", target)
}

func typedCandidatePreparation(t *testing.T, source NodeChainSource, position int, inventory string) *NodeChainCandidatePreparation {
	t.Helper()
	var p *NodeChainCandidatePreparation
	var err error
	if source.Schema == 3 {
		p, err = NewNodeChainSOCKSCandidatePreparation(startJSON(t, source), position, inventory)
	} else {
		p, err = NewNodeChainCONNECTCandidatePreparation(startJSON(t, source), position, inventory)
	}
	if err != nil {
		t.Fatal("original typed source cannot prepare its closed packet prefix", err)
	}
	return p
}

func TestNodeChainCandidatePreparationTypedClosedSource(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		for _, count := range []int{3, 4, 8} {
			t.Run(fmt.Sprintf("%s/%d", family, count), func(t *testing.T) {
				source, inventory := typedCandidatePreparationSource(t, family, count)
				original := startJSON(t, source)
				if _, err := NewNodeChain(original); err == nil {
					t.Fatal("typed saved source entered generic connected authority")
				}
				if _, err := NewNodeChainCandidatePreparation(original, 0, inventory); err == nil {
					t.Fatal("typed saved source entered generic preparation parser")
				}
				for position := 0; position < count-2; position++ {
					p := typedCandidatePreparation(t, source, position, inventory)
					full, err := p.typedOriginal.read()
					if err != nil || p.original != full.pair || p.OriginalSourceSHA256() != full.sourceSHA || p.OriginalSourceSHA256() == p.original.sourceSHA {
						t.Fatal("typed preparation detached original full-source authority", err)
					}
					record := externalTestRead(t, p.Source())
					if record["original_source"] != original || record["kind"] != full.kind {
						t.Fatal("typed private capture lost exact family/source")
					}
					graph, saved := externalTestRead(t, p.Config()), externalTestRead(t, full.config)
					if !reflect.DeepEqual(graph["inbounds"], saved["inbounds"]) || !reflect.DeepEqual(graph["route"].(map[string]any)["rules"], saved["route"].(map[string]any)["rules"]) {
						t.Fatal("complete saved typed restrictions were replaced by detached pair")
					}
					if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || !reflect.DeepEqual(externalTestFind(t, graph, SelectorTag)["outbounds"], []any{p.proofs[position].Tag}) {
						t.Fatal("typed candidate source opened unproved application ingress")
					}
					for _, raw := range graph["outbounds"].([]any) {
						kind := raw.(map[string]any)["type"]
						if kind == "socks" || kind == "http" || kind == "shadowsocks" {
							t.Fatal("typed prefix constructed imported/final outbound", kind)
						}
					}
					for _, proof := range p.original.proofs[position+1:] {
						if strings.Contains(p.Config(), proof.Tag) {
							t.Fatal("typed prefix constructed unselected suffix", proof.Position)
						}
					}
					if !reflect.DeepEqual(p.proofs, p.original.proofs[:position+1]) {
						t.Fatal("typed prefix lost original private proof inventory")
					}
					if _, err := ParseNodeChainCandidatePreparation(p.Source()); err == nil {
						t.Fatal("typed envelope entered generic preparation parser")
					}
					round, err := ParseNodeChainCandidatePreparationCapture(p.Source())
					if err != nil || round.Config() != p.Config() || round.CaptureSHA256() != p.CaptureSHA256() || round.OriginalSourceSHA256() != full.sourceSHA {
						t.Fatal("typed source private reopen changed original identity", err)
					}
					meta := externalTestRead(t, p.Metadata())
					if meta["original_source_sha256"] != full.sourceSHA || meta["application_open"] != false || meta["dns_open"] != false || meta["ready"] != false {
						t.Fatal("typed source fabricated connected authority")
					}
				}
			})
		}
	}
}

func TestNodeChainCandidatePreparationTypedRejectsSubstitution(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		t.Run(family, func(t *testing.T) {
			source, inventory := typedCandidatePreparationSource(t, family, 4)
			p := typedCandidatePreparation(t, source, 1, inventory)
			for _, position := range []int{-1, 2, 3, 4, 8} {
				var err error
				if source.Schema == 3 {
					_, err = NewNodeChainSOCKSCandidatePreparation(startJSON(t, source), position, inventory)
				} else {
					_, err = NewNodeChainCONNECTCandidatePreparation(startJSON(t, source), position, inventory)
				}
				if err == nil {
					t.Fatal("typed middle/final/foreign position became packet preparation", position)
				}
			}
			for _, fault := range []string{"owner-copy", "foreign-owner", "missing-owner", "pair", "source", "middle", "final", "catalog", "kind"} {
				t.Run(fault, func(t *testing.T) {
					fresh, err := ParseNodeChainCandidatePreparationCapture(p.Source())
					if err != nil {
						t.Fatal(err)
					}
					switch fault {
					case "owner-copy":
						if s := fresh.typedOriginal.socks; s != nil {
							copied := *s
							fresh.typedOriginal.socks = &copied
						} else {
							copied := *fresh.typedOriginal.connect
							fresh.typedOriginal.connect = &copied
						}
					case "foreign-owner":
						fresh.typedOriginal = p.typedOriginal
					case "missing-owner":
						fresh.typedOriginal = nil
					case "pair":
						fresh.original = p.original
					case "source":
						if s := fresh.typedOriginal.socks; s != nil {
							s.sourceJSON += " "
						} else {
							fresh.typedOriginal.connect.sourceJSON += " "
						}
					case "middle":
						if s := fresh.typedOriginal.socks; s != nil {
							copied := *s.middle
							s.middle = &copied
						} else {
							copied := *fresh.typedOriginal.connect.middle
							fresh.typedOriginal.connect.middle = &copied
						}
					case "final":
						fresh.original.nodes[len(fresh.original.nodes)-1].profile["api_token"] = "foreign-uncontacted-final"
					case "catalog":
						fresh.candidates.targets[0].Address = "192.0.2.66:443"
					case "kind":
						fresh.source = strings.Replace(fresh.source, "candidate-preparation", "candidate-authority", 1)
					}
					if fresh.validate() == nil || fresh.Source() != "" || fresh.Config() != "" || fresh.Metadata() != "" {
						t.Fatal("changed original typed authority retained candidate preparation", fault)
					}
				})
			}
		})
	}
}

// Real authenticated private HTTP and fifty real loopback TCP connects run;
// only the native packet adapter/ingress is the existing explicit double.
func TestNodeChainCandidatePreparationTypedRuntimeFifty(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		for _, count := range []int{3, 4, 8} {
			t.Run(fmt.Sprintf("%s/%d", family, count), func(t *testing.T) {
				source, inventory := typedCandidatePreparationSource(t, family, count)
				p := typedCandidatePreparation(t, source, count-3, inventory)
				runtime, owner := candidatePreparationRuntimeFromSource(t, p)
				if err := runtime.StartContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				progress := runtime.Progress()
				if !progress.Prepared || progress.ApplicationOpen || progress.DNSOpen || len(progress.Prefixes) != count-2 {
					t.Fatal("typed prefix became complete saved path", progress)
				}
				service, err := runtime.NewMeasurementContext(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				request := strings.Repeat("b", 32)
				deadline := time.Now().Add(hopmeasure.RequestTimeout)
				if err := service.Start(request, p.candidates.targets[0].ID); err != nil {
					t.Fatal(err)
				}
				for {
					if err := service.Drain(request); err == nil {
						break
					}
					if !time.Now().Before(deadline) {
						t.Fatal("typed original fifty exceeded unchanged request bound")
					}
				}
				status := candidateStatus(t, service)
				if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || owner.count.Load() != 50 || status.PrefixPosition != count-3 {
					t.Fatal("typed original prefix lost complete fifty", status, owner.count.Load())
				}
				if owner.lease.active.Load() || owner.lease.released.Load() != 1 {
					t.Fatal("typed measurement lost original native hold")
				}
				if err := runtime.CloseContext(context.Background()); err != nil {
					t.Fatal(err)
				}
				base := owner.nodeChainTestEngine
				base.mu.Lock()
				calls, dns := append([]string(nil), base.calls...), base.dnsCalls
				base.mu.Unlock()
				for i, tag := range calls {
					if tag != p.proofs[i%len(p.proofs)].Tag {
						t.Fatal("typed preparation contacted another source", calls)
					}
				}
				if dns != 0 || len(calls) < count-2 {
					t.Fatal("typed prefix contacted DNS or omitted private proof", calls, dns)
				}
				if _, err := runtime.NewMeasurementContext(t.Context()); err == nil {
					t.Fatal("retired typed owner reacquired measurement")
				}
			})
		}
	}
}

// Typed provenance remains live during private proof and measurement. A
// disposable caller cannot kill its owner, and a held native callback must
// join before retirement even though application ingress was never opened.
func TestNodeChainCandidatePreparationTypedRuntimeAuthority(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		for _, fault := range []string{"source", "native-owner", "lifetime", "caller", "held-callback"} {
			t.Run(family+"/"+fault, func(t *testing.T) {
				source, inventory := typedCandidatePreparationSource(t, family, 4)
				p := typedCandidatePreparation(t, source, 1, inventory)
				r, owner := candidatePreparationRuntimeFromSource(t, p)
				if fault == "held-callback" {
					entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
					var once sync.Once
					owner.nodeChainTestEngine.beforeObserve = func(context.Context) { once.Do(func() { close(entered) }); <-release }
					go func() { finished <- r.StartContext(context.Background()) }()
					<-entered
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
					err := r.CloseContext(ctx)
					cancel()
					if !errors.Is(err, context.DeadlineExceeded) {
						close(release)
						<-finished
						t.Fatal("typed unjoined native callback lost retirement handle", err)
					}
					select {
					case <-finished:
						close(release)
						t.Fatal("typed startup escaped held callback")
					default:
					}
					close(release)
					if err := <-finished; err == nil {
						t.Fatal("typed late callback revived cancelled source")
					}
					if err := r.CloseContext(context.Background()); err != nil {
						t.Fatal("typed original callback did not join on retry", err)
					}
				} else {
					life, stop := context.WithCancel(context.Background())
					defer stop()
					if err := r.StartContext(life); err != nil {
						t.Fatal(err)
					}
					if fault == "caller" {
						ctx, cancel := context.WithCancel(context.Background())
						cancel()
						if r.HealthyContext(ctx) == nil || r.HealthyContext(context.Background()) != nil {
							t.Fatal("typed disposable caller changed original owner lifetime")
						}
					} else {
						restore := func() {}
						switch fault {
						case "source":
							if s := p.typedOriginal.socks; s != nil {
								old := s.sourceJSON
								s.sourceJSON += " "
								restore = func() { s.sourceJSON = old }
							} else {
								s := p.typedOriginal.connect
								old := s.sourceJSON
								s.sourceJSON += " "
								restore = func() { s.sourceJSON = old }
							}
						case "native-owner":
							base := owner.nodeChainTestEngine
							base.mu.Lock()
							old := base.identity
							base.identity.EngineID = "foreign-owner"
							base.mu.Unlock()
							restore = func() { base.mu.Lock(); base.identity = old; base.mu.Unlock() }
						case "lifetime":
							stop()
						}
						if _, err := r.NewMeasurementContext(context.Background()); err == nil {
							restore()
							t.Fatal("typed changed original authority acquired measurement", fault)
						}
						restore()
						if _, err := r.NewMeasurementContext(context.Background()); err == nil || r.Progress().Prepared {
							t.Fatal("typed authority change-away-and-back revived preparation", fault)
						}
					}
					if err := r.CloseContext(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				if owner.count.Load() != 0 || r.Progress().Prepared {
					t.Fatal("typed refused or retired preparation dialed candidate")
				}
			})
		}
	}
}
