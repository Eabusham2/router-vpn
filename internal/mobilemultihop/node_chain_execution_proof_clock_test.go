package mobilemultihop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

// These fixtures execute the shipping private HTTP, public TLS, proof owner,
// lease Manager and comparison code. Native routing and the server worker are
// the original explicit test boundaries, not encrypted or installed acceptance.

// newNodeChainExecutionProofClockFixture preserves the production server/auto
// constructor boundary. Local is an actually proved Auto winner restored through
// its captured receipt, never a fabricated Local execution source or projection.
func newNodeChainExecutionProofClockFixture(t *testing.T, execution string) *nodeChainExecutionRuntimeFixture {
	t.Helper()
	if execution == "server" {
		return newNodeChainExecutionRuntimeFixture(t, execution)
	}
	if execution != "local" {
		t.Fatal("unknown measured execution", execution)
	}
	f := newNodeChainExecutionRuntimeFixture(t, "auto")
	server, err := f.runtime.projection.ProofInventory("server")
	if err != nil || len(server) != 3 {
		t.Fatal("missing original Server proof inventory", err)
	}
	var refused atomic.Int32
	f.engine.beforeDial = func(_ context.Context, tag, _ string) (net.Conn, error, bool) {
		if tag == server[1].Tag {
			refused.Add(1)
			return nil, errors.New("fixture Server proof is unavailable"), true
		}
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal("original Auto proof did not capture a Local winner", err)
	}
	capture, err := f.runtime.CaptureRestoreContext(ctx)
	if err != nil || refused.Load() == 0 || capture.execution != "local" ||
		capture.result.Winner == nil || *capture.result.Winner != f.runtime.candidate("local") {
		t.Fatal("Local restore did not retain the actual proved winner", err)
	}
	if _, err := capture.Source(); err == nil {
		t.Fatal("Local restore source escaped before original cleanup")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("original Auto bootstrap did not join", err)
	}
	// Bootstrap includes one failed Server trial and its exact DELETE. Verify
	// every original owner joined before isolating the next measured attempt.
	requireExecutionClockJoined(t, f, "server")
	source, err := capture.Source()
	if err != nil || source != f.runtime.projection.Source() {
		t.Fatal("Local restore changed its original private source", err)
	}
	// As in the original restore fixture, native replacement is an explicit
	// boundary. The same HTTP/TLS peers remain available; fresh engine/session
	// identities and a new runtime model a replacement after joined teardown.
	f.engine.mu.Lock()
	f.engine.identity.EngineID = "clock-restored-box"
	f.engine.identity.SessionID = "clock-restored-session"
	f.engine.epoch++
	f.engine.proofCalls, f.engine.publicCalls, f.engine.dnsCalls = nil, nil, nil
	f.engine.selections = nil
	f.engine.opens, f.engine.revokes = 0, 0
	f.engine.beforeDial = nil
	f.engine.mu.Unlock()
	f.mu.Lock()
	f.requests = nil
	f.mu.Unlock()
	restored, err := NewNodeChainExecutionRestoreRuntime(capture, f.engine)
	if err != nil {
		t.Fatal("joined Local winner could not create its original restore", err)
	}
	restored.testTLS = f.trust
	f.runtime = restored
	return f
}

func executionProofClockTarget(f *nodeChainExecutionRuntimeFixture) string {
	if f.runtime.restore != nil {
		return f.runtime.restore.result.Target
	}
	return Targets[0]
}

func TestNodeChainExecutionProofClockRetainsRealMeasurements(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			f := newNodeChainExecutionProofClockFixture(t, execution)
			source, config := f.runtime.projection.SourceSHA256(), f.runtime.projection.ConfigSHA256()
			var captures atomic.Int32
			f.runtime.testInterval = func() (hopmeasure.Interval, error) {
				captures.Add(1)
				return hopmeasure.StartInterval()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			p := f.runtime.Progress()
			if !p.Ready || !p.Complete || p.Stage != "selected" || p.Execution != execution ||
				len(p.Prefixes) != 3 || !p.DNSProven || !p.PublicProven || p.Comparison.Final == nil {
				t.Fatal("actual checked proofs did not admit the captured execution", p)
			}
			for _, prefix := range p.Prefixes {
				if !prefix.Proven || prefix.ResponseMS <= 0 {
					t.Fatal("actual proof published a nonpositive interval", prefix)
				}
			}
			m := p.Comparison.Final
			if !m.Eligible || m.LastNodeMS <= 0 || m.ExternalMS <= 0 || m.ScoreMS == nil ||
				*m.ScoreMS != (m.LastNodeMS+m.ExternalMS)/2 || m.Candidate != f.runtime.candidate(execution) {
				t.Fatal("checked clock changed the two-response score", m)
			}
			f.engine.mu.Lock()
			proofCalls, publicCalls := append([]string(nil), f.engine.proofCalls...), append([]string(nil), f.engine.publicCalls...)
			dns := append([]string(nil), f.engine.dnsCalls...)
			f.engine.mu.Unlock()
			if captures.Load() != 6 || len(proofCalls) != 4 || len(publicCalls) != 2 ||
				len(dns) != 1 || dns[0] != execution || p.Comparison.Target != executionProofClockTarget(f) {
				t.Fatal("checked clock changed actual proof inventory or selected DNS/target", captures.Load(), proofCalls, publicCalls, dns)
			}
			host := strings.Split(strings.TrimPrefix(executionProofClockTarget(f), "https://"), "/")[0]
			for _, call := range publicCalls {
				if !strings.HasSuffix(call, "/"+host) {
					t.Fatal("checked interval changed the captured public target", publicCalls)
				}
			}
			if f.runtime.projection.SourceSHA256() != source || f.runtime.projection.ConfigSHA256() != config {
				t.Fatal("proof clock changed original source authority")
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			requireExecutionClockJoined(t, f, execution)
		})
	}
}

func requireExecutionClockJoined(t *testing.T, f *nodeChainExecutionRuntimeFixture, execution string) {
	t.Helper()
	f.runtime.mu.Lock()
	active, closed := f.runtime.active, f.runtime.closed
	f.runtime.mu.Unlock()
	f.engine.mu.Lock()
	open, stops := f.engine.open, f.engine.stops
	f.engine.mu.Unlock()
	if active != nil || !closed || open || stops != 0 {
		t.Fatal("clock failure discarded original cleanup or retained forwarding", active, closed, open, stops)
	}
	f.runner.mu.Lock()
	for _, worker := range f.runner.workers {
		if worker.Alive() {
			t.Error("original server worker survived joined cleanup")
		}
	}
	f.runner.mu.Unlock()
	f.mu.Lock()
	var puts, deletes []string
	for _, request := range f.requests {
		switch request.method {
		case "PUT":
			puts = append(puts, request.session)
		case "DELETE":
			deletes = append(deletes, request.session)
		}
	}
	f.mu.Unlock()
	if execution == "server" {
		if len(puts) != 1 || len(deletes) != 1 || puts[0] != deletes[0] {
			t.Fatal("clock failure replaced the original lease or its exact DELETE", puts, deletes)
		}
	} else if len(puts) != 0 || len(deletes) != 0 {
		t.Fatal("Local clock measurement acquired a server lease", puts, deletes)
	}
}

func TestNodeChainExecutionProofClockRejectsInvalidIntervals(t *testing.T) {
	phases := []struct {
		name                   string
		capture, proofs, https int
	}{
		{"prefix", 1, 0, 0},
		{"public-admission", 4, 3, 0},
		{"last-score", 5, 3, 1},
		{"public-score", 6, 4, 1},
	}
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			for _, phase := range phases {
				t.Run(phase.name, func(t *testing.T) {
					for _, fault := range []string{"capture", "completion"} {
						t.Run(fault, func(t *testing.T) {
							f := newNodeChainExecutionProofClockFixture(t, execution)
							captureFailure := errors.New("original measurement capture refused")
							var count atomic.Int32
							var original *nodeChainExecutionTrial
							f.runtime.testInterval = func() (hopmeasure.Interval, error) {
								f.runtime.mu.Lock()
								original = f.runtime.active
								f.runtime.mu.Unlock()
								if int(count.Add(1)) == phase.capture {
									if fault == "capture" {
										return hopmeasure.Interval{}, captureFailure
									}
									// The existing zero Interval has no completion
									// authority. Real HTTP/TLS still runs first.
									return hopmeasure.Interval{}, nil
								}
								return hopmeasure.StartInterval()
							}
							ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
							defer cancel()
							err := f.runtime.Run(ctx)
							if err == nil {
								t.Fatal("invalid original interval admitted ordered execution")
							}
							if fault == "capture" && !errors.Is(err, captureFailure) {
								t.Fatal("original capture failure was replaced", err)
							}
							p := f.runtime.Progress()
							if p.Ready || !p.Complete || p.Stage != "failed" || len(p.Prefixes) != 0 ||
								p.Comparison.Final != nil || p.Comparison.Winner != nil {
								t.Fatal("invalid original interval published proof or score", p)
							}
							f.engine.mu.Lock()
							proofs, https, opens := len(f.engine.proofCalls), len(f.engine.publicCalls), f.engine.opens
							f.engine.mu.Unlock()
							wantProofs, wantHTTPS := phase.proofs, phase.https
							if fault == "completion" {
								if phase.name == "prefix" || phase.name == "last-score" {
									wantProofs++
								} else {
									wantHTTPS++
								}
							}
							if int(count.Load()) != phase.capture || proofs != wantProofs || https != wantHTTPS || opens != 0 {
								t.Fatal("clock failure changed real I/O admission or continued probing", count.Load(), proofs, https, opens)
							}
							if original == nil || !original.closed || !original.proofIO.closed.Load() || !original.controlIO.closed.Load() {
								t.Fatal("clock failure abandoned the exact original proof/control owner")
							}
							original.proofIO.mu.Lock()
							pending := original.proofIO.pending
							original.proofIO.mu.Unlock()
							if pending != nil {
								t.Fatal("clock rejection returned before original proof I/O joined")
							}
							if err := f.runtime.CloseContext(ctx); err != nil {
								t.Fatal(err)
							}
							requireExecutionClockJoined(t, f, execution)
						})
					}
				})
			}
		})
	}
}

func TestNodeChainExecutionProofClockCancellationKeepsOriginalJoin(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			for _, kind := range []string{"private", "public"} {
				t.Run(kind, func(t *testing.T) {
					f := newNodeChainExecutionProofClockFixture(t, execution)
					proofs, err := f.runtime.projection.ProofInventory(execution)
					if err != nil {
						t.Fatal(err)
					}
					host := strings.Split(strings.TrimPrefix(executionProofClockTarget(f), "https://"), "/")[0]
					position := len(proofs) - 1
					node, proof := f.runtime.projection.policy.local.nodes[position], proofs[position]
					api, _ := privateAPI(predecessorText(node.profile, "router_api"))
					entered, release := make(chan struct{}), make(chan struct{})
					var enterOnce, releaseOnce, closeOnce sync.Once
					finishHandler := func() { releaseOnce.Do(func() { close(release) }) }
					t.Cleanup(finishHandler)
					var requests atomic.Int32
					handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != "GET" || r.Header.Get("Cache-Control") != "no-store" ||
							r.Header.Get("Accept-Encoding") != "identity" {
							http.Error(w, "changed original proof headers", http.StatusForbidden)
							return
						}
						if kind == "private" {
							if r.Host != api.Host || r.URL.Path != "/health" ||
								r.Header.Get("Authorization") != "Bearer "+predecessorText(node.profile, "api_token") {
								http.Error(w, "changed original private proof", http.StatusForbidden)
								return
							}
						} else if r.Host != host || r.URL.Path != "/cdn-cgi/trace" ||
							len(r.URL.Query().Get("routervpn_proof")) != 32 || r.Header.Get("Authorization") != "" {
							http.Error(w, "changed original public TLS proof", http.StatusForbidden)
							return
						}
						requests.Add(1)
						enterOnce.Do(func() { close(entered) })
						<-release
						if kind == "private" {
							fmt.Fprintf(w, "{\"ok\":true,\"node_id\":%q,\"proof\":\"router-vpn-private-agent-v1\"}", proof.NodeID)
						} else {
							fmt.Fprint(w, "ip=203.0.113.88\n")
						}
					})
					var endpoint *httptest.Server
					if kind == "private" {
						endpoint = httptest.NewServer(handler)
						t.Cleanup(endpoint.Close)
					} else {
						var trust = f.trust
						endpoint, trust = nodeChainExecutionRuntimeTLS(t, handler)
						f.runtime.testTLS = trust
					}
					closeEntered := make(chan struct{})
					var allowed atomic.Bool
					counts := &nodeChainExecutionDiscoveryTestEngine{}
					counts.closeBefore = func(int32) error {
						closeOnce.Do(func() { close(closeEntered) })
						if !allowed.Load() {
							return errors.New("original measured proof socket close refused")
						}
						return nil
					}
					t.Cleanup(func() { allowed.Store(true); finishHandler() })
					f.engine.beforeDial = func(ctx context.Context, tag, address string) (net.Conn, error, bool) {
						target := api.Host
						if kind == "public" {
							target = net.JoinHostPort(host, "443")
						}
						if tag != proof.Tag || address != target {
							return nil, nil, false
						}
						connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.Listener.Addr().String())
						if err != nil {
							return nil, err, true
						}
						counts.dials.Add(1)
						return &nodeChainExecutionDiscoveryTestConn{Conn: connection, engine: counts}, nil, true
					}
					f.runtime.testInterval = hopmeasure.StartInterval
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					done := make(chan error, 1)
					go func() { done <- f.runtime.Run(ctx) }()
					select {
					case <-entered:
					case <-time.After(5 * time.Second):
						t.Fatal("actual original HTTP/TLS proof never entered")
					}
					cancel()
					select {
					case <-closeEntered:
					case <-time.After(3 * time.Second):
						t.Fatal("cancelled measured proof did not retire its original socket")
					}
					short, finish := context.WithTimeout(context.Background(), 25*time.Millisecond)
					closeErr := f.runtime.CloseContext(short)
					finish()
					f.runtime.mu.Lock()
					retained := f.runtime.active
					f.runtime.mu.Unlock()
					if closeErr == nil || retained == nil || counts.closes.Load() != 0 || f.runtime.Progress().Ready {
						t.Fatal("failed original socket close was reported as joined", closeErr, retained, counts.closes.Load())
					}
					allowed.Store(true)
					finishHandler()
					joined, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if err := f.runtime.CloseContext(joined); err != nil {
						t.Fatal("same original measured proof could not join on retry", err)
					}
					select {
					case err := <-done:
						if err == nil {
							t.Fatal("cancelled measured proof activated application traffic")
						}
					case <-joined.Done():
						t.Fatal("cancelled original Run did not join")
					}
					if requests.Load() != 1 || counts.dials.Load() != 1 || counts.closes.Load() != 1 {
						t.Fatal("cancelled proof replaced or abandoned its actual original connection", requests.Load(), counts.dials.Load(), counts.closes.Load())
					}
					f.engine.mu.Lock()
					opens := f.engine.opens
					f.engine.mu.Unlock()
					if opens != 0 {
						t.Fatal("cancelled clock measurement granted application traffic")
					}
					requireExecutionClockJoined(t, f, execution)
				})
			}
		})
	}
}
