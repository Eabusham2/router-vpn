package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// The original controller, source compiler, staged files, typed Ready parser,
// source/session guards and parent retirement execute here. The existing child
// and kernel fixtures are explicit models. Native command-loop and encrypted
// transport gates provide their separate evidence; these model receipts do not.
func desktopTypedConnectedCandidateFixture(t *testing.T, count int, protocol string, connected bool) (*desktopNodeChainOwnedFixture, *desktopNodeChainCandidateCatalog, string) {
	t.Helper()
	mode := map[int]string{3: "wg", 4: "awg2-fast", 8: "awg2-strong"}[count]
	var a *app
	var launch *desktopNodeLaunch
	if protocol == "socks5" {
		a, launch = desktopSOCKSPrefixProductLaunchFixture(t, count-2, mode, protocol)
	} else {
		a, launch = desktopCONNECTPrefixProductLaunchFixture(t, count-2, mode, protocol)
	}
	f := newDesktopNodeChainOwnedFixtureWith(t, a, launch.chain.selection)
	f.stagePublish(t)
	id := desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm")
	var c *desktopNodeChainCandidateCatalog
	var err error
	if connected {
		if err = startDesktopOwnedNodeChainLaunch(f.operation, f.operation, a, f.launch); err != nil {
			t.Fatal(err)
		}
		if err = proveDesktopNodeChainContext(f.operation, a, f.selection, f.launch.command); err != nil {
			t.Fatal(err)
		}
		a.mu.Lock()
		a.state.Connected, a.state.Phase = true, "connected"
		a.mu.Unlock()
		sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "typed-connected-candidates", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}})
		identity, _, captureErr := captureSpeedLabIdentityContext(f.operation, a)
		if captureErr != nil {
			t.Fatal(captureErr)
		}
		c, err = captureDesktopNodeChainCandidates(f.operation, a, identity, count-3, []string{id})
	} else {
		c, err = captureDesktopNodeChainCandidateSources(f.operation, a, f.launch, count-3, []string{id})
	}
	if err != nil {
		t.Fatal("original typed connected candidate source refused", err)
	}
	if c.plan != nil || c.prefixPreparation != nil || c.typedPlan == nil || c.typedPlan.current() != nil {
		t.Fatal("typed candidate borrowed a generic or saved-prefix owner")
	}
	return f, c, id
}

func desktopTypedConnectedCandidateStatus(t *testing.T, c *desktopNodeChainCandidateCatalog, id string) hopmeasure.CandidateStatus {
	t.Helper()
	var meta struct {
		PrefixPosition int    `json:"prefix_position"`
		PrefixID       string `json:"prefix_id"`
		Targets        []struct {
			ID     string `json:"id"`
			Source string `json:"source_sha256"`
		} `json:"targets"`
	}
	if json.Unmarshal([]byte(c.typedPlan.Metadata()), &meta) != nil || len(meta.Targets) != 1 {
		t.Fatal("typed candidate lost its sealed metadata")
	}
	now := time.Now().UnixMilli()
	return hopmeasure.CandidateStatus{Schema: 1, Measurement: "routed-tcp-connect", PrefixPosition: meta.PrefixPosition, PrefixID: meta.PrefixID,
		CaptureSHA256: c.typedPlan.CaptureSHA256(), CandidateID: id, CandidateSourceSHA256: meta.Targets[0].Source, MeasuredAt: now, ExpiresAt: now + 120000,
		Status: hopmeasure.Status{Stage: "complete", Complete: true, Drained: true, Results: []hopmeasure.Result{{ID: id, Role: "candidate", Kind: "tcp-connect", Ready: true,
			Benchmark: &hopmeasure.LatencyBenchmark{Schema: 1, Measurement: "routed-tcp-connect", Attempts: 50, TrimmedMean: 2, Distribution: &hopmeasure.Latency{Samples: 50, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4}}}}}}
}

func testDesktopTypedConnectedCandidateSource(t *testing.T, protocol string) {
	for _, count := range []int{3, 4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f, c, id := desktopTypedConnectedCandidateFixture(t, count, protocol, false)
			before := cloneRouterProfileStore(f.a.profiles)
			input, config := f.launch.chain.input, string(f.launch.config)
			if c.current(f.operation) == nil {
				t.Fatal("staged typed descriptor acquired unproved connected authority")
			}
			if _, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(input); err == nil {
				t.Fatal("typed candidate widened generic desktop source parser")
			}
			if _, err := mobilemultihop.ParseNodeChainLaunchInput(f.selection.Native.chain.input); err == nil {
				t.Fatal("typed candidate exposed generic runtime authority")
			}
			var original mobilemultihop.NodeChainSource
			if json.Unmarshal([]byte(f.selection.Native.chain.input), &original) != nil || len(original.Nodes) != count || len(original.IdentitySources) != count {
				t.Fatal("typed candidate shortened original full source")
			}
			var meta struct {
				PrefixPosition int    `json:"prefix_position"`
				PrefixID       string `json:"prefix_id"`
			}
			if json.Unmarshal([]byte(c.typedPlan.Metadata()), &meta) != nil || meta.PrefixPosition != count-3 || meta.PrefixID != f.selection.Nodes[count-3].Profile.ID {
				t.Fatal("typed candidate substituted its captured packet prefix")
			}
			if err := validateDesktopCandidateCatalogStatus(c, id, desktopTypedConnectedCandidateStatus(t, c, id), time.Now()); err != nil {
				t.Fatal("complete original typed receipt refused", err)
			}
			for _, position := range []int{count - 2, count - 1} {
				if _, err := captureDesktopNodeChainCandidateSources(f.operation, f.a, f.launch, position, []string{id}); err == nil {
					t.Fatal("typed proxy or final acquired packet-prefix candidate capability")
				}
			}
			if !reflect.DeepEqual(before, f.a.profiles) || input != f.launch.chain.input || config != string(f.launch.config) {
				t.Fatal("candidate capture changed original source or active selections")
			}
		})
	}
}
func TestDesktopTypedConnectedSOCKSCandidateSource(t *testing.T) {
	testDesktopTypedConnectedCandidateSource(t, "socks5")
}
func TestDesktopTypedConnectedHTTPCandidateSource(t *testing.T) {
	testDesktopTypedConnectedCandidateSource(t, "http-connect")
}
func TestDesktopTypedConnectedHTTPSCandidateSource(t *testing.T) {
	testDesktopTypedConnectedCandidateSource(t, "https-connect")
}

func testDesktopTypedConnectedCandidateAuthority(t *testing.T, protocol string) {
	for _, fault := range []string{"unstaged", "execution-owner", "saved-prefix", "generic-plan", "mixed-policy", "equal-policy", "equal-source", "foreign-launch", "missing-plan", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			f, c, id := desktopTypedConnectedCandidateFixture(t, 3, protocol, false)
			good := desktopTypedConnectedCandidateStatus(t, c, id)
			switch fault {
			case "unstaged":
				f.launch.command = nil
			case "execution-owner":
				f.launch.chain.execution = &desktopNodeChainExecutionLaunch{}
			case "saved-prefix":
				c.prefixPreparation = &mobilemultihop.NodeChainCandidatePreparation{}
			case "generic-plan":
				c.plan = &mobilemultihop.NodeChainCandidatePlan{}
			case "mixed-policy":
				_, ordinary := desktopNodeChainLaunchFixture(t, 3, "windows")
				f.launch.chain.policy = ordinary.chain.policy
			case "equal-policy":
				if protocol == "socks5" {
					p, err := mobilemultihop.ParseDesktopNodeChainSOCKSLaunchInput(f.launch.chain.input)
					if err != nil {
						t.Fatal(err)
					}
					f.launch.chain.socksPolicy = p
				} else {
					p, err := mobilemultihop.ParseDesktopNodeChainCONNECTLaunchInput(f.launch.chain.input)
					if err != nil {
						t.Fatal(err)
					}
					f.launch.chain.connectPolicy = p
				}
			case "equal-source":
				if protocol == "socks5" {
					p := *c.typedPlan.socksSource
					c.typedPlan.socksSource = &p
				} else {
					p := *c.typedPlan.connectSource
					c.typedPlan.connectSource = &p
				}
			case "foreign-launch":
				c.launch = &desktopNodeLaunch{chain: f.launch.chain, command: f.launch.command}
			case "missing-plan":
				c.typedPlan = nil
			case "cancelled":
				ctx, cancel := context.WithCancel(f.operation)
				cancel()
				if _, err := captureDesktopNodeChainCandidateSources(ctx, f.a, f.launch, 0, []string{id}); err == nil {
					t.Fatal("cancelled typed capture revived")
				}
				return
			}
			if validateDesktopCandidateCatalogStatus(c, id, good, time.Now()) == nil {
				t.Fatal("typed candidate accepted substituted original authority", fault)
			}
		})
	}
}
func TestDesktopTypedConnectedSOCKSCandidateAuthority(t *testing.T) {
	testDesktopTypedConnectedCandidateAuthority(t, "socks5")
}
func TestDesktopTypedConnectedHTTPCandidateAuthority(t *testing.T) {
	testDesktopTypedConnectedCandidateAuthority(t, "http-connect")
}
func TestDesktopTypedConnectedHTTPSCandidateAuthority(t *testing.T) {
	testDesktopTypedConnectedCandidateAuthority(t, "https-connect")
}

func TestDesktopTypedConnectedCandidatePublicCatalog(t *testing.T) {
	for _, protocol := range []string{"socks5", "http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			f, c, id := desktopTypedConnectedCandidateFixture(t, 3, protocol, true)
			before := cloneRouterProfileStore(f.a.profiles)
			mux := http.NewServeMux()
			registerOrderedCandidateRoutes(mux, f.a)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/multihop/prefix-candidates/catalog?prefix_position=0", nil).WithContext(f.operation))
			var value struct {
				Token       string                   `json:"view_token"`
				Measurement string                   `json:"measurement"`
				Samples     int                      `json:"samples"`
				Candidates  []orderedCandidateChoice `json:"candidates"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || len(value.Token) != 64 || value.Measurement != "routed-tcp-connect" || value.Samples != 50 {
				t.Fatal("typed connected public catalog refused original owner", response.Code, response.Body.String())
			}
			found := false
			for _, candidate := range value.Candidates {
				if candidate.ID == id {
					found = true
				}
			}
			if !found || !reflect.DeepEqual(before, f.a.profiles) || c.current(f.operation) != nil {
				t.Fatal("public typed candidates lost original source or mutated the active graph")
			}
			control := viaEntryControlFor(f.a)
			control.mu.Lock()
			view := control.orderedView
			control.mu.Unlock()
			if view == nil || view.catalog.typedPlan == nil || view.catalog.plan != nil || view.catalog.prefixPreparation != nil {
				t.Fatal("public typed catalog borrowed generic or saved-prefix authority")
			}
		})
	}
}

func testDesktopTypedConnectedCandidateReceipt(t *testing.T, protocol string) {
	_, c, id := desktopTypedConnectedCandidateFixture(t, 4, protocol, false)
	good := desktopTypedConnectedCandidateStatus(t, c, id)
	if err := validateDesktopCandidateCatalogStatus(c, id, good, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"schema", "measurement", "capture", "prefix", "prefix-id", "candidate", "source", "expiry", "renewed-expiry", "future", "undrained", "failed", "missing", "role", "kind", "not-ready", "http", "guessed-endpoint", "attempts", "failed-sample", "sample-count", "nan", "order", "mean", "trim", "jitter"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(good)
			var s hopmeasure.CandidateStatus
			_ = json.Unmarshal(raw, &s)
			b := s.Results[0].Benchmark
			switch fault {
			case "schema":
				s.Schema++
			case "measurement":
				s.Measurement = "icmp"
			case "capture":
				s.CaptureSHA256 = strings.Repeat("a", 64)
			case "prefix":
				s.PrefixPosition++
			case "prefix-id":
				s.PrefixID = "other"
			case "candidate":
				s.CandidateID = "other"
			case "source":
				s.CandidateSourceSHA256 = strings.Repeat("a", 64)
			case "expiry":
				s.MeasuredAt -= 120000
				s.ExpiresAt -= 120000
			case "renewed-expiry":
				s.ExpiresAt++
			case "future":
				s.MeasuredAt += 120000
				s.ExpiresAt += 120000
			case "undrained":
				s.Drained = false
			case "failed":
				s.Failure = "stale"
			case "missing":
				s.Results = nil
			case "role":
				s.Results[0].Role = "exit"
			case "kind":
				s.Results[0].Kind = "private-node"
			case "not-ready":
				s.Results[0].Ready = false
			case "http":
				b.Measurement = "http-response"
			case "guessed-endpoint":
				b.Endpoint = "198.51.100.1:443"
			case "attempts":
				b.Attempts--
			case "failed-sample":
				b.Failed++
			case "sample-count":
				b.Distribution.Samples--
			case "nan":
				b.TrimmedMean = math.NaN()
			case "order":
				b.Distribution.P90 = 7
			case "mean":
				b.Distribution.Average = 9
			case "trim":
				b.TrimmedMean = 8
			case "jitter":
				b.Distribution.Jitter = -1
			}
			if validateDesktopCandidateCatalogStatus(c, id, s, time.Now()) == nil {
				t.Fatal("forged or incomplete score accepted")
			}
		})
	}
}

func TestDesktopTypedConnectedSOCKSCandidateReceipt(t *testing.T) {
	testDesktopTypedConnectedCandidateReceipt(t, "socks5")
}
func TestDesktopTypedConnectedHTTPCandidateReceipt(t *testing.T) {
	testDesktopTypedConnectedCandidateReceipt(t, "http-connect")
}
func TestDesktopTypedConnectedHTTPSCandidateReceipt(t *testing.T) {
	testDesktopTypedConnectedCandidateReceipt(t, "https-connect")
}

func testDesktopTypedConnectedCandidateMailbox(t *testing.T, protocol string) {
	f, c, id := desktopTypedConnectedCandidateFixture(t, 3, protocol, true)
	// Each completed mailbox releases its real MTU hold and resumes Auto.
	// Join those application workers before the native model and TempDir retire.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := retireDesktopOrderedLatencyFixture(ctx, f.a, f.launch.command); err != nil {
			t.Error("candidate mailbox fixture left background work before native/file cleanup", err)
		}
	})
	for _, fault := range []string{"success", "cancel", "cancel-delayed", "wrong-capture", "partial-samples", "catalog-away-back"} {
		t.Run(fault, func(t *testing.T) {
			generation := f.launch.chain.candidateGeneration
			ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.RequestTimeout)
			defer cancel()
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
			done := make(chan error, 1)
			workerDone := make(chan struct{})
			statusFixture := desktopTypedConnectedCandidateStatus(t, c, id)
			t.Cleanup(func() {
				cancel()
				releaseWorker()
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-workerDone:
				case <-timer.C:
					t.Error("typed mailbox model worker did not join")
				}
			})
			go func() {
				defer close(workerDone)
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					raw, err := readDesktopRuntimeFile(f.launch, "node-chain-typed-candidate-request.json", 16384)
					if err == nil {
						var q desktopNodeChainTypedCandidateRequest
						if json.Unmarshal(raw, &q) != nil {
							done <- errors.New("malformed request")
							return
						}
						if fault == "cancel" || fault == "cancel-delayed" {
							cancel()
						}
						if fault == "catalog-away-back" {
							f.a.mu.Lock()
							saved := f.a.profiles.Profiles[2].APIToken
							f.a.profiles.Profiles[2].APIToken += "-relinked"
							_, _ = f.a.candidateCatalogRevisionLocked()
							f.a.profiles.Profiles[2].APIToken = saved
							_, _ = f.a.candidateCatalogRevisionLocked()
							f.a.mu.Unlock()
						}
						if fault == "cancel" || fault == "cancel-delayed" || fault == "catalog-away-back" {
							deadline := time.NewTimer(3 * time.Second)
							defer deadline.Stop()
							for {
								body, e := readDesktopRuntimeFile(f.launch, "node-chain-typed-candidate-cancel.json", 16384)
								if e == nil {
									if string(body) != string(raw) {
										done <- errors.New("foreign cancel")
										return
									}
									break
								}
								select {
								case <-ticker.C:
								case <-deadline.C:
									done <- errors.New("cancel missing")
									return
								}
							}
						}
						if fault == "cancel-delayed" {
							<-release // Exact native close remains owned past the first drain.
						}
						s := statusFixture
						s.Request = q.Request
						if fault == "wrong-capture" {
							s.CaptureSHA256 = strings.Repeat("f", 64)
						}
						if fault == "partial-samples" {
							s.Results[0].Benchmark.Distribution.Samples--
						}
						result := desktopNodeChainTypedCandidateResult{desktopNodeChainTypedCandidateRequest: q, CompletedAt: time.Now().UnixMilli(), Status: s}
						body, _ := json.Marshal(result)
						// Match the native producer's atomic result publication.
						// A completed previous receipt remains until this request
						// replaces it; the parent's last-request guard ignores it.
						f.launch.workspaceMu.Lock()
						err := desktopExternalDirectoryCurrent(f.launch)
						if err == nil {
							err = f.launch.directoryRoot.WriteFile(".node-chain-typed-candidate-result.json.pending", body, 0600)
						}
						if err == nil {
							err = f.launch.directoryRoot.Rename(".node-chain-typed-candidate-result.json.pending", "node-chain-typed-candidate-result.json")
						}
						f.launch.workspaceMu.Unlock()
						if err != nil {
							done <- err
							return
						}
						if err := f.launch.directoryRoot.Remove("node-chain-typed-candidate-request.json"); err != nil {
							done <- err
							return
						}
						done <- nil
						return
					}
					if !errors.Is(err, os.ErrNotExist) {
						done <- err
						return
					}
					select {
					case <-ticker.C:
					case <-ctx.Done():
						done <- ctx.Err()
						return
					}
				}
			}()
			finish, err := beginDesktopNodeChainMeasurementHold(ctx, f.a, f.launch)
			if err != nil {
				t.Fatal(err)
			}
			s, err := exchangeDesktopNodeChainCandidate(ctx, c, id)
			finish(!errors.Is(err, errDesktopNodeChainMeasurementPending))
			if fault == "cancel-delayed" {
				if !errors.Is(err, errDesktopNodeChainMeasurementPending) || !mtuSuspended(f.a) {
					releaseWorker()
					t.Fatal("unjoined native request lost its original parent hold", err)
				}
				short, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
				pending := retryDesktopNodeChainCandidateDrain(short, f.launch, err)
				stop()
				if !errors.Is(pending, context.DeadlineExceeded) || !errors.Is(pending, errDesktopNodeChainMeasurementPending) || !mtuSuspended(f.a) {
					releaseWorker()
					t.Fatal("retry renewed its caller or released an unjoined hold", pending)
				}
				if retryDesktopNodeChainCandidateDrain(context.Background(), &desktopNodeLaunch{chain: &desktopNodeChainLaunch{}}, pending) == nil {
					releaseWorker()
					t.Fatal("retained failure changed native launch")
				}
				releaseWorker()
				joined, stop := context.WithTimeout(context.Background(), 5*time.Second)
				joinErr := retryDesktopNodeChainCandidateDrain(joined, f.launch, pending)
				stop()
				if joinErr != nil {
					t.Fatal("exact original retry did not join", joinErr)
				}
				finish(true)
				if retryDesktopNodeChainCandidateDrain(context.Background(), f.launch, pending) != nil {
					t.Fatal("joined original handle was not idempotent")
				}
			}
			if fault == "success" && (err != nil || !s.Drained) {
				t.Fatal("original candidate exchange", err)
			}
			if fault != "success" && err == nil {
				t.Fatal("failed candidate gained a score")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if f.launch.chain.candidateGeneration != generation+1 || f.launch.chain.candidateLast == "" || mtuSuspended(f.a) {
				t.Fatal("candidate did not join its original hold")
			}
			for _, kind := range []string{"source", "live", "request", "cancel"} {
				if _, err := f.launch.directoryRoot.Lstat("node-chain-typed-candidate-" + kind + ".json"); !os.IsNotExist(err) {
					t.Fatal("owned mailbox retained after joined result", kind, err)
				}
			}
		})
	}
}

func TestDesktopTypedConnectedSOCKSCandidateMailbox(t *testing.T) {
	testDesktopTypedConnectedCandidateMailbox(t, "socks5")
}
func TestDesktopTypedConnectedHTTPCandidateMailbox(t *testing.T) {
	testDesktopTypedConnectedCandidateMailbox(t, "http-connect")
}
func TestDesktopTypedConnectedHTTPSCandidateMailbox(t *testing.T) {
	testDesktopTypedConnectedCandidateMailbox(t, "https-connect")
}
