package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func desktopCandidateAddCustomSource(t *testing.T, a *app, cipher string) string {
	t.Helper()
	if cipher != "" {
		q := createRequestFor("shadowsocks")
		size := 32
		if cipher == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		q.Method, q.Secret = cipher, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", size)))
		p, err := externalProfileFromCreateRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		p.ID, p.Name, p.StartLayer = "custom-candidate", "Exact custom candidate", "off"
		a.mu.Lock()
		a.profiles.Profiles = append(a.profiles.Profiles, p)
		a.mu.Unlock()
		return p.ID
	}
	return a.profiles.SelectedID
}

func desktopCandidateSourceTestCatalog(t *testing.T, cipher string) (*app, *desktopNodeChainCandidateCatalog, string) {
	t.Helper()
	a, launch := desktopNodeChainLaunchFixture(t, 3, "windows")
	id := desktopCandidateAddCustomSource(t, a, cipher)
	catalog, err := captureDesktopNodeChainCandidateSources(context.Background(), a, launch, 0, []string{id})
	if err != nil {
		t.Fatal(err)
	}
	return a, catalog, id
}

func desktopCandidateTestCatalog(t *testing.T, cipher string) (*desktopNodeChainOwnedFixture, *desktopNodeChainCandidateCatalog, string) {
	t.Helper()
	f := startupProvedNodeChainOwner(t, 3)
	id := desktopCandidateAddCustomSource(t, f.a, cipher)
	sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{ID: "original-ordered-candidates", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}})
	identity, _, err := captureSpeedLabIdentityContext(context.Background(), f.a)
	if err != nil {
		t.Fatal("original candidate path", err)
	}
	catalog, err := captureDesktopNodeChainCandidates(context.Background(), f.a, identity, 0, []string{id})
	if err != nil {
		t.Fatal("original candidate catalog", err)
	}
	return f, catalog, id
}

func desktopCandidateStatusFixture(t *testing.T, c *desktopNodeChainCandidateCatalog, id string) hopmeasure.CandidateStatus {
	t.Helper()
	var meta struct {
		PrefixPosition int    `json:"prefix_position"`
		PrefixID       string `json:"prefix_id"`
		Targets        []struct {
			ID     string `json:"id"`
			Source string `json:"source_sha256"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(c.plan.Metadata()), &meta); err != nil || len(meta.Targets) != 1 {
		t.Fatal("missing candidate metadata", err)
	}
	now := time.Now().UnixMilli()
	return hopmeasure.CandidateStatus{Schema: 1, Measurement: "routed-tcp-connect", PrefixPosition: meta.PrefixPosition, PrefixID: meta.PrefixID,
		CaptureSHA256: c.plan.CaptureSHA256(), CandidateID: id, CandidateSourceSHA256: meta.Targets[0].Source, MeasuredAt: now, ExpiresAt: now + 120000,
		Status: hopmeasure.Status{Stage: "complete", Complete: true, Drained: true, Results: []hopmeasure.Result{{ID: id, Role: "candidate", Kind: "tcp-connect", Ready: true,
			Benchmark: &hopmeasure.LatencyBenchmark{Schema: 1, Measurement: "routed-tcp-connect", Attempts: 50, TrimmedMean: 2, Distribution: &hopmeasure.Latency{Samples: 50, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4}}}}}}
}

func TestDesktopCandidateCatalogGenerationCannotRevive(t *testing.T) {
	a, _ := desktopNodeChainCaptureFixture(t, 3)
	a.mu.Lock()
	defer a.mu.Unlock()
	before, err := a.candidateCatalogRevisionLocked()
	if err != nil {
		t.Fatal(err)
	}
	original := a.profiles.Profiles[2].APIToken
	a.profiles.Profiles[2].APIToken += "-relinked"
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	a.profiles.Profiles[2].APIToken = original
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	after, err := a.candidateCatalogRevisionLocked()
	if err != nil || before == after || strings.SplitN(before, ":", 2)[1] != strings.SplitN(after, ":", 2)[1] {
		t.Fatal("change-away/back revived original catalog")
	}
}

func TestDesktopCandidateCatalogCapturesSavedSources(t *testing.T) {
	for _, cipher := range []string{"", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		name := cipher
		if name == "" {
			name = "paired"
		}
		t.Run(name, func(t *testing.T) {
			a, c, id := desktopCandidateSourceTestCatalog(t, cipher)
			if c.plan.CaptureSHA256() == "" || c.inventorySHA == "" || !strings.Contains(c.plan.Metadata(), id) {
				t.Fatal("lost sealed capture")
			}
			before := c.revision
			a.mu.Lock()
			a.profiles.Profiles[0].UseCount++
			a.profiles.Profiles[0].LatencyMedianMs = 23
			effective := a.profiles.Profiles[0].EffectiveMTU
			a.profiles.Profiles[0].EffectiveMTU = 1300
			revision, err := a.candidateCatalogRevisionLocked()
			a.profiles.Profiles[0].EffectiveMTU = effective
			a.mu.Unlock()
			if err != nil || revision != before {
				t.Fatal("measurement readback edited source generation", err)
			}
			if cipher != "" && len(c.assets) != 0 {
				t.Fatal("custom candidate borrowed paired credentials")
			}
			if _, err := c.launch.chain.policy.NodeChain().NewCandidatePlan(2, c.inventory); err == nil {
				t.Fatal("lazy final SS mislabeled as TCP handshake prefix")
			}
		})
	}
}

func TestDesktopCandidateCatalogRejectsSourceAndSessionChanges(t *testing.T) {
	for _, fault := range []string{"source-same-content-replaced", "source-change-away-back", "catalog-removal", "reader", "session", "network", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			if fault == "reader" {
				f, c, _ := desktopCandidateTestCatalog(t, "")
				f.heartbeat.Lock()
				f.live.Reader++
				f.heartbeat.Unlock()
				f.publishHeartbeat(t)
				if c.current(context.Background()) == nil {
					t.Fatal("changed native reader retained original candidate authority")
				}
				return
			}
			a, c, id := desktopCandidateSourceTestCatalog(t, "")
			// Explicit session/network boundary for the fast live-catalog
			// pulse. This fixture grants no native launch or proof authority;
			// the reader case above and mailbox composition below use the
			// full shipping admission and original owned child.
			network := "original-candidate-network"
			owner := &nativeMultihopRuntime{launch: c.launch, networkIdentityContext: func(ctx context.Context) (string, error) { return network, ctx.Err() }}
			a.state.Connected, a.state.Phase, a.state.RouterID = true, "connected", a.profiles.SelectedID
			setActiveMultihopGraph(a, c.launch.chain.selection)
			graph, _ := getActiveMultihopGraph(a)
			tracker := &sessionTracker{a: a, session: &connectionSession{ID: "original-candidate-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: a.profiles.SelectedID}}
			sessionTrackers.Store(a, tracker)
			nativeMultihopOwners.Store(a, owner)
			t.Cleanup(func() { sessionTrackers.Delete(a); nativeMultihopOwners.Delete(a); activeMultihopGraphs.Delete(a) })
			c.identity = speedLabPathIdentity{Ordered: owner, Graph: graph, GraphOK: true, Tracker: tracker, SessionID: tracker.session.ID, RouterID: a.profiles.SelectedID, StateToken: mtuStateSnapshotToken(a.state), Network: network}
			if c.pulseCurrent(context.Background()) != nil {
				t.Fatal("live catalog fixture could not establish its explicit parent boundary")
			}
			ctx := context.Background()
			switch fault {
			case "source-same-content-replaced", "source-change-away-back":
				path := filepath.Join(clientRoot(a), "generated", id, "shadowsocks", "sing-box.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if fault == "source-same-content-replaced" {
					if err := os.WriteFile(path+".swap", raw, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path+".swap", path); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(path, append(raw, ' '), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					changed := time.Now().Add(-time.Hour)
					if err := os.Chtimes(path, changed, changed); err != nil {
						t.Fatal(err)
					}
				}
			case "catalog-removal":
				a.mu.Lock()
				a.profiles.Profiles = a.profiles.Profiles[:2]
				a.mu.Unlock()
			case "session":
				tracker.mu.Lock()
				tracker.session.ID = "replacement"
				tracker.mu.Unlock()
			case "network":
				network = "replacement-network"
			case "cancelled":
				cancelled, stop := context.WithCancel(ctx)
				stop()
				ctx = cancelled
			}
			if err := c.pulseCurrent(ctx); err == nil {
				t.Fatal("changed original candidate owner accepted")
			}
		})
	}
}

func TestDesktopCandidateReceiptRequiresCompleteFiftySampleSource(t *testing.T) {
	_, c, id := desktopCandidateSourceTestCatalog(t, "")
	good := desktopCandidateStatusFixture(t, c, id)
	if err := validateDesktopNodeChainCandidateStatus(c.plan, id, good, time.Now()); err != nil {
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
			if validateDesktopNodeChainCandidateStatus(c.plan, id, s, time.Now()) == nil {
				t.Fatal("forged or incomplete score accepted")
			}
		})
	}
}

// The native child is an explicit mailbox double here. The real encrypted
// prefix test separately counts all fifty actual destination TCP handshakes.
func TestDesktopCandidateMailboxJoinsBeforePublication(t *testing.T) {
	f, c, id := desktopCandidateTestCatalog(t, "")
	for _, fault := range []string{"success", "cancel", "cancel-delayed", "wrong-capture", "partial-samples", "catalog-away-back"} {
		t.Run(fault, func(t *testing.T) {
			generation := f.launch.chain.candidateGeneration
			ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.RequestTimeout)
			defer cancel()
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					raw, err := readDesktopRuntimeFile(f.launch, "node-chain-candidate-request.json", 16384)
					if err == nil {
						var q desktopNodeChainCandidateRequest
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
								body, e := readDesktopRuntimeFile(f.launch, "node-chain-candidate-cancel.json", 16384)
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
						s := desktopCandidateStatusFixture(t, c, id)
						s.Request = q.Request
						if fault == "wrong-capture" {
							s.CaptureSHA256 = strings.Repeat("f", 64)
						}
						if fault == "partial-samples" {
							s.Results[0].Benchmark.Distribution.Samples--
						}
						result := desktopNodeChainCandidateResult{desktopNodeChainCandidateRequest: q, CompletedAt: time.Now().UnixMilli(), Status: s}
						body, _ := json.Marshal(result)
						// Match the native producer's atomic result publication.
						// A completed previous receipt remains until this request
						// replaces it; the parent's last-request guard ignores it.
						f.launch.workspaceMu.Lock()
						err := desktopExternalDirectoryCurrent(f.launch)
						if err == nil {
							err = f.launch.directoryRoot.WriteFile(".node-chain-candidate-result.json.pending", body, 0600)
						}
						if err == nil {
							err = f.launch.directoryRoot.Rename(".node-chain-candidate-result.json.pending", "node-chain-candidate-result.json")
						}
						f.launch.workspaceMu.Unlock()
						if err != nil {
							done <- err
							return
						}
						if err := f.launch.directoryRoot.Remove("node-chain-candidate-request.json"); err != nil {
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
					close(release)
					t.Fatal("unjoined native request lost its original parent hold", err)
				}
				short, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
				pending := retryDesktopNodeChainCandidateDrain(short, f.launch, err)
				stop()
				if !errors.Is(pending, context.DeadlineExceeded) || !errors.Is(pending, errDesktopNodeChainMeasurementPending) || !mtuSuspended(f.a) {
					close(release)
					t.Fatal("retry renewed its caller or released an unjoined hold", pending)
				}
				if retryDesktopNodeChainCandidateDrain(context.Background(), &desktopNodeLaunch{chain: &desktopNodeChainLaunch{}}, pending) == nil {
					close(release)
					t.Fatal("retained failure changed native launch")
				}
				close(release)
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
				if _, err := f.launch.directoryRoot.Lstat("node-chain-candidate-" + kind + ".json"); !os.IsNotExist(err) {
					t.Fatal("owned mailbox retained after joined result", kind, err)
				}
			}
		})
	}
}

func TestDesktopCandidateLateFinishCannotReleaseReplacementHold(t *testing.T) {
	a := &app{state: state{Mode: "off", Phase: "off"}}
	launch := &desktopNodeLaunch{chain: &desktopNodeChainLaunch{}}
	first, err := beginDesktopNodeChainMeasurementHold(context.Background(), a, launch)
	if err != nil {
		t.Fatal(err)
	}
	first(true)
	second, err := beginDesktopNodeChainMeasurementHold(context.Background(), a, launch)
	if err != nil {
		t.Fatal(err)
	}
	defer second(true)
	first(true)
	if !mtuSuspended(a) || launch.chain.measurementRelease == nil || launch.chain.measurementOwner == nil {
		t.Fatal("late old finish released replacement MTU hold")
	}
	if third, err := beginDesktopNodeChainMeasurementHold(context.Background(), a, launch); err == nil || third != nil {
		t.Fatal("late finish admitted an overlapping measurement")
	}
	second(true)
	if mtuSuspended(a) {
		t.Fatal("original replacement did not release its own hold")
	}
}
