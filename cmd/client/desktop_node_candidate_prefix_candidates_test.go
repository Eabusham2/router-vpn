//go:build linux || windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"router-vpn/internal/hopmeasure"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestDesktopCandidatePrefixReceiptRequiresCompleteFiftySampleSource(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	q.Scope = orderedCandidateSavedPrefixScope
	p := beginOrderedPreparationFixture(t, a, q)
	c, id := p.inventory, q.CandidateIDs[0]
	good := desktopCandidateStatusFixture(t, c, id)
	good.CaptureSHA256 = p.prefixPreparation.CaptureSHA256()
	if err := validateDesktopNodeCandidatePrefixStatus(p.prefixPreparation, id, good, time.Now()); err != nil {
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
			if validateDesktopNodeCandidatePrefixStatus(p.prefixPreparation, id, s, time.Now()) == nil {
				t.Fatal("forged or incomplete score accepted")
			}
		})
	}
}

// The child here is a protocol double. Published native child tests count the
// real fifty TCP connections; this fixture checks parent ownership and join.
func TestDesktopCandidatePrefixMailboxJoinsBeforePublication(t *testing.T) {
	for _, fault := range []string{"success", "cancel", "cancel-delayed", "wrong-capture", "partial-samples", "catalog-away-back"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopCandidatePrefixOwnedFixture(t, "wg", 0)
			f.start(t)
			stopHeartbeat := desktopPrefixMailboxHeartbeat(t, f)
			p := f.purpose
			c, id := p.inventory, p.request.CandidateIDs[0]
			r := &orderedCandidatePreparedRuntime{preparation: p, catalog: c}
			current := func(ctx context.Context) error {
				if err := p.sourceCurrent(ctx); err != nil {
					return err
				}
				return desktopCandidatePrefixCurrent(ctx, f.a, f.launch)
			}
			generation := f.launch.candidatePrefix.candidateGeneration
			ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.RequestTimeout)
			defer cancel()
			release := make(chan struct{})
			done := make(chan error, 1)
			workerContext, stopWorker := context.WithCancel(context.Background())
			t.Cleanup(func() {
				cancel()
				stopWorker()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("original modeled prefix worker did not join")
				}
			})
			go func() {
				defer close(done)
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					raw, err := readDesktopRuntimeFile(f.launch, "node-candidate-prefix-request.json", 16384)
					if err == nil {
						var q desktopNodeCandidatePrefixRequest
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
								body, e := readDesktopRuntimeFile(f.launch, "node-candidate-prefix-cancel.json", 16384)
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
							select {
							case <-release:
							case <-workerContext.Done():
								done <- workerContext.Err()
								return
							} // Original modeled worker remains retained until release.
						}
						s := desktopCandidateStatusFixture(t, c, id)
						s.CaptureSHA256 = p.prefixPreparation.CaptureSHA256()
						s.Request = q.Request
						if fault == "wrong-capture" {
							s.CaptureSHA256 = strings.Repeat("f", 64)
						}
						if fault == "partial-samples" {
							s.Results[0].Benchmark.Distribution.Samples--
						}
						result := desktopNodeCandidatePrefixResult{desktopNodeCandidatePrefixRequest: q, CompletedAt: time.Now().UnixMilli(), Status: s}
						body, _ := json.Marshal(result)
						// Match the native producer's atomic result publication.
						// A completed previous receipt remains until this request
						// replaces it; the parent's last-request guard ignores it.
						f.launch.workspaceMu.Lock()
						err := desktopExternalDirectoryCurrent(f.launch)
						if err == nil {
							err = f.launch.directoryRoot.WriteFile(".node-candidate-prefix-result.json.pending", body, 0600)
						}
						if err == nil {
							err = f.launch.directoryRoot.Rename(".node-candidate-prefix-result.json.pending", "node-candidate-prefix-result.json")
						}
						f.launch.workspaceMu.Unlock()
						if err != nil {
							done <- err
							return
						}
						if err := f.launch.directoryRoot.Remove("node-candidate-prefix-request.json"); err != nil {
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
					case <-workerContext.Done():
						done <- workerContext.Err()
						return
					}
				}
			}()
			if err := p.holdLease(ctx); err != nil {
				t.Fatal(err)
			}
			s, err := exchangeDesktopNodeCandidatePrefixObserved(ctx, r, id, current, current)
			if fault == "cancel-delayed" {
				if !errors.Is(err, errDesktopNodeChainMeasurementPending) || !mtuSuspended(f.a) {
					close(release)
					t.Fatal("unjoined native request lost its original parent hold", err)
				}
				short, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
				pending := retryDesktopNodeCandidatePrefixDrain(short, f.launch, err)
				stop()
				if !errors.Is(pending, context.DeadlineExceeded) || !errors.Is(pending, errDesktopNodeChainMeasurementPending) || !mtuSuspended(f.a) {
					close(release)
					t.Fatal("retry renewed its caller or released an unjoined hold", pending)
				}
				if retryDesktopNodeCandidatePrefixDrain(context.Background(), &desktopNodeLaunch{candidatePrefix: &desktopNodeCandidatePrefixLaunch{}}, pending) == nil {
					close(release)
					t.Fatal("retained failure changed native launch")
				}
				close(release)
				joined, stop := context.WithTimeout(context.Background(), 5*time.Second)
				joinErr := retryDesktopNodeCandidatePrefixDrain(joined, f.launch, pending)
				stop()
				if joinErr != nil {
					t.Fatal("exact original retry did not join", joinErr)
				}
				if retryDesktopNodeCandidatePrefixDrain(context.Background(), f.launch, pending) != nil {
					t.Fatal("joined original handle was not idempotent")
				}
			}
			if fault == "success" && (err != nil || !s.Drained) {
				t.Fatal("original candidate exchange", err)
			}
			if fault != "success" && err == nil {
				t.Fatal("failed candidate gained a score")
			}
			if f.launch.candidatePrefix.candidateGeneration == generation {
				cancel()
				stopWorker()
			}
			select {
			case workerErr := <-done:
				if workerErr != nil {
					t.Fatal("original modeled prefix worker", workerErr)
				}
			case <-time.After(3 * time.Second):
				cancel()
				stopWorker()
				t.Fatal("original modeled prefix worker did not complete its bounded join")
			}
			if f.launch.candidatePrefix.candidateGeneration != generation+1 || f.launch.candidatePrefix.candidateLast == "" || !mtuSuspended(f.a) {
				t.Fatal("candidate did not join its original hold")
			}
			for _, kind := range []string{"live", "request", "cancel"} {
				if _, err := f.launch.directoryRoot.Lstat("node-candidate-prefix-" + kind + ".json"); !os.IsNotExist(err) {
					t.Fatal("owned mailbox retained after joined result", kind, err)
				}
			}
			stopHeartbeat()
			if err := p.retireNative(context.Background()); err != nil {
				t.Fatal("prefix native retirement", err)
			}
			if mtuSuspended(f.a) || !p.nativeDown {
				t.Fatal("joined prefix retained its original MTU lease")
			}

		})
	}
}

// The real native loop continuously publishes these same original private
// records. This explicit child double renews only its heartbeat timestamps;
// root's foreign/stale-ready fixtures retain their manually controlled files.
func desktopPrefixMailboxHeartbeat(t *testing.T, f *desktopCandidatePrefixOwnedFixture) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready, live := f.ready, f.live
	write := func() error {
		ready.ObservedAt = time.Now().UnixMilli()
		live.Heartbeat = ready.ObservedAt
		f.launch.workspaceMu.Lock()
		defer f.launch.workspaceMu.Unlock()
		if err := desktopExternalDirectoryCurrent(f.launch); err != nil {
			return err
		}
		for name, value := range map[string]any{"node-candidate-prefix-ready.json": ready, "node-mtu-status.json": live} {
			raw, err := json.Marshal(value)
			if err != nil {
				return err
			}
			temporary := "." + name + ".pending"
			if err := f.launch.directoryRoot.WriteFile(temporary, raw, 0600); err != nil {
				return err
			}
			if err := f.launch.directoryRoot.Rename(temporary, name); err != nil {
				return err
			}
		}
		return nil
	}
	if err := write(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-tick.C:
				if err := write(); err != nil {
					done <- err
					return
				}
			}
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error("original modeled prefix heartbeat", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("original modeled prefix heartbeat did not join")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func TestDesktopCandidatePrefixDrainHonorsHeldLifecycleAndRetainsOriginalHandle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		launch := &desktopNodeLaunch{candidatePrefix: &desktopNodeCandidatePrefixLaunch{}}
		retired := 0
		handle := &desktopNodeCandidatePrefixRetirement{launch: launch, request: strings.Repeat("a", 32), run: func(ctx context.Context) error { retired++; return ctx.Err() }}
		launch.candidatePrefix.candidatePending = handle
		failure := &desktopNodeCandidatePrefixPendingError{retirement: handle, cause: errors.New("original pending worker")}
		launch.candidatePrefix.mu.Lock()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		done := make(chan error, 1)
		go func() { done <- retryDesktopNodeCandidatePrefixDrain(ctx, launch, failure) }()
		synctest.Wait()
		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errDesktopNodeChainMeasurementPending) {
				t.Fatal("held lifecycle lost bounded original retry", err)
			}
		default:
			t.Fatal("prefix retry waited past its original caller")
		}
		cancel()
		launch.candidatePrefix.mu.Unlock()
		if retired != 0 || handle.joined.Load() || launch.candidatePrefix.candidatePending != handle {
			t.Fatal("failed lifecycle lock discarded original native cleanup")
		}
		if err := retryDesktopNodeCandidatePrefixDrain(context.Background(), launch, failure); err != nil {
			t.Fatal(err)
		}
		if retired != 1 || !handle.joined.Load() || launch.candidatePrefix.candidatePending != nil {
			t.Fatal("original retry did not finish its exact cleanup")
		}
	})
}
