package mobilemultihop

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/routechoice"
)

// These execute the original controller and actual HTTP exchanges through the
// existing explicit outbound fixture. They are not native VPN or TLS acceptance.
type legacyProofClockHTTP struct {
	calls   atomic.Int32
	entered chan struct{}
	drained chan struct{}
}

func legacyProofClockFixture(t *testing.T, held bool) (*Controller, *fakeEngine, *legacyProofClockHTTP) {
	t.Helper()
	previous := Targets
	Targets = []string{"http://1.1.1.1/check"}
	t.Cleanup(func() { Targets = previous })
	graph, metadata := fixture(t, "auto")
	c, err := New(graph, metadata)
	if err != nil {
		t.Fatal(err)
	}
	e := &fakeEngine{servers: map[string]*httptest.Server{}, selected: LocalTag, identity: "original-proof-clock-fixture"}
	observation := &legacyProofClockHTTP{entered: make(chan struct{}, 1), drained: make(chan struct{}, 1)}
	for _, tag := range []string{"entry-wg", LocalTag, ServerTag} {
		handler := e.handler(tag)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			observation.calls.Add(1)
			if held {
				select {
				case observation.entered <- struct{}{}:
				default:
				}
				<-r.Context().Done()
				select {
				case observation.drained <- struct{}{}:
				default:
				}
				return
			}
			handler(w, r)
		}))
		e.servers[tag] = server
		t.Cleanup(server.Close)
	}
	// The fixture supplies only the explicit native owner boundary; metadata,
	// HTTP proof, selected tags, comparison probes and lease operations are real.
	c.engine, c.engineID = e, e.Identity()
	c.generation.Store(1)
	t.Cleanup(func() { _ = c.Close() })
	return c, e, observation
}

func legacyProofClockProbe(c *Controller, execution, kind string) func(context.Context) (time.Duration, error) {
	selected, tag := routechoice.Local, LocalTag
	if execution == "server" {
		selected, tag = routechoice.Server, ServerTag
	}
	s := &trial{owner: c, candidate: c.candidate(selected), tag: tag}
	if kind == "private" {
		return s.ProbeLast
	}
	return func(ctx context.Context) (time.Duration, error) { return s.ProbeExternal(ctx, Targets[0]) }
}

func TestControllerProofClockPublishesActualMeasuredResponses(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		for _, kind := range []string{"private", "external"} {
			t.Run(execution+"/"+kind, func(t *testing.T) {
				c, _, observation := legacyProofClockFixture(t, false)
				var captures atomic.Int32
				c.testProofInterval = func() (hopmeasure.Interval, error) {
					captures.Add(1)
					return hopmeasure.StartInterval()
				}
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				elapsed, err := legacyProofClockProbe(c, execution, kind)(ctx)
				if err != nil || elapsed <= 0 || captures.Load() != 1 || observation.calls.Load() != 1 {
					t.Fatal("actual routed proof lost its checked interval", elapsed, err, captures.Load(), observation.calls.Load())
				}
			})
		}
	}
}

func TestControllerProofClockRejectsInvalidOriginalInterval(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		for _, kind := range []string{"private", "external"} {
			for _, phase := range []string{"capture", "completion"} {
				t.Run(execution+"/"+kind+"/"+phase, func(t *testing.T) {
					c, _, observation := legacyProofClockFixture(t, false)
					private := errors.New("test-only private clock failure detail")
					var captures atomic.Int32
					c.testProofInterval = func() (hopmeasure.Interval, error) {
						captures.Add(1)
						if phase == "capture" {
							return hopmeasure.Interval{}, private
						}
						return hopmeasure.Interval{}, nil
					}
					ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
					defer cancel()
					elapsed, err := legacyProofClockProbe(c, execution, kind)(ctx)
					if err == nil || elapsed != 0 || captures.Load() != 1 {
						t.Fatal("unchecked measurement clock admitted original routed proof", execution, kind, phase, elapsed, err)
					}
					if phase == "capture" && !errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) {
						t.Fatal("measurement failure lost typed cause or exposed private detail")
					}
					want := int32(0)
					if phase == "completion" {
						want = 1
					}
					if observation.calls.Load() != want {
						t.Fatal("measurement refusal crossed its original HTTP boundary", phase, observation.calls.Load(), want)
					}
					var progress Progress
					if exactJSON([]byte(c.ProgressJSON()), &progress, 16384) != nil || len(progress.Measurements) != 0 || c.Healthy() {
						t.Fatal("failed measurement published eligible progress")
					}
				})
			}
		}
	}
}

func TestControllerProofClockPreservesOriginalHTTPFailure(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			c, e, observation := legacyProofClockFixture(t, false)
			e.mu.Lock()
			e.badLocal, e.badServer = true, true
			e.mu.Unlock()
			c.testProofInterval = func() (hopmeasure.Interval, error) { return hopmeasure.Interval{}, nil }
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			elapsed, err := legacyProofClockProbe(c, execution, "private")(ctx)
			var status controlError
			if elapsed != 0 || !errors.As(err, &status) || status.status != 500 || observation.calls.Load() != 1 {
				t.Fatal("invalid clock masked the actual HTTP refusal", elapsed, err, observation.calls.Load())
			}
		})
	}
}

func TestControllerProofClockPreservesHeldHTTPCancellation(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		for _, kind := range []string{"private", "external"} {
			t.Run(execution+"/"+kind, func(t *testing.T) {
				c, _, observation := legacyProofClockFixture(t, true)
				c.testProofInterval = func() (hopmeasure.Interval, error) { return hopmeasure.Interval{}, nil }
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				type proofResult struct {
					elapsed time.Duration
					err     error
				}
				result := make(chan proofResult, 1)
				go func() {
					elapsed, err := legacyProofClockProbe(c, execution, kind)(ctx)
					result <- proofResult{elapsed: elapsed, err: err}
				}()
				select {
				case <-observation.entered:
				case <-ctx.Done():
					t.Fatal("held proof did not enter original HTTP exchange", ctx.Err())
				}
				cancel()
				select {
				case got := <-result:
					if got.elapsed != 0 || !errors.Is(got.err, context.Canceled) {
						t.Fatal("invalid clock replaced original cancellation", got.elapsed, got.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("cancelled original HTTP exchange did not return")
				}
				select {
				case <-observation.drained:
				case <-time.After(3 * time.Second):
					t.Fatal("original cancelled HTTP handler did not drain")
				}
				if observation.calls.Load() != 1 {
					t.Fatal("cancellation repeated its original exchange")
				}
			})
		}
	}
}

func TestControllerProofClockCannotBlockLeaseAcquisitionOrDelete(t *testing.T) {
	c, e, observation := legacyProofClockFixture(t, false)
	private := errors.New("test-only failed measurement clock")
	var captures atomic.Int32
	c.testProofInterval = func() (hopmeasure.Interval, error) {
		captures.Add(1)
		return hopmeasure.Interval{}, private
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := c.acquire(ctx); err != nil {
		t.Fatal("measurement clock blocked original lease acquisition", err)
	}
	e.mu.Lock()
	acquired := e.lease != nil
	e.mu.Unlock()
	if !acquired || !c.ownsLease || captures.Load() != 0 || observation.calls.Load() != 2 {
		t.Fatal("lease acquisition entered measurement clock or lost actual GET/PUT", acquired, c.ownsLease, captures.Load(), observation.calls.Load())
	}
	if elapsed, err := legacyProofClockProbe(c, "server", "private")(ctx); elapsed != 0 || !errors.Is(err, private) || captures.Load() != 1 || observation.calls.Load() != 2 {
		t.Fatal("failing proof clock crossed into private target I/O", elapsed, err)
	}
	if err := c.release(); err != nil {
		t.Fatal("measurement clock prevented original authenticated DELETE", err)
	}
	e.mu.Lock()
	retained := e.lease != nil
	e.mu.Unlock()
	if retained || c.ownsLease || captures.Load() != 1 || observation.calls.Load() != 3 {
		t.Fatal("failed measurement retained or replaced the original lease", retained, c.ownsLease, captures.Load(), observation.calls.Load())
	}
}
