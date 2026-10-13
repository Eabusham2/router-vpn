package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"router-vpn/internal/routechoice"
	"sync/atomic"
	"testing"
	"time"
)

func localProbeTargets(t *testing.T) {
	t.Helper()
	previous := Targets
	Targets = []string{"http://1.1.1.1/check"}
	t.Cleanup(func() { Targets = previous })
}
func outcomeController(t *testing.T, execution string) (*Controller, *fakeEngine) {
	t.Helper()
	graph, meta := fixture(t, execution)
	c, err := New(graph, meta)
	if err != nil {
		t.Fatal(err)
	}
	return c, makeEngine(t)
}
func TestPreparedComparisonDoesNotReportHealthy(t *testing.T) {
	c, e := outcomeController(t, "local")
	c.engine = e
	c.engineID = e.Identity()
	if c.Healthy() {
		t.Fatal("unrun comparison is healthy solely because its engine exists")
	}
}
func TestFailedComparisonCannotReportHealthyBeforeClose(t *testing.T) {
	localProbeTargets(t)
	c, e := outcomeController(t, "auto")
	e.badLocal = true
	e.badServer = true
	if err := c.Run(context.Background(), e); !errors.Is(err, routechoice.ErrNoWinner) {
		t.Fatal(err)
	}
	if c.Healthy() {
		t.Fatal("failed comparison reports healthy until someone happens to call Close")
	}
	var progress Progress
	if json.Unmarshal([]byte(c.ProgressJSON()), &progress) != nil || progress.Stage != "failed" || !progress.Complete {
		t.Fatal("failure outcome lost")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestHealthyRejectsSelectorDriftWithoutAnEngineRestart(t *testing.T) {
	localProbeTargets(t)
	c, e := outcomeController(t, "local")
	if err := c.Run(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.Healthy() {
		t.Fatal("proved selected path did not become healthy")
	}
	e.mu.Lock()
	e.selected = ServerTag
	e.mu.Unlock()
	if c.Healthy() {
		t.Fatal("unproved selector change is reported healthy")
	}
}

type activationEngine struct {
	*fakeEngine
	afterSelect func()
}

func (e *activationEngine) Select(tag string) error {
	err := e.fakeEngine.Select(tag)
	if err == nil && e.afterSelect != nil {
		e.afterSelect()
	}
	return err
}
func TestActivationCannotPublishAStaleWinner(t *testing.T) {
	for _, kind := range []string{"network", "engine", "cancel", "selector"} {
		t.Run(kind, func(t *testing.T) {
			localProbeTargets(t)
			c, raw := outcomeController(t, "local")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e := &activationEngine{fakeEngine: raw}
			e.afterSelect = func() {
				switch kind {
				case "network":
					c.NetworkChanged()
				case "engine":
					raw.mu.Lock()
					raw.identity = "replacement"
					raw.mu.Unlock()
				case "cancel":
					cancel()
				case "selector":
					raw.mu.Lock()
					raw.selected = ServerTag
					raw.mu.Unlock()
				}
			}
			if err := c.Run(ctx, e); err == nil {
				t.Fatal("stale winner accepted", kind)
			}
			if c.Healthy() {
				t.Fatal("stale winner reported healthy")
			}
			var state Progress
			_ = json.Unmarshal([]byte(c.ProgressJSON()), &state)
			if state.Stage == "selected" {
				t.Fatal("stale result published as selected")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestCatalogReplyCannotAuthorizeMutationInAChangedSession(t *testing.T) {
	for _, kind := range []string{"engine", "network"} {
		t.Run(kind, func(t *testing.T) {
			c, e := outcomeController(t, "server")
			c.engine = e
			c.engineID = e.Identity()
			puts := atomic.Int32{}
			caps := largeCapabilityFixture(c)
			fallback := e.handler(c.meta.EntryTag)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_ = json.NewEncoder(w).Encode(caps)
					if kind == "network" {
						c.NetworkChanged()
					} else {
						e.mu.Lock()
						e.identity = "replacement"
						e.mu.Unlock()
					}
					return
				}
				if r.Method == http.MethodPut {
					puts.Add(1)
				}
				fallback(w, r)
			}))
			t.Cleanup(server.Close)
			e.servers[c.meta.EntryTag] = server
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := c.acquire(ctx); err == nil {
				t.Fatal("stale catalog authorized a new lease")
			}
			if puts.Load() != 0 || c.ownsLease {
				t.Fatal("changed session mutated a relay", puts.Load())
			}
		})
	}
}
func TestStaleRenewalReplyCannotExtendOwnedExpiry(t *testing.T) {
	c, e := outcomeController(t, "server")
	c.engine = e
	c.engineID = e.Identity()
	fallback := e.handler(c.meta.EntryTag)
	stale := atomic.Bool{}
	puts := atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
		}
		fallback(w, r)
		if stale.Load() && r.Method == http.MethodPut {
			e.mu.Lock()
			e.identity = "replacement"
			e.mu.Unlock()
		}
	}))
	t.Cleanup(server.Close)
	e.servers[c.meta.EntryTag] = server
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	original := c.expected.ExpiresAt
	stale.Store(true)
	if err := c.renewLocked(ctx); err == nil {
		t.Fatal("stale renewal accepted")
	}
	if !c.expected.ExpiresAt.Equal(original) || !c.ownsLease {
		t.Fatal("stale renewal changed proof or discarded cleanup ownership")
	}
	before := puts.Load()
	if err := c.renewLocked(ctx); err == nil || puts.Load() != before {
		t.Fatal("already-stale session sent another mutation")
	}
	if err := c.release(); err != nil {
		t.Fatal("retained old control transport could not acknowledge cleanup", err)
	}
}
