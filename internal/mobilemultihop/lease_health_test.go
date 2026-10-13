package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Exercise the actual selection/controller against private HTTP test peers.
// No OS VPN or physical networking is represented by these policy tests.
func TestServerHealthNeedsAnUnexpiredAcknowledgedLease(t *testing.T) {
	localProbeTargets(t)
	c, e := outcomeController(t, "server")
	if err := c.Run(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.Healthy() {
		t.Fatal("proved server outcome never became healthy")
	}
	// Expire the last acknowledged deadline without waiting for the renewal
	// timer. A native watchdog must not wait on another network operation.
	expired := time.Now().Add(-time.Second)
	c.leaseDeadline.Store(&expired)
	if c.Healthy() {
		t.Fatal("expired server lease still reports healthy")
	}
}

func TestUnacknowledgedServerLeaseCannotBecomeHealthy(t *testing.T) {
	c, e := outcomeController(t, "server")
	c.engine, c.engineID = e, e.Identity()
	e.selected = ServerTag
	c.progress = Progress{Stage: "selected", Complete: true, Execution: "server"}
	c.ownsLease = true // A request may have succeeded remotely, but not proved.
	if c.Healthy() {
		t.Fatal("unacknowledged remote state advertised as healthy")
	}
	// The independent local candidate does not require any server lease.
	c.progress.Execution = "local"
	e.selected = LocalTag
	if !c.Healthy() {
		t.Fatal("local outcome incorrectly requires a relay lease")
	}
}

func TestUncertainReleaseRevokesHealthButRetainsCleanupOwnership(t *testing.T) {
	localProbeTargets(t)
	c, e := outcomeController(t, "server")
	if err := c.Run(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	e.mu.Lock()
	e.rejectCleanup = true
	e.mu.Unlock()
	if err := c.release(); err == nil {
		t.Fatal("unacknowledged cleanup accepted")
	}
	if c.Healthy() {
		t.Fatal("uncertain released relay is still healthy")
	}
	if !c.ownsLease {
		t.Fatal("lost ownership of uncertain cleanup")
	}
	e.mu.Lock()
	e.rejectCleanup = false
	e.mu.Unlock()
	if err := c.release(); err != nil {
		t.Fatal(err)
	}
	if c.ownsLease {
		t.Fatal("confirmed cleanup retained a lease")
	}
}

func TestInvalidRenewalCannotRefreshTheAcknowledgedDeadline(t *testing.T) {
	c, e := outcomeController(t, "server")
	c.engine, c.engineID = e, e.Identity()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := c.leaseDeadline.Load()
	if deadline == nil || !deadline.After(time.Now()) {
		t.Fatal("valid lease acknowledgement did not publish a deadline")
	}
	// Return a structurally valid JSON document with a different owner.
	old := e.servers[c.meta.EntryTag]
	invalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"node_id": "wrong", "expires_at": time.Now().Add(time.Hour)})
	}))
	defer invalid.Close()
	e.servers[c.meta.EntryTag] = invalid
	if err := c.renewLocked(ctx); err == nil {
		t.Fatal("changed lease owner accepted")
	}
	if c.leaseDeadline.Load() != deadline {
		t.Fatal("invalid renewal refreshed deadline")
	}
	e.servers[c.meta.EntryTag] = old
	if err := c.release(); err != nil {
		t.Fatal(err)
	}
	if c.leaseDeadline.Load() != nil {
		t.Fatal("released lease retained its proof deadline")
	}
}

func TestHealthReadDoesNotWaitForLeaseNetworkLock(t *testing.T) {
	localProbeTargets(t)
	c, e := outcomeController(t, "server")
	if err := c.Run(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.leaseMu.Lock()
	done := make(chan bool, 1)
	go func() { done <- c.Healthy() }()
	select {
	case healthy := <-done:
		c.leaseMu.Unlock()
		if !healthy {
			t.Fatal("current proved server path unexpectedly unhealthy")
		}
	case <-time.After(time.Second):
		c.leaseMu.Unlock()
		<-done
		t.Fatal(errors.New("health read waited on the renewal network lock"))
	}
}

func TestExpiredServerActivationCannotPublishSelected(t *testing.T) {
	localProbeTargets(t)
	c, raw := outcomeController(t, "server")
	engine := &activationEngine{fakeEngine: raw}
	engine.afterSelect = func() {
		expired := time.Now().Add(-time.Second)
		c.leaseDeadline.Store(&expired)
	}
	if err := c.Run(context.Background(), engine); err == nil {
		t.Fatal("expired server lease was selected")
	}
	if c.Healthy() {
		t.Fatal("expired activated relay advertised as healthy")
	}
	var progress Progress
	if err := json.Unmarshal([]byte(c.ProgressJSON()), &progress); err != nil {
		t.Fatal(err)
	}
	if progress.Stage != "failed" || !progress.Complete {
		t.Fatal("expired activation lost its failure outcome")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
