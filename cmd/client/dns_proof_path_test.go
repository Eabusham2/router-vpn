package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func dnsPathFixture(t *testing.T) (*app, *sessionTracker, observedConnection, string) {
	t.Helper()
	a, _, session := asyncPathFixture(t, "http://10.77.0.1:8787")
	tracker := sessionTrackerFor(a)
	tracker.dnsProofRunning = true
	tracker.dnsProofLastAttempt = time.Now()
	tracker.session.DNSProof = dnsProofState{Status: "checking"}
	return a, tracker, tracker.capture(), session.ID
}

func successfulDNSProof(context.Context, *app, observedConnection, string) dnsProofState {
	return dnsProofState{Mode: "custom", Host: "9.9.9.9", Status: "passed", LatencyMs: 2.5, Reason: "test resolver evidence"}
}

func TestDNSProofPathRejectsStaleObservationBeforeProbe(t *testing.T) {
	for _, change := range []string{"session", "runtime", "phase", "proof", "graph", "profile", "owner"} {
		t.Run(change, func(t *testing.T) {
			a, tracker, snapshot, id := dnsPathFixture(t)
			switch change {
			case "session":
				id = "older-session"
			case "runtime":
				a.state.RuntimeMode = "hysteria2"
			case "phase":
				a.state.Phase = "checking"
			case "proof":
				tracker.session.PathProof = "failed"
			case "graph":
				clearActiveMultihopGraph(a)
			case "profile":
				a.profiles.Profiles[1].APIToken = "rotated"
			case "owner":
				sessionTrackers.Delete(a)
			}
			calls := 0
			tracker.proveDNSAsyncWithProbe(id, snapshot, "shadowsocks", func(context.Context, *app, observedConnection, string) dnsProofState {
				calls++
				return dnsProofState{Status: "passed"}
			})
			if calls != 0 || tracker.snapshot(0).DNSProof.Status == "passed" {
				t.Fatal("stale observation started a DNS probe")
			}
		})
	}
}

func TestDNSProofPathCancelsAndDiscardsOnSessionGraphOrPolicyChange(t *testing.T) {
	for _, change := range []string{"disconnect", "runtime", "session", "graph", "lifecycle", "exit-policy", "entry-credential"} {
		t.Run(change, func(t *testing.T) {
			a, tracker, snapshot, id := dnsPathFixture(t)
			started, done := make(chan struct{}), make(chan struct{})
			var cancelled atomic.Bool
			go func() {
				defer close(done)
				tracker.proveDNSAsyncWithProbe(id, snapshot, "shadowsocks", func(ctx context.Context, owner *app, _ observedConnection, _ string) dnsProofState {
					if release, err := owner.beginNodeBoundOperation(); err != nil {
						t.Error("network work holds the operation lock")
					} else {
						release()
					}
					close(started)
					select {
					case <-ctx.Done():
						cancelled.Store(true)
					case <-time.After(2 * time.Second):
						t.Error("DNS proof context was not cancelled")
					}
					// Even a resolver that returns a successful late result must not
					// publish it into the replacement path/session.
					return successfulDNSProof(ctx, owner, snapshot, "shadowsocks")
				})
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("owned DNS work did not start")
			}
			switch change {
			case "disconnect":
				a.mu.Lock()
				a.state.Connected = false
				a.state.Phase = "stopping"
				a.mu.Unlock()
			case "runtime":
				a.mu.Lock()
				a.state.RuntimeMode = "hysteria2"
				a.mu.Unlock()
			case "session":
				tracker.mu.Lock()
				tracker.session.ID = "new-session"
				tracker.session.DNSProof = dnsProofState{Status: "checking", Reason: "new owner"}
				tracker.mu.Unlock()
			case "graph":
				g, _ := getActiveMultihopGraph(a)
				g.Started = g.Started.Add(time.Second)
				activeMultihopGraphs.Store(a, g)
			case "lifecycle":
				homeExitProofs.Delete(a)
			case "exit-policy":
				a.mu.Lock()
				a.profiles.Profiles[1].DNSHost = "8.8.8.8"
				a.mu.Unlock()
			case "entry-credential":
				a.mu.Lock()
				a.profiles.Profiles[0].APIToken = "new-entry-token"
				a.mu.Unlock()
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("DNS worker did not terminate")
			}
			current := tracker.snapshot(0)
			if !cancelled.Load() || current.DNSProof.Status == "passed" || current.DNSProof.LatencyMs != 0 {
				t.Fatalf("stale DNS proof survived: %+v", current.DNSProof)
			}
			tracker.mu.Lock()
			running := tracker.dnsProofRunning
			tracker.mu.Unlock()
			if change == "session" {
				if !running || current.DNSProof.Reason != "new owner" {
					t.Fatal("old worker modified the new DNS proof owner")
				}
			} else if running {
				t.Fatal("terminated DNS worker retained its running flag")
			}
			a.mu.Lock()
			connected := a.state.Connected
			a.mu.Unlock()
			if change != "disconnect" && !connected {
				t.Fatal("measurement cleanup stopped the VPN")
			}
		})
	}
}

func TestDNSProofPathAdoptionRechecksBeforeObserverTick(t *testing.T) {
	for _, change := range []string{"graph", "transaction", "unchanged", "resolver-failed"} {
		t.Run(change, func(t *testing.T) {
			a, tracker, snapshot, id := dnsPathFixture(t)
			if change == "transaction" {
				a.operationMu.Lock()
				defer a.operationMu.Unlock()
			}
			tracker.proveDNSAsyncWithProbe(id, snapshot, "shadowsocks", func(ctx context.Context, _ *app, _ observedConnection, _ string) dnsProofState {
				if change == "graph" {
					g, _ := getActiveMultihopGraph(a)
					g.Started = g.Started.Add(time.Second)
					activeMultihopGraphs.Store(a, g)
				}
				if change == "resolver-failed" {
					return dnsProofState{Status: "failed", Reason: "resolver did not answer"}
				}
				return successfulDNSProof(ctx, a, snapshot, "shadowsocks")
			})
			current := tracker.snapshot(0)
			want := "not-proven"
			if change == "unchanged" {
				want = "passed"
			}
			if change == "resolver-failed" {
				want = "failed"
			}
			if current.DNSProof.Status != want {
				t.Fatalf("got=%+v want=%s", current.DNSProof, want)
			}
			if tracker.dnsProofRunning {
				t.Fatal("completed DNS proof retained ownership")
			}
			if (tracker.dnsProofBinding != nil) != (want == "passed") {
				t.Fatal("successful proof lifetime not bound to the current path")
			}
		})
	}
}

func TestDNSProofPassedStateInvalidatesOnLaterPathChanges(t *testing.T) {
	for _, change := range []string{"graph", "credentials", "dns-policy", "runtime", "lifecycle", "measurement-only"} {
		t.Run(change, func(t *testing.T) {
			a, tracker, snapshot, id := dnsPathFixture(t)
			tracker.proveDNSAsyncWithProbe(id, snapshot, "shadowsocks", successfulDNSProof)
			if tracker.snapshot(0).DNSProof.Status != "passed" {
				t.Fatal("initial valid proof not adopted")
			}
			switch change {
			case "graph":
				g, _ := getActiveMultihopGraph(a)
				g.Started = g.Started.Add(time.Second)
				activeMultihopGraphs.Store(a, g)
			case "credentials":
				a.profiles.Profiles[0].APIToken = "rotated"
			case "dns-policy":
				a.profiles.Profiles[1].DNSHost = "1.1.1.1"
			case "runtime":
				a.state.RuntimeMode = "hysteria2"
			case "lifecycle":
				homeExitProofs.Delete(a)
			case "measurement-only":
				a.profiles.Profiles[1].PublicIP = "203.0.113.17"
				a.profiles.Profiles[1].LatencyMedianMs = 8
			}
			// Hold scheduling for this test: the next proof is a separate job.
			tracker.dnsProofRunning = true
			tracker.observe(tracker.capture())
			current := tracker.snapshot(0)
			if change == "measurement-only" {
				if current.DNSProof.Status != "passed" {
					t.Fatal("unrelated measurement invalidated good DNS proof")
				}
			} else if current.DNSProof.Status == "passed" || current.DNSProof.LatencyMs != 0 {
				t.Fatalf("old DNS proof survived %s: %+v", change, current.DNSProof)
			}
		})
	}
}

func TestSelectedDNSLookupReceivesCancellationAndCannotAdoptLateSuccess(t *testing.T) {
	for _, scenario := range []string{"working", "before", "in-flight", "empty", "runtime-mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			a, tracker, snapshot, _ := dnsPathFixture(t)
			root := clientRoot(a)
			config := filepath.Join(root, "run", "owned", "sing-box.json")
			writeDNSRuntimeTestConfig(t, config, "custom", "9.9.9.9", 53)
			if err := registerActiveDNSRuntimeConfig(a, "exit", "shadowsocks", config); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { activeDNSRuntimeIdentities.Delete(a) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "before" {
				cancel()
			}
			if scenario == "runtime-mismatch" {
				snapshot.Profile.DNSHost = "1.1.1.1"
			}
			calls := 0
			result := proveSelectedDNSWithLookup(ctx, a, snapshot, "shadowsocks", func(ctx context.Context, host string) ([]string, error) {
				calls++
				if host != "example.com" {
					t.Fatal("wrong resolver question")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("resolver work has no bound")
				}
				if scenario == "in-flight" {
					cancel()
					<-ctx.Done()
				}
				if scenario == "empty" {
					return nil, nil
				}
				return []string{"203.0.113.1"}, nil
			})
			if (result.Status == "passed") != (scenario == "working") {
				t.Fatalf("scenario=%s proof=%+v", scenario, result)
			}
			if (scenario == "before" || scenario == "runtime-mismatch") && calls != 0 {
				t.Fatal("preflight failure reached OS resolver")
			}
			if !tracker.snapshot(0).Connected {
				t.Fatal("DNS lookup modified VPN")
			}
		})
	}
}

func TestLocalDNSProxyContextCancelsItsLiveUDPProbe(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- probeLocalDNSProxyContext(ctx, conn.LocalAddr().String()) }()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := conn.ReadFrom(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("local DNS proof kept its cancelled socket")
	}
}

func TestDNSObservationOwnsMutableProfileSlices(t *testing.T) {
	a, tracker, _, _ := dnsPathFixture(t)
	a.profiles.Profiles[1].CustomLayers = []string{"one"}
	a.profiles.Profiles[1].External = &common.ExternalNodeConfig{Protocol: "socks5", SOCKS5: &common.ExternalSOCKS5Config{Host: "old"}}
	snapshot := tracker.capture()
	a.profiles.Profiles[1].CustomLayers[0] = "two"
	a.profiles.Profiles[1].External.SOCKS5.Host = "new"
	if strings.Join(snapshot.Profile.CustomLayers, ",") != "one" || snapshot.Profile.External.SOCKS5.Host != "old" {
		t.Fatal("captured DNS identity follows mutable profile pointers")
	}
}
