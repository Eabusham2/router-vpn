package mobilemultihop

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This engine models the original native instance and routes using owned pipes.
// The public proof still executes TLS/HTTP and the final proof executes HTTP;
// actual SOCKS and Xray encryption is exercised by the separate native peer gate.
type importedSOCKSXrayProofEngine struct {
	mu            sync.Mutex
	id, selected  string
	meta          Metadata
	public        func(context.Context, string, string) (net.Conn, error)
	dnsFailure    error
	afterDNS      func()
	wrongFinal    bool
	dnsCalls      atomic.Int32
	finalCalls    atomic.Int32
	externalCalls atomic.Int32
	workers       sync.WaitGroup
	t             *testing.T
}

func (e *importedSOCKSXrayProofEngine) Identity() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.id
}
func (e *importedSOCKSXrayProofEngine) IdentityContext(ctx context.Context) (string, error) {
	return e.Identity(), ctx.Err()
}
func (e *importedSOCKSXrayProofEngine) replace() {
	e.mu.Lock()
	e.id = "replacement-native-instance"
	e.mu.Unlock()
}
func (e *importedSOCKSXrayProofEngine) Selected() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.selected
}
func (e *importedSOCKSXrayProofEngine) SelectedContext(ctx context.Context) (string, error) {
	return e.Selected(), ctx.Err()
}
func (e *importedSOCKSXrayProofEngine) Select(tag string) error {
	if tag != LocalTag {
		return errors.New("SOCKS REALITY fixture refused an unowned execution")
	}
	e.mu.Lock()
	e.selected = tag
	e.mu.Unlock()
	return nil
}
func (e *importedSOCKSXrayProofEngine) DNSProof(ctx context.Context) error {
	e.dnsCalls.Add(1)
	if e.afterDNS != nil {
		e.afterDNS()
	}
	return errors.Join(e.dnsFailure, ctx.Err())
}
func (e *importedSOCKSXrayProofEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tag == "entry-wg" {
		return e.public(ctx, "captured-entry", address)
	}
	if (tag != LocalTag && tag != "proxy") || (address != "10.77.0.1:8787" && address != "1.1.1.1:80") {
		return nil, errors.New("SOCKS REALITY fixture refused a foreign proof route")
	}
	client, server := net.Pipe()
	if deadline, ok := ctx.Deadline(); ok {
		_ = server.SetDeadline(deadline)
	}
	e.workers.Add(1)
	go func() {
		defer e.workers.Done()
		defer server.Close()
		stop := context.AfterFunc(ctx, func() { _ = server.Close() })
		defer stop()
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		defer request.Body.Close()
		var body string
		if address == "10.77.0.1:8787" {
			e.finalCalls.Add(1)
			if request.Method != "GET" || request.URL.Path != "/health" || request.Host != address || request.Header.Get("Authorization") != "Bearer "+e.meta.ExitToken {
				e.t.Error("SOCKS REALITY final proof changed its exact paired request")
				return
			}
			node := e.meta.ExitNodeID
			if e.wrongFinal {
				node = "different-paired-node"
			}
			body = fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":"router-vpn-private-agent-v1"}`, node)
		} else {
			e.externalCalls.Add(1)
			if request.Method != "GET" || request.URL.Path != "/check" || request.Header.Get("Authorization") != "" {
				e.t.Error("SOCKS REALITY external probe changed its route or exposed private credentials")
				return
			}
			body = "original-routed-response"
		}
		_, _ = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}()
	return client, nil
}
func (e *importedSOCKSXrayProofEngine) join() {
	done := make(chan struct{})
	go func() { e.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		e.t.Error("original SOCKS REALITY proof worker did not join")
	}
}

func importedSOCKSXrayProofFixture(t *testing.T, fault string) (*Controller, *importedSOCKSXrayProofEngine, *atomic.Int32) {
	t.Helper()
	plan := importedSOCKSXrayCompile(t, importedSOCKSXrayFixture(t))
	certificate, trust := externalPublicProofCertificate(t, "1.1.1.1")
	ip := "203.0.113.88"
	if fault == "wrong-public-ip" {
		ip = "203.0.113.89"
	}
	body := "ip=" + ip + "\n"
	dial, public, _ := externalPublicProofPeer(t, certificate, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	engine := &importedSOCKSXrayProofEngine{id: "original-socks-reality-instance", selected: LocalTag, meta: plan.meta, public: dial, wrongFinal: fault == "wrong-paired-final", t: t}
	plan.engine, plan.engineID, plan.externalResponseTLS = engine, engine.id, trust
	t.Cleanup(engine.join)
	t.Cleanup(func() {
		if err := plan.Close(); err != nil {
			t.Error("original SOCKS REALITY controller did not close", err)
		}
	})
	return plan, engine, public
}

func TestImportedEntrySOCKSRealityVisionRequiresBothProofsAndDNS(t *testing.T) {
	for _, fault := range []string{"success", "wrong-public-ip", "wrong-paired-final", "dns-failure", "cancel-during-dns", "missing-dns-capability", "changed-owner"} {
		t.Run(fault, func(t *testing.T) {
			plan, engine, public := importedSOCKSXrayProofFixture(t, fault)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			switch fault {
			case "dns-failure":
				engine.dnsFailure = errors.New("original selected DNS rejected")
			case "cancel-during-dns":
				engine.afterDNS = cancel
			case "missing-dns-capability":
				plan.engine = &importedNoDNS{Engine: engine}
			case "changed-owner":
				engine.afterDNS = engine.replace
			}
			err := (&trial{owner: plan, tag: LocalTag}).Verify(ctx)
			if fault == "success" {
				if err != nil || public.Load() != 1 || engine.dnsCalls.Load() != 1 || engine.finalCalls.Load() != 1 {
					t.Fatal("SOCKS REALITY lost one of its distinct original proofs", err)
				}
			} else if err == nil {
				t.Fatal("SOCKS REALITY retained a failed or cancelled proof")
			}
			if public.Load() != 1 {
				t.Fatal("SOCKS REALITY negative did not reach the actual public TLS proof")
			}
			if fault != "success" && fault != "wrong-paired-final" && engine.finalCalls.Load() != 0 {
				t.Fatal("SOCKS REALITY continued final proof after a failed original prerequisite")
			}
			if (fault == "wrong-public-ip" || fault == "missing-dns-capability") && engine.dnsCalls.Load() != 0 {
				t.Fatal("SOCKS REALITY manufactured a selected DNS result")
			}
		})
	}
}

type importedSOCKSXrayHopEngine struct{ *importedSOCKSXrayProofEngine }

func (e *importedSOCKSXrayHopEngine) Identity() string {
	return e.importedSOCKSXrayProofEngine.Identity() + ":" + e.Selected()
}
func (e *importedSOCKSXrayHopEngine) IdentityContext(ctx context.Context) (string, error) {
	return e.Identity(), ctx.Err()
}

func TestImportedEntrySOCKSRealityVisionRetainedRuntime(t *testing.T) {
	for _, retirement := range []string{"close", "network-change", "replacement"} {
		t.Run(retirement, func(t *testing.T) {
			plan, engine, public := importedSOCKSXrayProofFixture(t, "success")
			old := Targets
			Targets = []string{"http://1.1.1.1/check"}
			defer func() { Targets = old }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := plan.Run(ctx, engine); err != nil {
				t.Fatal("SOCKS REALITY original Local execution failed", err)
			}
			if !plan.Healthy() || engine.Selected() != LocalTag || !plan.progress.Complete || plan.progress.Execution != "local" || public.Load() == 0 || engine.dnsCalls.Load() == 0 || engine.finalCalls.Load() == 0 || engine.externalCalls.Load() == 0 {
				t.Fatal("SOCKS REALITY became ready without its original Local path and proofs")
			}
			original := &importedSOCKSXrayHopEngine{engine}
			measurement, err := plan.NewImportedHopMeasurement(original)
			if err != nil {
				t.Fatal("proved SOCKS REALITY owner could not create its own hop measurement", err)
			}
			defer measurement.Close()
			switch retirement {
			case "close":
				if err := plan.Close(); err != nil {
					t.Fatal(err)
				}
			case "network-change":
				plan.NetworkChanged()
			case "replacement":
				engine.replace()
			}
			if plan.Healthy() || plan.MatchesEngine(engine) {
				t.Fatal("retired SOCKS REALITY graph kept original readiness")
			}
			if _, err := plan.NewImportedHopMeasurement(original); err == nil {
				t.Fatal("retired SOCKS REALITY graph acquired replacement measurement authority")
			}
			if _, err := (&trial{owner: plan, tag: LocalTag}).ProbeExternal(ctx, "http://1.1.1.1/check"); err == nil {
				t.Fatal("retired SOCKS REALITY graph admitted another routed probe")
			}
		})
	}
}
