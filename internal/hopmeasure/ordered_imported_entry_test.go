package hopmeasure

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

type importedEntryTestEngine struct {
	*importedNodesMeasurementFixture
}

func (e *importedEntryTestEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	switch tag {
	case e.hops[0].Tag:
		return e.public[0].Dial(ctx, "external-entry", address)
	case e.hops[1].Tag:
		return e.public[1].Dial(ctx, "external-entry", address)
	case e.hops[2].Tag:
		return e.private.Dial(ctx, "proxy", address)
	default:
		return nil, errors.New("unselected test route")
	}
}

func TestOrderedImportedEntryFiftyOriginalResponses(t *testing.T) {
	legacy, private := fixture(t)
	hops := importedNodesHops(3, 0, 1)
	hops[2].API, hops[2].Token, hops[2].Proof = legacy.hops[1].API, legacy.hops[1].Token, legacy.hops[1].Proof
	engine := &importedEntryTestEngine{&importedNodesMeasurementFixture{private: private, public: [2]*publicFixture{newPublicFixture(t), newPublicFixture(t)}, hops: hops}}
	if _, err := NewOrderedImportedNodesContext(t.Context(), engine, hops); err == nil {
		t.Fatal("custom first admitted by the older paired-entry constructor")
	}
	if _, err := NewOrderedImportedNodesServerContext(t.Context(), engine, hops); err == nil {
		t.Fatal("custom first admitted by the paired Server constructor")
	}
	base, err := NewOrderedImportedEntryContext(t.Context(), engine, hops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := base.Close(); err != nil {
			t.Error(err)
		}
	})
	roots := x509.NewCertPool()
	for _, provider := range engine.public {
		roots.AddCert(provider.server.Certificate())
	}
	base.publicTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	latency, err := NewOrderedLatencyContext(t.Context(), base, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := latency.Close(); err != nil {
			t.Error(err)
		}
	})
	for position, hop := range hops {
		request := fmt.Sprintf("%032x", position+1)
		if err := latency.Start(request, hop.ID); err != nil {
			t.Fatal(err)
		}
		state := orderedLatencyResult(t, latency, request)
		if state.Failure != "" || len(state.Results) != 1 {
			t.Fatal(state)
		}
		row := state.Results[0]
		if !row.Ready || row.Kind != hop.Kind || row.Role != hop.Role || row.ID != hop.ID || row.Benchmark == nil || row.Benchmark.Attempts != 50 || row.Benchmark.Failed != 0 || row.Benchmark.Distribution == nil || row.Benchmark.Distribution.Samples != 50 {
			t.Fatal("incomplete measured original route", position)
		}
		var saved OrderedLatencyReceipt
		if err := json.Unmarshal([]byte(latency.SavedJSON(hop.ID)), &saved); err != nil || saved.Position != position || saved.Request != request || saved.NodeID != hop.ID {
			t.Fatal("changed saved position", err)
		}
	}
	for i, public := range engine.public {
		if public.downloaded.Load() != 50 {
			t.Fatal("public benchmark did not traverse its own TLS provider", i)
		}
	}
	private.mu.Lock()
	final := private.requests["proxy"]
	entry := private.requests["entry-wg"]
	private.mu.Unlock()
	if final != 50 || entry != 0 || engine.held.Load() || engine.releases.Load() != 3 {
		t.Fatal("borrowed private entry or failed to drain benchmark")
	}
}

func TestOrderedPrivateResponseMixedEntryUsesOnlyCapturedFinal(t *testing.T) {
	legacy, private := fixture(t)
	hops := importedNodesHops(3, 0, 1)
	hops[2].API, hops[2].Token, hops[2].Proof = legacy.hops[1].API, legacy.hops[1].Token, legacy.hops[1].Proof
	engine := &importedEntryTestEngine{&importedNodesMeasurementFixture{private: private, public: [2]*publicFixture{newPublicFixture(t), newPublicFixture(t)}, hops: hops}}
	service, err := NewOrderedImportedEntryContext(t.Context(), engine, hops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	id := strings.Repeat("e", 32)
	if err := service.StartOrderedResponseContext(t.Context(), id, 2); err != nil {
		t.Fatal(err)
	}
	state := latencyStatus(t, service, id)
	if len(state.Results) != 1 || state.Results[0].ID != hops[2].ID {
		t.Fatal("lost original private final or invented entry result", state)
	}
	if _, err := service.CompletedOrderedResponseContext(t.Context(), id, 2); err != nil {
		t.Fatal(err)
	}
	for _, provider := range engine.public {
		provider.mu.Lock()
		n := len(provider.tags)
		provider.mu.Unlock()
		if n != 0 {
			t.Fatal("imported entry borrowed a private measurement")
		}
	}
	private.mu.Lock()
	defer private.mu.Unlock()
	if len(private.requests) != 1 || private.requests["proxy"] != 2 {
		t.Fatal("expected two actual native final requests", private.requests)
	}
}
