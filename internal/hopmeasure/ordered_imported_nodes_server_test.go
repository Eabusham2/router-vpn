package hopmeasure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func importedNodesServerHops(count int, positions ...int) []Hop {
	hops := importedNodesHops(count, positions...)
	for i := 1; i < len(hops); i++ {
		hops[i].Tag = fmt.Sprintf("routervpn-chain-server-%d-%s", i, strings.Repeat("a", 16))
	}
	return hops
}
func TestOrderedImportedNodesServerOriginalInventory(t *testing.T) {
	for count := 3; count <= 8; count++ {
		for _, layout := range []string{"adjacent", "sparse"} {
			t.Run(fmt.Sprintf("%d/%s", count, layout), func(t *testing.T) {
				var positions []int
				for i := 1; i < count-1; i++ {
					if layout == "adjacent" || i%2 == 1 {
						positions = append(positions, i)
					}
				}
				hops := importedNodesServerHops(count, positions...)
				original := append([]Hop(nil), hops...)
				engine := &testEngine{generation: "original-Server-owner"}
				service, err := NewOrderedImportedNodesServerContext(t.Context(), engine, hops)
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				for i := range hops {
					hops[i].Tag = "replaced"
					retained := service.hops[i]
					retained.Label = original[i].Label
					if !reflect.DeepEqual(retained, original[i]) {
						t.Fatal("original inventory not frozen")
					}
				}
				if _, err := NewOrderedImportedNodesContext(t.Context(), engine, original); err == nil {
					t.Fatal("Local constructor admitted Server suffix")
				}
			})
		}
	}
}
func TestOrderedImportedNodesServerInventoryRefusals(t *testing.T) {
	cases := map[string]func([]Hop){
		"entry-public": func(h []Hop) { h[0].Kind = "public-path" }, "final-public": func(h []Hop) { h[len(h)-1].Kind = "public-path" },
		"missing-public":               func(h []Hop) { h[1].Kind = "private-node"; h[3].Kind = "private-node" },
		"private-credential-on-public": func(h []Hop) { h[1].Token = "foreign" }, "private-proof-on-public": func(h []Hop) { h[3].Proof = strings.Repeat("a", 64) },
		"private-API-on-public": func(h []Hop) { h[1].API = "http://10.0.0.1" }, "wrong-role": func(h []Hop) { h[1].Role = "exit" },
		"swapped-tags": func(h []Hop) { h[1].Tag, h[3].Tag = h[3].Tag, h[1].Tag }, "wrong-generation": func(h []Hop) { h[3].Tag = "routervpn-chain-server-3-" + strings.Repeat("b", 16) },
		"Local-tag": func(h []Hop) { h[1].Tag = orderedHops(5)[1].Tag }, "duplicate-identity": func(h []Hop) { h[3].ID = h[1].ID }, "duplicate-private-proof": func(h []Hop) { h[4].Proof = h[0].Proof },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := importedNodesServerHops(5, 1, 3)
			mutate(h)
			service, err := NewOrderedImportedNodesServerContext(t.Context(), &testEngine{generation: "original"}, h)
			if err == nil || service != nil {
				t.Fatal("foreign public/Server inventory admitted")
			}
		})
	}
}
func TestOrderedImportedNodesServerFiftyOriginalResponses(t *testing.T) {
	service, engine := importedNodesLatencyFixtureOwned(t, true)
	assertImportedNodesFiftyOriginalTags(t, service, engine)
}

func TestOrderedImportedNodesServerRefusesIncompleteTLSStaleAndCancelledResults(t *testing.T) {
	for _, fault := range []string{"failed-fiftieth", "untrusted-second", "generation-replaced", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			service, engine := importedNodesLatencyFixtureOwned(t, true)
			first, second := engine.hops[1], engine.hops[2]
			for i, hop := range []Hop{first, second} {
				request := fmt.Sprintf("%032x", i+1)
				if err := service.Start(request, hop.ID); err != nil {
					t.Fatal(err)
				}
				state := orderedLatencyResult(t, service, request)
				if state.Failure != "" || len(state.Results) != 1 || !state.Results[0].Ready {
					t.Fatal("baseline did not reach both original TLS providers", state)
				}
			}
			savedFirst, savedSecond := service.SavedJSON(first.ID), service.SavedJSON(second.ID)
			beforeFirst, beforeSecond := engine.public[0].downloaded.Load(), engine.public[1].downloaded.Load()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch fault {
			case "failed-fiftieth":
				var attempts atomic.Int32
				engine.public[1].dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					if attempts.Add(1) == 50 {
						return nil, errors.New("second import's original fiftieth connection refused")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp", engine.public[1].server.Listener.Addr().String())
				}
			case "untrusted-second":
				service.service.publicTLS = engine.public[0].tls
			case "generation-replaced", "cancel":
				var observations atomic.Int32
				engine.before = func(ctx context.Context) error {
					if observations.Add(1) == 12 {
						if fault == "cancel" {
							cancel()
						} else {
							engine.private.mu.Lock()
							engine.private.generation = "replacement-original-engine"
							engine.private.mu.Unlock()
						}
					}
					return ctx.Err()
				}
			}
			request := strings.Repeat("c", 32)
			if err := service.StartContext(ctx, request, second.ID); err != nil {
				t.Fatal("control did not enter the original selected worker", err)
			}
			state := orderedLatencyResult(t, service, request)
			for _, row := range state.Results {
				if row.Ready || row.Benchmark != nil {
					t.Fatal("partial or substituted imported response published", row)
				}
			}
			if service.SavedJSON(first.ID) != savedFirst || service.SavedJSON(second.ID) != savedSecond || engine.held.Load() || engine.releases.Load() != 3 {
				t.Fatal("failed second import replaced an original result or escaped join")
			}
			if engine.public[0].downloaded.Load() != beforeFirst {
				t.Fatal("second import's failed measurement used the first import")
			}
			actual := engine.public[1].downloaded.Load() - beforeSecond
			if fault == "failed-fiftieth" && actual != 49 || fault == "untrusted-second" && actual != 0 || (fault == "generation-replaced" || fault == "cancel") && (actual == 0 || actual >= 50) {
				t.Fatal("control did not reach its intended original response boundary", actual)
			}
		})
	}
}
