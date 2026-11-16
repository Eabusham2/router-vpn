package hopmeasure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOrderedOpenVPNServerPrefixOwnsPositionsAndPublicRole(t *testing.T) {
	for count := 3; count <= 8; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			hops := importedSSServerPrefixHops(count)
			engine := orderedServerAdmissionEngine{}
			service, err := NewOrderedOpenVPNServerPrefixContext(t.Context(), engine, hops)
			if err != nil {
				t.Fatal(err)
			}
			if len(service.hops) != count || service.hops[count-2].Kind != "public-path" {
				t.Fatal("complete selected inventory lost")
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := NewOrderedOpenVPNPrefixContext(t.Context(), engine, hops); err == nil {
				t.Fatal("Server acquired Local tag authority")
			}
			if _, err := NewOrderedServerContext(t.Context(), engine, hops); err == nil {
				t.Fatal("ordinary private path acquired public authority")
			}
			if count > 3 {
				if _, err := NewOrderedImportedServerContext(t.Context(), engine, hops); err == nil {
					t.Fatal("typed trio constructor widened")
				}
			}
		})
	}
	for name, mutate := range map[string]func([]Hop){
		"source":               func(h []Hop) { h[2].Tag = "routervpn-chain-server-2-" + strings.Repeat("b", 16) },
		"position":             func(h []Hop) { h[2].Tag = h[1].Tag },
		"local-prefix":         func(h []Hop) { h[2].Tag = orderedHops(6)[2].Tag },
		"public-earlier":       func(h []Hop) { h[1].Kind = "public-path"; h[1].API, h[1].Token, h[1].Proof = "", "", "" },
		"public-final":         func(h []Hop) { h[5].Kind = "public-path"; h[5].API, h[5].Token, h[5].Proof = "", "", "" },
		"public-private-token": func(h []Hop) { h[4].Token = "borrowed" },
		"duplicate-proof":      func(h []Hop) { h[2].Proof = h[1].Proof },
		"role":                 func(h []Hop) { h[2].Role = "exit" },
	} {
		t.Run(name, func(t *testing.T) {
			hops := importedSSServerPrefixHops(6)
			mutate(hops)
			if _, err := NewOrderedOpenVPNServerPrefixContext(t.Context(), orderedServerAdmissionEngine{}, hops); err == nil {
				t.Fatal("changed original position or role accepted")
			}
		})
	}
}

func TestOrderedOpenVPNServerPrefixMeasuresFiftyOriginalPublicResponses(t *testing.T) {
	for _, fault := range []string{"", "failed-fiftieth"} {
		t.Run(fault, func(t *testing.T) {
			hops := importedSSServerPrefixHops(8)
			public := newPublicFixture(t)
			if fault == "failed-fiftieth" {
				var attempts atomic.Int32
				public.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					if attempts.Add(1) == 50 {
						return nil, errors.New("last original public dial refused")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp", public.server.Listener.Addr().String())
				}
			}
			engine := &importedSSServerPublicEngine{publicFixture: public, tag: hops[6].Tag}
			base, err := NewOrderedOpenVPNServerPrefixContext(t.Context(), engine, hops)
			if err != nil {
				t.Fatal(err)
			}
			base.publicTLS = public.tls
			t.Cleanup(func() {
				if err := base.Close(); err != nil {
					t.Error(err)
				}
			})
			service, err := NewOrderedLatencyContext(t.Context(), base, strings.Repeat("a", 64), strings.Repeat("b", 64))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := service.Close(); err != nil {
					t.Error(err)
				}
			})
			id := strings.Repeat("c", 32)
			if err := service.Start(id, hops[6].ID); err != nil {
				t.Fatal(err)
			}
			state := orderedLatencyResult(t, service, id)
			if engine.active.Load() || engine.releases.Load() != 1 {
				t.Fatal("original measurement activity did not join")
			}
			if fault != "" {
				if public.downloaded.Load() != 49 {
					t.Fatal("causal fiftieth refusal did not retain49 actual responses", public.downloaded.Load())
				}
				for _, row := range state.Results {
					if row.Ready || row.Benchmark != nil {
						t.Fatal("partial public samples published")
					}
				}
				return
			}
			if state.Failure != "" || len(state.Results) != 1 {
				t.Fatal(state)
			}
			row := state.Results[0]
			if !row.Ready || row.ID != hops[6].ID || row.Role != "intermediate" || row.Kind != "public-path" || row.Benchmark == nil || row.Benchmark.Attempts != 50 || row.Benchmark.Failed != 0 || row.Benchmark.Measurement != "routed-https-response-after-tls" || row.Benchmark.Distribution == nil || row.Benchmark.Distribution.Samples != 50 {
				t.Fatal("public fifty response identity changed", row)
			}
			public.mu.Lock()
			calls := len(public.tags)
			public.mu.Unlock()
			if calls != 50 || public.downloaded.Load() != 50 {
				t.Fatal("public response inventory changed", calls, public.downloaded.Load())
			}
		})
	}
}
