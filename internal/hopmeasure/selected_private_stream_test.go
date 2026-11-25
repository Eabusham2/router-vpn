package hopmeasure

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestSelectedPrivateStreamMeasurement(t *testing.T) {
	for _, count := range []int{4, 5, 9, 16, PhysicalTraversalDepth} {
		for _, pos := range slices.Compact([]int{2, count - 2}) {
			for _, server := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/private-%d/server-%t", count, pos, server), func(t *testing.T) {
					mask := make([]bool, count)
					var public []int
					for i := 1; i < count-1; i++ {
						if i != pos {
							mask[i] = true
							public = append(public, i)
						}
					}
					source := ""
					hops := importedNodesHops(count, public...)
					if server {
						source = strings.Repeat("a", 64)
						hops = importedNodesServerHops(count, public...)
					}
					engine := &testEngine{generation: "original-selected-engine"}
					service, err := NewSelectedPrivateStreamContext(t.Context(), engine, hops, mask, pos, source)
					if err != nil || service == nil || service.engine != engine || service.identity != engine.generation || len(service.hops) != count || service.hops[pos].Proof != hops[pos].Proof {
						t.Fatal("original measurement owner, position or credential lost", err)
					}
					if err = service.Close(); err != nil {
						t.Fatal(err)
					}
					refuse := func(h []Hop, frozen []bool, private int, digest string) {
						t.Helper()
						if s, e := NewSelectedPrivateStreamContext(t.Context(), engine, h, frozen, private, digest); s != nil || e == nil {
							t.Fatal("foreign role, credential, route or generation admitted")
						}
					}
					replaced := slices.Clone(mask)
					replaced[pos] = true
					refuse(hops, replaced, pos, source)
					changed := slices.Clone(hops)
					changed[1] = orderedHops(count)[1]
					refuse(changed, mask, pos, source)
					changed = slices.Clone(hops)
					changed[pos].Proof = hops[0].Proof
					refuse(changed, mask, pos, source)
					refuse(hops, mask, 1, source)
					if server {
						refuse(hops, mask, pos, strings.Repeat("b", 64))
						changed = slices.Clone(hops)
						changed[pos].Tag = fmt.Sprintf("routervpn-chain-server-%d-%s", pos, strings.Repeat("b", 16))
						refuse(changed, mask, pos, source)
					}
					if count > 8 {
						if s, e := newOrderedImportedNodesContext(t.Context(), engine, hops, server); s != nil || e == nil {
							t.Fatal("legacy inventory acquired expanded private-stream admission")
						}
					}
				})
			}
		}
	}
}
