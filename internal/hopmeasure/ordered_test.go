package hopmeasure

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func orderedHops(count int) []Hop {
	hops := make([]Hop, count)
	for i := range hops {
		role := "intermediate"
		if i == 0 {
			role = "entry"
		} else if i == count-1 {
			role = "exit"
		}
		hops[i] = Hop{ID: fmt.Sprint(i), Role: role, Tag: fmt.Sprintf("routervpn-chain-%d-aaaaaaaaaaaa-node-bbbbbbbbbbbb", i),
			API: "http://10.77.0.1:8787", Token: "captured-token", Proof: fmt.Sprintf("%064x", i+1)}
	}
	return hops
}
func TestOrderedMeasurementPreservesExactPrefixInventory(t *testing.T) {
	engine := &testEngine{generation: "original"}
	for _, count := range []int{2, 3, 8} {
		hops := orderedHops(count)
		service, err := NewOrderedContext(context.Background(), engine, hops)
		if err != nil || len(service.hops) != count {
			t.Fatal(count, err)
		}
		if _, err := NewContext(context.Background(), engine, hops); err == nil {
			t.Fatal("legacy pair constructor accepted ordered tags")
		}
		hops[0].Token = "replacement"
		if service.hops[0].Token != "captured-token" {
			t.Fatal("caller changed retained inventory")
		}
	}
	for name, mutate := range map[string]func([]Hop) []Hop{
		"truncated":      func(h []Hop) []Hop { return h[:1] },
		"oversized":      func(h []Hop) []Hop { return orderedHops(9) },
		"swapped":        func(h []Hop) []Hop { h[0], h[1] = h[1], h[0]; return h },
		"missing-middle": func(h []Hop) []Hop { return append(h[:1], h[2:]...) },
		"repeated-proof": func(h []Hop) []Hop { h[1].Proof = h[0].Proof; return h },
		"legacy-tag":     func(h []Hop) []Hop { h[0].Tag = "entry-wg"; return h },
		"foreign-family": func(h []Hop) []Hop { h[0].Tag = strings.Replace(h[0].Tag, "-node-", "-dns-", 1); return h },
		"wrong-role":     func(h []Hop) []Hop { h[1].Role = "exit"; return h },
		"public-path":    func(h []Hop) []Hop { h[1].Kind = "public-path"; return h },
		"public-api":     func(h []Hop) []Hop { h[1].API = "http://1.1.1.1:80"; return h },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewOrderedContext(context.Background(), engine, mutate(orderedHops(3))); err == nil {
				t.Fatal("unowned ordered inventory accepted")
			}
		})
	}
}
