package hopmeasure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

type orderedServerAdmissionEngine struct{}

func (orderedServerAdmissionEngine) Identity() string { return "captured-server-path" }
func (orderedServerAdmissionEngine) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("admission cannot dial")
}

func orderedServerAdmissionHops() []Hop {
	var hops []Hop
	for position := 0; position < 4; position++ {
		tag, role := fmt.Sprintf("routervpn-chain-server-%d-%s", position, strings.Repeat("a", 16)), "intermediate"
		if position == 0 {
			tag, role = "routervpn-chain-0-"+strings.Repeat("b", 12)+"-node-"+strings.Repeat("c", 12), "entry"
		} else if position == 3 {
			role = "exit"
		}
		hops = append(hops, Hop{ID: fmt.Sprint(position), Role: role, Tag: tag, API: fmt.Sprintf("http://10.80.%d.1:8787", position), Token: "original-token", Proof: strings.Repeat(fmt.Sprint(position+1), 64), Kind: "private-node"})
	}
	return hops
}

func TestOrderedServerMeasurementAdmitsOnlyOnePositionalSource(t *testing.T) {
	hops := orderedServerAdmissionHops()
	service, err := NewOrderedServerContext(context.Background(), orderedServerAdmissionEngine{}, hops)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOrderedContext(context.Background(), orderedServerAdmissionEngine{}, hops); err == nil {
		t.Fatal("ordinary Local constructor admitted Server tags")
	}
	for name, change := range map[string]func([]Hop){
		"server-entry":     func(h []Hop) { h[0].Tag = "routervpn-chain-server-1-" + strings.Repeat("a", 16) },
		"wrong-position":   func(h []Hop) { h[1].Tag = h[2].Tag },
		"different-source": func(h []Hop) { h[2].Tag = "routervpn-chain-server-2-" + strings.Repeat("b", 16) },
		"local-middle": func(h []Hop) {
			h[1].Tag = "routervpn-chain-1-" + strings.Repeat("b", 12) + "-node-" + strings.Repeat("c", 12)
		},
		"public-middle":   func(h []Hop) { h[1].Kind = "public-path" },
		"duplicate-proof": func(h []Hop) { h[2].Proof = h[1].Proof },
		"wrong-role":      func(h []Hop) { h[1].Role = "exit" },
		"default-route":   func(h []Hop) { h[3].Tag = "proxy" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]Hop(nil), hops...)
			change(candidate)
			if _, err := NewOrderedServerContext(context.Background(), orderedServerAdmissionEngine{}, candidate); err == nil {
				t.Fatal("uncaptured ordered Server route admitted")
			}
		})
	}
}
