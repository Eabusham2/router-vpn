package hopmeasure

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func connectPrefixHops(count int) []Hop {
	hops := orderedHops(count)
	for i := range hops {
		hops[i].Kind = "private-node"
	}
	middle := count - 2
	hops[middle].Kind, hops[middle].API, hops[middle].Token, hops[middle].Proof = "public-path", "", "", ""
	return hops
}

func TestOrderedCONNECTPrefixMeasurementAuthority(t *testing.T) {
	for count := 3; count <= 8; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			hops := connectPrefixHops(count)
			engine := &testEngine{generation: "original"}
			s, err := NewOrderedCONNECTPrefixContext(t.Context(), engine, hops)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.hops) != count || s.hops[count-2].Kind != "public-path" {
				t.Fatal("original complete hop inventory lost")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if count > 3 {
				if _, err := NewOrderedImportedMiddleContext(t.Context(), engine, hops); err == nil {
					t.Fatal("ordinary imported path widened")
				}
			}
			if _, err := NewOrderedContext(t.Context(), engine, hops); err == nil {
				t.Fatal("private ordered path admitted public hop")
			}
			if _, err := NewOrderedImportedServerContext(t.Context(), engine, hops); err == nil {
				t.Fatal("Local prefix acquired Server authority")
			}
		})
	}
	for _, name := range []string{"omission", "reorder", "public-first", "public-final", "two-public", "middle-token", "duplicate-proof", "duplicate-id", "wrong-tag"} {
		t.Run(name, func(t *testing.T) {
			hops := connectPrefixHops(6)
			switch name {
			case "omission":
				hops = append(hops[:1], hops[2:]...)
			case "reorder":
				hops[0], hops[2] = hops[2], hops[0]
			case "public-first":
				hops[0].Kind = "public-path"
			case "public-final":
				hops[5].Kind = "public-path"
			case "two-public":
				hops[2].Kind = "public-path"
			case "middle-token":
				hops[4].Token = "foreign"
			case "duplicate-proof":
				hops[2].Proof = hops[0].Proof
			case "duplicate-id":
				hops[2].ID = hops[0].ID
			case "wrong-tag":
				hops[2].Tag = hops[0].Tag
			}
			if _, err := NewOrderedCONNECTPrefixContext(t.Context(), &testEngine{generation: "original"}, hops); err == nil {
				t.Fatal("captured CONNECT prefix authority changed", name)
			}
		})
	}
}

type refusedCONNECTPrefixObservation struct{ *testEngine }

func (e *refusedCONNECTPrefixObservation) IdentityContext(context.Context) (string, error) {
	return "", errors.New("original observation refused")
}
func TestOrderedCONNECTPrefixRefusedObservation(t *testing.T) {
	if _, err := NewOrderedCONNECTPrefixContext(t.Context(), &refusedCONNECTPrefixObservation{&testEngine{generation: "original"}}, connectPrefixHops(8)); err == nil {
		t.Fatal("refused original observation fabricated prefix authority")
	}
}
