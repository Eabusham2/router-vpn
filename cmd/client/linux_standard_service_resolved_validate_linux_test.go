//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/standardengine"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolvedDNSSECAdoptionRequiresLocalProof(t *testing.T) {
	q, err := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"secure", "proven-insecure", "bogus-ad", "unknown", "changed-question", "changed-rcode", "alias-before-adoption", "bogus-alias-before-adoption"} {
		t.Run(scenario, func(t *testing.T) {
			packet := resolvedScopeAnswer(q, 0)
			packet[0] ^= 0x75
			packet[3] |= 0x20
			verdict := standardengine.DNSSECVerdict{State: 1, Packet: packet}
			switch scenario {
			case "proven-insecure":
				verdict.State = 2
			case "bogus-ad":
				verdict.State = 3
			case "unknown":
				verdict.State = 0
			case "changed-question":
				packet[13] ^= 1
			case "changed-rcode":
				verdict.RCode = 3
			case "alias-before-adoption", "bogus-alias-before-adoption":
				if scenario == "bogus-alias-before-adoption" {
					verdict.State = 3
				}
				binary.BigEndian.PutUint16(packet[6:8], 1)
				packet = append(packet, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, 2, 0xc0, 12)
				verdict.Packet = packet
			}
			answer, err := resolvedValidatedAnswer(q, verdict)
			if scenario == "secure" || scenario == "proven-insecure" {
				if err != nil || len(answer) < 12 || answer[0] != q[0] || (answer[3]&0x20 != 0) != (scenario == "secure") {
					t.Fatal("local proof lost original question/security", err)
				}
				return
			}
			if err == nil || answer != nil {
				t.Fatal("unproved result adopted")
			}
			if scenario == "alias-before-adoption" || scenario == "bogus-alias-before-adoption" {
				var alias *resolvedDNSSECAliasProofRequired
				if !errors.As(err, &alias) {
					t.Fatal("alias discovery lost before disposition", err)
				}
			}
		})
	}
}
func TestResolvedDNSSECChildrenJoinBeforeGroup(t *testing.T) {
	q, err := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"joined", "retained-child"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var active atomic.Int32
			var entered atomic.Int32
			barrier := make(chan struct{})
			f := &resolvedScopeFixture{}
			scopes := []resolvedQueryScope{{}, {}}
			for i := range scopes {
				index := i
				scopes[i].validate = func(work context.Context) ([]byte, error) {
					active.Add(1)
					defer active.Add(-1)
					if entered.Add(1) == 2 {
						close(barrier)
					}
					select {
					case <-barrier:
					case <-work.Done():
						return nil, work.Err()
					}
					if index == 0 {
						return resolvedScopeAnswer(q, 0), nil
					}
					<-work.Done()
					return nil, work.Err()
				}
			}
			retire := func(context.Context) error {
				if active.Load() != 0 {
					t.Error("group attempted child retirement while scope still admitting callbacks")
				}
				if f.closed {
					t.Error("physical group closed before child join")
				}
				if scenario == "retained-child" {
					return errors.New("exact child callback remains")
				}
				return nil
			}
			answer, err := resolveOriginalScopesOwned(ctx, f, scopes, q, retire)
			if scenario == "retained-child" {
				var retained *resolvedGroupRetirementError
				if err == nil || answer != nil || f.closed || !errors.As(err, &retained) {
					t.Fatal("retained child released group", err, f.closed)
				}
			} else if err != nil || answer == nil || !f.closed {
				t.Fatal("joined children failed adoption", err)
			}
		})
	}
}
func TestResolvedDNSSECAliasDiscoveredBeforeVerdict(t *testing.T) {
	q, _ := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
	for _, kind := range []uint16{5, 39} {
		packet := resolvedScopeAnswer(q, 0)
		binary.BigEndian.PutUint16(packet[6:8], 1)
		packet = append(packet, 0xc0, 12, byte(kind>>8), byte(kind), 0, 1, 0, 0, 0, 1, 0, 2, 0xc0, 12)
		answer, err := resolvedDNSSECOriginalReply(packet, nil)
		var alias *resolvedDNSSECAliasProofRequired
		if answer != nil || !errors.As(err, &alias) {
			t.Fatal("unproved alias flowed into original trust plan", kind, err)
		}
		packet[0] ^= 1
		if alias.Packet[0] == packet[0] {
			t.Fatal("alias proof input was mutable")
		}
	}
}
