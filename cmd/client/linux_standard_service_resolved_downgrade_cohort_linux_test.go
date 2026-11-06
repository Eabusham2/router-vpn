//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
	"sync"
	"testing"
	"time"
)

type resolvedDowngradeJoinedFixture struct {
	resolvedScopeFixture
	close func()
}

func (f *resolvedDowngradeJoinedFixture) Close(ctx context.Context) error {
	if f.close != nil {
		f.close()
	}
	return f.resolvedScopeFixture.Close(ctx)
}
func TestResolvedDowngradeShippingCohort(t *testing.T) {
	for _, scenario := range []string{"address", "alias-proof", "alias-no-link", "validator-error", "terminal-retirement-error", "bogus-without-compatibility", "strict", "secure", "state-changed-on-join", "state-changed-before-adoption", "group-close-failed", "cancelled-after-terminal", "foreign-scope"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			policy := resolvedAdapterPolicy()
			policy.Manager.DNSSEC = "allow-downgrade"
			if scenario == "strict" {
				policy.Manager.DNSSEC = "yes"
			}
			owner := &resolvedDNSSECOwnerFixture{policy: policy}
			plan, err := captureLinuxResolvedDNSSECPlan(ctx, ctx, owner, policy, "vpn.example", 0)
			if err != nil {
				t.Fatal(err)
			}
			cohort, err := newResolvedDowngradeCohort([]*standardengine.ResolvedDNSSECPlan{plan})
			if err != nil {
				t.Fatal(err)
			}
			question, err := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
			if err != nil {
				t.Fatal(err)
			}
			alias := scenario == "alias-proof" || scenario == "alias-no-link"
			if alias {
				question, err = systembootstrap.ResolvedAliasQuery(question, "vpn.example", 5)
				if err != nil {
					t.Fatal(err)
				}
			}
			packet := resolvedScopeAnswer(question, 0)
			if alias && scenario != "alias-no-link" {
				binary.BigEndian.PutUint16(packet[6:8], 1)
				target := []byte{5, 'o', 't', 'h', 'e', 'r', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
				packet = append(packet, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, byte(len(target)))
				packet = append(packet, target...)
			}
			packet[3] |= 0x20
			verdict := standardengine.DNSSECVerdict{State: 3, Packet: packet}
			if scenario == "secure" {
				verdict.State = 1
			}
			var terminalErr error
			if scenario == "validator-error" {
				terminalErr = errors.New("failed authenticated terminal exchange")
			}
			if scenario == "terminal-retirement-error" {
				terminalErr = &resolvedGroupRetirementError{errors.New("original child did not join")}
			}
			raw, _ := policy.Canonical()
			state := standardengine.ResolvedServerState{PolicySHA256: standardengine.ResolvedPolicySHA256(raw), Name: "vpn.example", Selected: *policy.Manager.CurrentDNS, Row: standardengine.ResolvedServerRow{Server: "192.0.2.53:5353#original.example", Type: "system", DNSSECMode: policy.Manager.DNSSEC, VerifiedFeatureLevel: "n/a", PossibleFeatureLevel: "UDP+EDNS0", PacketDoOff: true}}
			if scenario == "strict" {
				state.Row.DNSSECSupported = true
			}
			if scenario == "bogus-without-compatibility" {
				state.Row.PacketDoOff = false
				state.Row.DNSSECSupported = true
			}
			if scenario == "foreign-scope" {
				state.Index = 1
			}
			transport := &resolvedDowngradeTransport{answer: packet}
			observe := func(check context.Context) (standardengine.ResolvedServerState, error) { return state, check.Err() }
			guard := func(check context.Context) error { return check.Err() }
			group := &resolvedDowngradeJoinedFixture{}
			childJoined := false
			group.close = func() {
				if !childJoined {
					t.Error("group closed before child retirement")
				}
				if scenario == "state-changed-on-join" {
					state.Row.FailedUDPAttempts++
				}
			}
			if scenario == "group-close-failed" {
				group.closeErr = errors.New("original group remains owned")
			}
			scopes := []resolvedQueryScope{{validate: func(work context.Context) ([]byte, error) {
				if scenario == "cancelled-after-terminal" {
					cancel()
				}
				return resolveResolvedTerminal(work, policy, plan, "udp", question, verdict, terminalErr, alias, transport, guard, observe, cohort)
			}}}
			classify := systembootstrap.ResolvedResponseSuccess
			if alias {
				classify = func(q, r []byte) (bool, error) {
					step, e := systembootstrap.ResolvedAliasStep(q, r)
					return step != nil, e
				}
			}
			answer, err := resolveResolvedCompatibilityCohort(ctx, group, scopes, question, func(context.Context) error { childJoined = true; return nil }, classify, cohort)
			if scenario == "state-changed-before-adoption" {
				state.Row.PacketDoOff = false
				state.Row.DNSSECSupported = true
				if check := cohort.Recheck(ctx); check != nil {
					err = check
					answer = nil
				}
			}
			accepted := scenario == "address" || scenario == "alias-proof" || scenario == "secure"
			if accepted {
				if err != nil || len(answer) < 12 {
					t.Fatal("shipping cohort refused", err)
				}
				if scenario != "secure" && answer[3]&0x20 != 0 {
					t.Fatal("compatibility invented AD")
				}
			} else if err == nil || answer != nil {
				t.Fatal("unproved cohort adopted", scenario)
			}
			if scenario == "group-close-failed" && cohort.sealed {
				t.Fatal("retained cleanup permitted seal")
			}
			if scenario == "validator-error" || scenario == "terminal-retirement-error" || scenario == "bogus-without-compatibility" || scenario == "strict" || scenario == "secure" || scenario == "cancelled-after-terminal" || scenario == "foreign-scope" {
				if transport.calls != 0 {
					t.Fatal("forbidden fallback acquired transport")
				}
			}
		})
	}
}
func TestResolvedDowngradeCohortBound(t *testing.T) {
	ctx := context.Background()
	c := &resolvedDowngradeCohort{allowed: make(map[int32]bool)}
	for i := int32(0); i < 257; i++ {
		c.allowed[i] = true
	}
	if c.Recheck(ctx) == nil {
		t.Fatal("unjoined ledger adopted")
	}
	check := func(context.Context) error { return nil }
	if c.retain(999, check) == nil {
		t.Fatal("foreign scope admitted before capacity")
	}
	var workers sync.WaitGroup
	for i := int32(0); i < 257; i++ {
		workers.Add(1)
		go func(index int32) {
			defer workers.Done()
			if err := c.retain(index, check); err != nil {
				t.Error(err)
			}
		}(i)
	}
	workers.Wait()
	if c.retain(0, check) == nil || c.retain(999, check) == nil {
		t.Fatal("duplicate or foreign scope admitted")
	}
	if err := c.SealAndRecheck(ctx); err != nil {
		t.Fatal(err)
	}
	if c.retain(0, check) == nil {
		t.Fatal("sealed ledger mutated")
	}
}
