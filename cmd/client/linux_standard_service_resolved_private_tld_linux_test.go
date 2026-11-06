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

func privateTLDClientFixture(t *testing.T, ctx context.Context) (standardengine.ResolvedPolicy, []byte, []resolvedPrivateCandidate) {
	t.Helper()
	p := resolvedAdapterPolicy()
	p.Manager.DNSSEC = "allow-downgrade"
	link := standardengine.ResolvedDNS{Index: 7, Address: "192.0.2.54", Port: 3053}
	p.Manager.DNS = append(p.Manager.DNS, link)
	p.Links = []standardengine.ResolvedScope{{Index: 7, DNS: []standardengine.ResolvedDNS{link}, CurrentDNS: &link, DNSSEC: "allow-downgrade", DNSOverTLS: "no", DefaultRoute: true}}
	q, err := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
	if err != nil {
		t.Fatal(err)
	}
	var rows []resolvedPrivateCandidate
	for _, index := range []int32{0, 7} {
		owner := &resolvedDNSSECOwnerFixture{policy: p, changed: true}
		plan, err := captureLinuxResolvedDNSSECPlan(ctx, ctx, owner, p, "vpn.example", index)
		if err != nil {
			t.Fatal(err)
		}
		a := resolvedScopeAnswer(q, 0)
		binary.BigEndian.PutUint16(a[6:], 1)
		a = append(a, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, byte(9+index))
		a[3] |= 0x20
		c, err := systembootstrap.NewResolvedPrivateTLDCandidate(q, a)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := standardengine.NewResolvedPrivateTLDProof(p, plan, 1, c.SHA256())
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, resolvedPrivateCandidate{plan, proof, c})
	}
	return p, q, rows
}
func TestResolvedPrivateTLDJoinedShipping(t *testing.T) {
	for _, scenario := range []string{"secure", "parallel-isolation", "invalid-sibling", "bogus", "insecure", "nodata", "wrong-name", "alias-answer", "child-error", "retire-error", "close-error", "postjoin-change", "cancelled", "candidate-swap"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			p, q, rows := privateTLDClientFixture(t, ctx)
			parallel := scenario == "parallel-isolation" || scenario == "invalid-sibling"
			if !parallel {
				rows = rows[:1]
			}
			if scenario == "candidate-swap" {
				_, _, other := privateTLDClientFixture(t, ctx)
				rows[0].answer = other[1].answer
			}
			group := &resolvedDowngradeJoinedFixture{}
			joined := false
			group.close = func() {
				if !joined {
					t.Error("proof group closed before exact children joined")
				}
			}
			if scenario == "close-error" {
				group.closeErr = errors.New("group still owned")
			}
			var mu sync.Mutex
			arrivals := 0
			barrier := make(chan struct{})
			calls := 0
			validate := func(work context.Context, row resolvedPrivateCandidate) (standardengine.DNSSECVerdict, error) {
				mu.Lock()
				arrivals++
				calls++
				if parallel && arrivals == len(rows) {
					close(barrier)
				}
				mu.Unlock()
				if parallel {
					select {
					case <-barrier:
					case <-work.Done():
						return standardengine.DNSSECVerdict{}, work.Err()
					}
				}
				if scenario == "cancelled" {
					cancel()
					return standardengine.DNSSECVerdict{}, work.Err()
				}
				if scenario == "child-error" {
					return standardengine.DNSSECVerdict{}, errors.New("original child terminal error")
				}
				if scenario == "parallel-isolation" && row.plan.Index() == 0 {
					<-work.Done()
					return standardengine.DNSSECVerdict{}, work.Err()
				}
				proofQ := resolvedPrivateTLDQuestion(row.proof, q[:2])
				a := resolvedScopeAnswer(proofQ, 3)
				v := standardengine.DNSSECVerdict{State: 1, RCode: 3, NXDomain: 1, Packet: a}
				switch scenario {
				case "bogus":
					v.State = 3
				case "insecure":
					v.State = 2
				case "nodata":
					v.RCode = 0
					v.NXDomain = 0
					a[3] &^= 15
				case "wrong-name":
					a[13] ^= 1
				case "alias-answer":
					a[7] = 1
					v.Packet = append(a, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 7, 5, 'o', 't', 'h', 'e', 'r', 0)
				}
				if scenario == "invalid-sibling" && row.plan.Index() == 0 {
					v.State = 3
				}
				return v, nil
			}
			retire := func(context.Context) error {
				if scenario == "retire-error" {
					return errors.New("child still owned")
				}
				joined = true
				return nil
			}
			checks := 0
			recheck := func(context.Context) error {
				checks++
				if !group.closed || !joined {
					t.Error("authority checked before proof owners retired")
				}
				if scenario == "postjoin-change" {
					return errors.New("original root changed")
				}
				return nil
			}
			answer, err := resolvePrivateTLDJoined(ctx, p, q, group, rows, validate, retire, recheck)
			want := scenario == "secure" || parallel
			if (err == nil) != want {
				t.Fatal(scenario, err)
			}
			if want {
				if answer[3]&0x20 != 0 {
					t.Fatal("private exception invented AD")
				}
				if parallel && answer[len(answer)-1] != 16 {
					t.Fatal("other scope proof adopted foreign candidate")
				}
				if checks != 1 {
					t.Fatal("postjoin check omitted")
				}
			}
			if scenario == "candidate-swap" && calls != 0 {
				t.Fatal("changed candidate acquired proof query")
			}
			if scenario == "retire-error" && group.closed {
				t.Fatal("group released before child join")
			}
		})
	}
}
func TestResolvedPrivateTLDCandidateRetention(t *testing.T) {
	for _, scenario := range []string{"eligible", "validator-error", "secure", "insecure", "negative", "no-data", "sealed", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			p, q, rows := privateTLDClientFixture(t, ctx)
			row := rows[0]
			v := standardengine.DNSSECVerdict{State: 3, HaveData: 1, Packet: row.answer.UnsignedAnswer()}
			var failure error
			switch scenario {
			case "validator-error":
				failure = errors.New("unjoined child")
			case "secure":
				v.State = 1
			case "insecure":
				v.State = 2
			case "negative":
				v.RCode = 3
				v.NXDomain = 1
			case "no-data":
				v.HaveData = 0
			}
			ledger := &resolvedPrivateCandidates{}
			if scenario == "sealed" {
				ledger.seal()
			}
			ledger.retain(p, row.plan, q, v, failure)
			if scenario == "duplicate" {
				ledger.retain(p, row.plan, q, v, nil)
			}
			got := ledger.seal()
			want := scenario == "eligible" || scenario == "duplicate"
			if (len(got) == 1) != want {
				t.Fatal("invalid candidate retained", scenario, len(got))
			}
		})
	}
}
func TestResolvedPrivateTLDCohortReservation(t *testing.T) {
	for used := 0; used <= 32; used++ {
		if resolvedPrivateTLDSlot(used, false) != (used < 31) || resolvedPrivateTLDSlot(used, true) {
			t.Fatal("exception changed original cohort allowance", used)
		}
	}
}

type resolvedPrivatePlanOwner struct {
	resolvedDNSSECOwnerFixture
	drop bool
}

func (o *resolvedPrivatePlanOwner) rootDSScoped(ctx, original context.Context, index int32, name string) (standardengine.ResolvedRootDSDecision, error) {
	r, err := o.resolvedDNSSECOwnerFixture.rootDSScoped(ctx, original, index, name)
	if o.drop && index == 7 {
		r.Root = nil
		r.Outcome = "synthetic-unsigned"
	}
	return r, err
}
func TestResolvedPrivateTLDShippingContinuation(t *testing.T) {
	for _, scenario := range []string{"proved", "normal-positive", "normal-negative", "no-extra-slot", "original-retirement", "all-scope-plan-change", "physical-current-loss", "cancel-before-proof", "alias-required", "authority-lost"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			p, q, rows := privateTLDClientFixture(t, ctx)
			plans := []*standardengine.ResolvedDNSSECPlan{rows[0].plan, rows[1].plan}
			cohort, err := newResolvedDowngradeCohort(plans)
			if err != nil {
				t.Fatal(err)
			}
			owner := &resolvedPrivatePlanOwner{resolvedDNSSECOwnerFixture: resolvedDNSSECOwnerFixture{policy: p, changed: true}}
			fullCheck, err := resolvedAliasTrustRecheck(ctx, owner, p, "vpn.example", plans)
			if err != nil {
				t.Fatal(err)
			}
			var private *resolvedPrivateCandidates
			if scenario != "no-extra-slot" {
				private = &resolvedPrivateCandidates{}
			}
			original := &resolvedDowngradeJoinedFixture{}
			retired := false
			original.close = func() {
				if !retired {
					t.Error("original group preceded child join")
				}
			}
			row := rows[0]
			v := standardengine.DNSSECVerdict{State: 3, HaveData: 1, Packet: row.answer.UnsignedAnswer()}
			recorded := make(chan struct{})
			raw, _ := p.Canonical()
			state := standardengine.ResolvedServerState{PolicySHA256: standardengine.ResolvedPolicySHA256(raw), Name: row.plan.Name(), Selected: *p.Manager.CurrentDNS, Row: standardengine.ResolvedServerRow{Server: "192.0.2.53:5353#original.example", Type: "system", DNSSECMode: "allow-downgrade", VerifiedFeatureLevel: "n/a", PossibleFeatureLevel: "UDP+EDNS0+DO", DNSSECSupported: true}}
			transport := &resolvedDowngradeTransport{}
			scopes := []resolvedQueryScope{{validate: func(work context.Context) ([]byte, error) {
				answer, err := resolveResolvedTerminal(work, p, row.plan, "udp", q, v, nil, false, transport, func(context.Context) error { return nil }, func(context.Context) (standardengine.ResolvedServerState, error) { return state, nil }, cohort)
				if err != nil {
					private.retain(p, row.plan, q, v, nil)
				}
				close(recorded)
				return answer, err
			}}}
			if scenario == "normal-positive" || scenario == "normal-negative" {
				scopes = append(scopes, resolvedQueryScope{validate: func(work context.Context) ([]byte, error) {
					<-recorded
					if scenario == "normal-negative" {
						return resolvedScopeAnswer(q, 3), nil
					}
					return rows[1].answer.UnsignedAnswer(), nil
				}})
			}
			answer, originalErr := resolveResolvedCompatibilityCohort(ctx, original, scopes, q, func(context.Context) error {
				if scenario == "original-retirement" {
					return errors.New("original child retained")
				}
				retired = true
				return nil
			}, systembootstrap.ResolvedResponseSuccess, cohort)
			if scenario == "all-scope-plan-change" {
				owner.drop = true
			}
			if !errors.As(originalErr, new(*resolvedGroupRetirementError)) {
				if check := fullCheck(ctx); check != nil {
					originalErr = &resolvedAliasAuthorityError{check}
					answer = nil
				}
			}
			if scenario == "alias-required" {
				originalErr = &resolvedDNSSECAliasProofRequired{}
			}
			if scenario == "authority-lost" {
				originalErr = &resolvedAliasAuthorityError{errors.New("original daemon lost")}
			}
			if scenario == "cancel-before-proof" {
				cancel()
			}
			calls := 0
			result, err := resolvePrivateTLDAfterOriginal(ctx, answer, originalErr, private, func(candidates []resolvedPrivateCandidate) ([]byte, error) {
				calls++
				if !original.closed || !retired {
					t.Fatal("proof started before original owners retired")
				}
				if scenario == "physical-current-loss" {
					return nil, &resolvedAliasAuthorityError{errors.New("physical ownership lost")}
				}
				proofGroup := &resolvedDowngradeJoinedFixture{}
				proofJoined := false
				proofGroup.close = func() {
					if !proofJoined {
						t.Error("auxiliary group preceded child join")
					}
				}
				return resolvePrivateTLDJoined(ctx, p, q, proofGroup, candidates, func(work context.Context, c resolvedPrivateCandidate) (standardengine.DNSSECVerdict, error) {
					proofQ := resolvedPrivateTLDQuestion(c.proof, q[:2])
					return standardengine.DNSSECVerdict{State: 1, RCode: 3, NXDomain: 1, Packet: resolvedScopeAnswer(proofQ, 3)}, nil
				}, func(context.Context) error { proofJoined = true; return nil }, fullCheck)
			})
			want := scenario == "proved" || scenario == "normal-positive" || scenario == "normal-negative"
			if (err == nil) != want {
				t.Fatal(scenario, err)
			}
			if want && result[3]&0x20 != 0 {
				t.Fatal("exception invented AD")
			}
			wantCalls := 0
			if scenario == "proved" || scenario == "physical-current-loss" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatal("unused or forbidden auxiliary admission", scenario, calls)
			}
			if transport.calls != 0 {
				t.Fatal("ordinary incompatibility fallback unexpectedly ran")
			}
		})
	}
}
