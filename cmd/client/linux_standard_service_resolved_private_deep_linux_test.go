//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
	"strings"
	"sync"
	"testing"
	"time"
)

func privateDeepClientFixture(t *testing.T, ctx context.Context) (standardengine.ResolvedPolicy, []byte, []resolvedPrivateDeepCandidate) {
	t.Helper()
	p, _, _ := privateTLDClientFixture(t, ctx)
	q, err := dnsmeasure.TransportBootstrapQuery("host.vpn.example", false)
	if err != nil {
		t.Fatal(err)
	}
	var rows []resolvedPrivateDeepCandidate
	for _, index := range []int32{0, 7} {
		owner := &resolvedDNSSECOwnerFixture{policy: p, changed: true}
		plan, e := captureLinuxResolvedDNSSECPlan(ctx, ctx, owner, p, "host.vpn.example", index)
		if e != nil {
			t.Fatal(e)
		}
		a := resolvedScopeAnswer(q, 0)
		binary.BigEndian.PutUint16(a[6:], 1)
		a = append(a, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, byte(9+index))
		candidate, e := systembootstrap.NewResolvedPrivateDeepCandidate(q, a)
		if e != nil {
			t.Fatal(e)
		}
		cap, e := standardengine.NewResolvedPrivateDSDependencies(p, plan, 1, candidate.SHA256())
		if e != nil {
			t.Fatal(e)
		}
		rows = append(rows, resolvedPrivateDeepCandidate{plan: plan, capability: cap, answer: candidate})
	}
	return p, q, rows
}
func privateDeepModelReplies(row resolvedPrivateDeepCandidate) []standardengine.ResolvedPrivateDSReply {
	var rows []standardengine.ResolvedPrivateDSReply
	for _, want := range row.capability.Questions() {
		q := resolvedPrivateDSQuestion(want.Name, 43, []byte{1, 2})
		rows = append(rows, standardengine.ResolvedPrivateDSReply{AuthoritySHA256: standardengine.SHA256(row.capability.Canonical()), Question: q, Response: resolvedScopeAnswer(q, 0)})
	}
	return rows
}
func TestResolvedPrivateDeepRootShipping(t *testing.T) {
	for _, scenario := range []string{"secure", "nxdomain", "nodata", "positive-sibling", "invalid-sibling", "incomplete-chain", "positive-ds", "signed-ds", "bogus-root", "insecure-root", "nodata-root", "child-error", "retire-error", "close-error", "stale-plan", "physical-current-loss", "cancelled", "foreign-candidate", "completion-error"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			p, q, rows := privateDeepClientFixture(t, ctx)
			parallel := scenario == "positive-sibling" || scenario == "invalid-sibling"
			if !parallel {
				rows = rows[:1]
			}
			if scenario == "nxdomain" || scenario == "nodata" || scenario == "positive-sibling" {
				code := byte(3)
				if scenario == "nodata" {
					code = 0
				}
				a := resolvedScopeAnswer(q, code)
				c, e := systembootstrap.NewResolvedPrivateDeepCandidate(q, a)
				if e != nil {
					t.Fatal(e)
				}
				rows[0].answer = c
				rows[0].capability, e = standardengine.NewResolvedPrivateDSDependencies(p, rows[0].plan, 1, c.SHA256())
				if e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "foreign-candidate" {
				_, _, other := privateDeepClientFixture(t, ctx)
				rows[0].answer = other[1].answer
			}
			group := &resolvedDowngradeJoinedFixture{}
			retired, checked := false, false
			group.close = func() {
				if !retired {
					t.Error("root group closed before child retirement")
				}
			}
			if scenario == "close-error" {
				group.closeErr = errors.New("original grants retained")
			}
			var mu sync.Mutex
			arrivals := 0
			barrier := make(chan struct{})
			negativeReady := make(chan struct{})
			validate := func(work context.Context, row resolvedPrivateDeepCandidate) (standardengine.DNSSECVerdict, error) {
				mu.Lock()
				arrivals++
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
					return standardengine.DNSSECVerdict{}, errors.New("child terminal failure")
				}
				if scenario == "positive-sibling" && row.plan.Index() == 7 {
					select {
					case <-negativeReady:
					case <-work.Done():
						return standardengine.DNSSECVerdict{}, work.Err()
					}
				}
				rootQ := resolvedPrivateDSQuestion(row.capability.TLD(), 1, q[:2])
				v := standardengine.DNSSECVerdict{State: 1, RCode: 3, NXDomain: 1, Packet: resolvedScopeAnswer(rootQ, 3)}
				if scenario == "bogus-root" || scenario == "invalid-sibling" && row.plan.Index() == 0 {
					v.State = 3
				}
				if scenario == "insecure-root" {
					v.State = 2
				}
				if scenario == "nodata-root" {
					v.RCode = 0
					v.NXDomain = 0
					v.Packet = resolvedScopeAnswer(rootQ, 0)
				}
				return v, nil
			}
			replies := func(row resolvedPrivateDeepCandidate) []standardengine.ResolvedPrivateDSReply {
				r := privateDeepModelReplies(row)
				if scenario == "incomplete-chain" {
					return r[:1]
				}
				if scenario == "positive-ds" {
					r[0].Response[7] = 1
				}
				if scenario == "signed-ds" {
					r[0].Response[9] = 1
					r[0].Response = append(r[0].Response, 0xc0, 12, 0, 46, 0, 1, 0, 0, 0, 1, 0, 0)
				}
				return r
			}
			preview := func(row resolvedPrivateDeepCandidate, rq []byte, v standardengine.DNSSECVerdict) error {
				_, e := row.capability.Complete(replies(row), rq, v)
				if scenario == "positive-sibling" && row.plan.Index() == 0 {
					close(negativeReady)
				}
				return e
			}
			complete := func(row resolvedPrivateDeepCandidate, rq []byte, v standardengine.DNSSECVerdict) (*standardengine.ResolvedPrivateDSProof, error) {
				if !retired || !checked || !group.closed {
					t.Error("adoption before exact joins/rechecks")
				}
				if scenario == "completion-error" {
					return nil, errors.New("changed root owner")
				}
				return row.capability.Complete(replies(row), rq, v)
			}
			answer, err := resolvePrivateDeepRootJoined(ctx, p, q, group, rows, validate, preview, complete, func(context.Context) error {
				retired = true
				if scenario == "retire-error" {
					return errors.New("child still owned")
				}
				return nil
			}, func(context.Context) error {
				checked = true
				if scenario == "stale-plan" || scenario == "physical-current-loss" {
					return errors.New("original authority changed")
				}
				return nil
			})
			success := scenario == "secure" || scenario == "nxdomain" || scenario == "nodata" || parallel
			if success {
				if err != nil || len(answer) < 12 || answer[3]&0x20 != 0 {
					t.Fatal("original joined proof rejected", err)
				}
				if scenario == "positive-sibling" && binary.BigEndian.Uint16(answer[6:8]) != 1 {
					t.Fatal("negative erased positive sibling")
				}
			} else if err == nil || answer != nil {
				t.Fatal("invalid proof adopted", scenario)
			}
		})
	}
}
func TestResolvedPrivateDeepDependencyRetirement(t *testing.T) {
	for _, scenario := range []string{"complete", "partial-sibling", "incomplete", "close-error", "stale-plan", "physical-current-loss", "cancelled", "seal-error"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _, rows := privateDeepClientFixture(t, ctx)
			group := &resolvedDowngradeJoinedFixture{}
			var mu sync.Mutex
			active := 0
			arrived := 0
			barrier := make(chan struct{})
			checked := false
			group.close = func() {
				mu.Lock()
				defer mu.Unlock()
				if active != 0 {
					t.Error("DS group closed before dependency IO joined")
				}
			}
			if scenario == "close-error" {
				group.closeErr = errors.New("grant retained")
			}
			got, err := resolvePrivateDSDependenciesJoined(ctx, group, rows, func(work context.Context, row resolvedPrivateDeepCandidate) ([]*mobiletor.DesktopLinuxPrivateDSReply, error) {
				mu.Lock()
				active++
				arrived++
				if arrived == 2 {
					close(barrier)
				}
				mu.Unlock()
				defer func() { mu.Lock(); active--; mu.Unlock() }()
				select {
				case <-barrier:
				case <-work.Done():
					return nil, work.Err()
				}
				if scenario == "cancelled" {
					cancel()
					return nil, context.Canceled
				}
				if scenario == "incomplete" || scenario == "partial-sibling" && row.plan.Index() == 0 {
					return nil, errors.New("missing parent DS")
				}
				return nil, nil
			}, func(row resolvedPrivateDeepCandidate, _ []*mobiletor.DesktopLinuxPrivateDSReply) (*mobiletor.DesktopLinuxPrivateDSChain, error) {
				if !group.closed || !checked {
					t.Error("chain sealed before Close/current")
				}
				if scenario == "seal-error" {
					return nil, errors.New("foreign receipt")
				}
				return &mobiletor.DesktopLinuxPrivateDSChain{}, nil
			}, func(context.Context) error {
				checked = true
				if scenario == "stale-plan" || scenario == "physical-current-loss" {
					return errors.New("original changed")
				}
				return nil
			})
			if scenario == "complete" || scenario == "partial-sibling" {
				if err != nil || len(got) == 0 {
					t.Fatal(err)
				}
				if scenario == "partial-sibling" && (len(got) != 1 || got[0].plan.Index() != 7) {
					t.Fatal("incomplete sibling leaked")
				}
			} else if err == nil {
				t.Fatal("invalid dependency phase adopted")
			}
		})
	}
}
func TestResolvedPrivateDeepContinuation(t *testing.T) {
	for _, scenario := range []string{"proved", "normal-positive", "normal-negative", "capacity", "alias-purpose", "original-retirement", "authority-loss", "cancelled", "validator-error", "metadata", "secure-state", "old-depth"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			p, q, rows := privateDeepClientFixture(t, ctx)
			ledger := &resolvedPrivateDeepCandidates{}
			v := standardengine.DNSSECVerdict{State: 3, HaveData: 1, Packet: rows[0].answer.UnsignedAnswer()}
			var ve error
			if scenario == "validator-error" {
				ve = errors.New("unjoined child")
			}
			if scenario == "metadata" {
				v.HaveData = 0
			}
			if scenario == "secure-state" {
				v.State = 1
			}
			if scenario == "old-depth" {
				p, q, old := privateTLDClientFixture(t, ctx)
				ledger.retain(p, old[0].plan, q, standardengine.DNSSECVerdict{State: 3, HaveData: 1, Packet: old[0].answer.UnsignedAnswer()}, nil)
			} else {
				ledger.retain(p, rows[0].plan, q, v, ve)
			}
			var answer []byte
			err := errors.New("original validation failed")
			switch scenario {
			case "normal-positive":
				answer = rows[0].answer.UnsignedAnswer()
				err = nil
			case "normal-negative":
				answer = resolvedScopeAnswer(q, 3)
				err = nil
			case "capacity":
				if resolvedPrivateDeepSlot(30, false) {
					t.Fatal("exception stole ordinary capacity")
				}
				ledger = nil
			case "alias-purpose":
				if resolvedPrivateDeepSlot(0, true) {
					t.Fatal("alias acquired DS exception")
				}
				ledger = nil
			case "original-retirement":
				err = &resolvedGroupRetirementError{err}
			case "authority-loss":
				err = &resolvedAliasAuthorityError{err}
			case "cancelled":
				cancel()
			}
			calls := 0
			got, e := resolvePrivateDeepAfterOriginal(ctx, answer, err, ledger, func(r []resolvedPrivateDeepCandidate) ([]byte, error) {
				calls++
				return r[0].answer.UnsignedAnswer(), nil
			})
			if scenario == "proved" {
				if e != nil || got == nil || calls != 1 {
					t.Fatal("continuation missing", e)
				}
			} else if strings.HasPrefix(scenario, "normal-") {
				if e != nil || calls != 0 || got == nil {
					t.Fatal("normal winner changed")
				}
			} else if calls != 0 || e == nil {
				t.Fatal("invalid continuation admitted", scenario)
			}
		})
	}
	for used := -1; used <= 33; used++ {
		if resolvedPrivateDeepSlot(used, false) != (used >= 0 && used < 30) {
			t.Fatal("cohort bound changed")
		}
		if resolvedPrivateTLDSlot(used, false) != (used >= 0 && used < 31) {
			t.Fatal("old bound changed")
		}
	}
}

func TestResolvedPrivateDeepNormalTerminalBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, q, rows := privateDeepClientFixture(t, ctx)
	row := rows[0]
	ledger := &resolvedPrivateDeepCandidates{}
	v := standardengine.DNSSECVerdict{State: 3, HaveData: 1, Packet: row.answer.UnsignedAnswer()}
	group := &resolvedDowngradeJoinedFixture{}
	retired := false
	group.close = func() {
		if !retired {
			t.Error("original group preceded child join")
		}
	}
	cohort, err := newResolvedDowngradeCohort([]*standardengine.ResolvedDNSSECPlan{row.plan})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := p.Canonical()
	state := standardengine.ResolvedServerState{PolicySHA256: standardengine.ResolvedPolicySHA256(raw), Name: row.plan.Name(), Selected: *p.Manager.CurrentDNS, Row: standardengine.ResolvedServerRow{Server: "192.0.2.53:5353#original.example", Type: "system", DNSSECMode: "allow-downgrade", VerifiedFeatureLevel: "n/a", PossibleFeatureLevel: "UDP+EDNS0+DO", DNSSECSupported: true}}
	original, originalErr := resolveResolvedCompatibilityCohort(ctx, group, []resolvedQueryScope{{validate: func(work context.Context) ([]byte, error) {
		answer, terminalErr := resolveResolvedTerminal(work, p, row.plan, "udp", q, v, nil, false, &resolvedDowngradeTransport{}, func(context.Context) error { return nil }, func(context.Context) (standardengine.ResolvedServerState, error) { return state, nil }, cohort)
		if terminalErr != nil {
			ledger.retain(p, row.plan, q, v, nil)
		}
		return answer, terminalErr
	}}}, q, func(context.Context) error { retired = true; return nil }, systembootstrap.ResolvedResponseSuccess, cohort)
	if original != nil || originalErr == nil || !retired || !group.closed {
		t.Fatal("normal terminal did not fail and join", originalErr)
	}
	calls := 0
	answer, err := resolvePrivateDeepAfterOriginal(ctx, original, originalErr, ledger, func(r []resolvedPrivateDeepCandidate) ([]byte, error) {
		calls++
		if !retired || !group.closed || len(r) != 1 {
			t.Fatal("auxiliary preceded original join")
		}
		return r[0].answer.UnsignedAnswer(), nil
	})
	if err != nil || answer == nil || calls != 1 {
		t.Fatal("joined terminal did not dispatch exact dependency candidate", err)
	}
}
