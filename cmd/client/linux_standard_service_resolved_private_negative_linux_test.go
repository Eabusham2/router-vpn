//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
	"sync"
	"testing"
	"time"
)

func TestResolvedPrivateTLDNegativeShipping(t *testing.T) {
	for _, scenario := range []string{"nxdomain-a", "nxdomain-aaaa", "nodata-a", "nodata-aaaa", "nxdomain-positive-sibling", "nodata-positive-sibling", "metadata-code", "metadata-nx", "metadata-data", "child-error", "bogus-proof", "insecure-proof", "nodata-proof", "retire-error", "close-error", "postjoin-change", "cancelled", "original-retirement", "normal-winner", "capacity"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			p, q, base := privateTLDClientFixture(t, ctx)
			if scenario == "nxdomain-aaaa" || scenario == "nodata-aaaa" {
				q[len(q)-3] = 28
			}
			code := byte(3)
			if scenario == "nodata-a" || scenario == "nodata-aaaa" || scenario == "nodata-positive-sibling" {
				code = 0
			}
			a := resolvedScopeAnswer(q, code)
			a[3] |= 0x20
			v := standardengine.DNSSECVerdict{State: 3, RCode: uint32(code), Packet: a}
			if code == 3 {
				v.NXDomain = 1
			}
			var childErr error
			switch scenario {
			case "metadata-code":
				v.RCode = 0
			case "metadata-nx":
				v.NXDomain = 0
			case "metadata-data":
				v.HaveData = 1
			case "child-error":
				childErr = errors.New("child did not join")
			}
			ledger := &resolvedPrivateCandidates{}
			ledger.retain(p, base[0].plan, q, v, childErr)
			rejectRetention := scenario == "metadata-code" || scenario == "metadata-nx" || scenario == "metadata-data" || scenario == "child-error"
			if rejectRetention {
				if len(ledger.seal()) != 0 {
					t.Fatal("foreign original verdict retained")
				}
				return
			}
			if len(ledger.rows) != 1 {
				t.Fatal("original negative not retained")
			}
			positiveSibling := scenario == "nxdomain-positive-sibling" || scenario == "nodata-positive-sibling"
			if positiveSibling {
				ledger.retain(p, base[1].plan, q, standardengine.DNSSECVerdict{State: 3, HaveData: 1, Packet: base[1].answer.UnsignedAnswer()}, nil)
			}
			originalGroup := &resolvedDowngradeJoinedFixture{}
			originalJoined := false
			originalGroup.close = func() {
				if !originalJoined {
					t.Error("original group closed before validator child join")
				}
			}
			cohort, e := newResolvedDowngradeCohort([]*standardengine.ResolvedDNSSECPlan{base[0].plan})
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := p.Canonical()
			state := standardengine.ResolvedServerState{PolicySHA256: standardengine.ResolvedPolicySHA256(raw), Name: base[0].plan.Name(), Selected: *p.Manager.CurrentDNS, Row: standardengine.ResolvedServerRow{Server: "192.0.2.53:5353#original.example", Type: "system", DNSSECMode: "allow-downgrade", VerifiedFeatureLevel: "n/a", PossibleFeatureLevel: "UDP+EDNS0+DO", DNSSECSupported: true}}
			originalAnswer, originalErr := resolveResolvedCompatibilityCohort(ctx, originalGroup, []resolvedQueryScope{{validate: func(work context.Context) ([]byte, error) {
				return resolveResolvedTerminal(work, p, base[0].plan, "udp", q, v, nil, false, &resolvedDowngradeTransport{}, func(context.Context) error { return nil }, func(context.Context) (standardengine.ResolvedServerState, error) { return state, nil }, cohort)
			}}}, q, func(context.Context) error { originalJoined = true; return nil }, systembootstrap.ResolvedResponseSuccess, cohort)
			if originalErr == nil || originalAnswer != nil || !originalJoined || !originalGroup.closed {
				t.Fatal("original bogus negative escaped joined normal terminal", originalErr)
			}
			if scenario == "original-retirement" {
				originalErr = &resolvedGroupRetirementError{errors.New("original owner retained")}
			}
			if scenario == "normal-winner" {
				originalErr = nil
				originalAnswer = base[1].answer.UnsignedAnswer()
			}
			if scenario == "capacity" {
				if resolvedPrivateTLDSlot(31, false) {
					t.Fatal("exception stole ordinary slot")
				}
				ledger = nil
			}
			calls := 0
			joined := false
			group := &resolvedDowngradeJoinedFixture{}
			group.close = func() {
				if !joined {
					t.Error("group closed before all proof children joined")
				}
			}
			if scenario == "close-error" {
				group.closeErr = errors.New("original physical group retained")
			}
			var mu sync.Mutex
			negativeFinished := make(chan struct{})
			arrivals := 0
			result, err := resolvePrivateTLDAfterOriginal(ctx, originalAnswer, originalErr, ledger, func(rows []resolvedPrivateCandidate) ([]byte, error) {
				calls++
				if !originalJoined || !originalGroup.closed {
					t.Fatal("auxiliary preceded original joined cohort")
				}
				return resolvePrivateTLDJoined(ctx, p, q, group, rows, func(work context.Context, row resolvedPrivateCandidate) (standardengine.DNSSECVerdict, error) {
					mu.Lock()
					arrivals++
					mu.Unlock()
					if positiveSibling && row.plan.Index() != 0 {
						select {
						case <-negativeFinished:
							// Keep the positive owner live while the completed
							// negative is classified; it must not cancel us.
							select {
							case <-time.After(25 * time.Millisecond):
							case <-work.Done():
								t.Error("negative retired a still-valid positive scope")
								return standardengine.DNSSECVerdict{}, work.Err()
							}
						case <-work.Done():
							t.Error("negative canceled original positive sibling")
							return standardengine.DNSSECVerdict{}, work.Err()
						}
					}
					proofQ := resolvedPrivateTLDQuestion(row.proof, q[:2])
					proof := standardengine.DNSSECVerdict{State: 1, RCode: 3, NXDomain: 1, Packet: resolvedScopeAnswer(proofQ, 3)}
					switch scenario {
					case "bogus-proof":
						proof.State = 3
					case "insecure-proof":
						proof.State = 2
					case "nodata-proof":
						proof.RCode = 0
						proof.NXDomain = 0
						proof.Packet = resolvedScopeAnswer(proofQ, 0)
					case "cancelled":
						cancel()
					}
					if positiveSibling && row.plan.Index() == 0 {
						close(negativeFinished)
					}
					return proof, nil
				}, func(context.Context) error {
					if scenario == "retire-error" {
						return errors.New("proof child retained")
					}
					joined = true
					return nil
				}, func(context.Context) error {
					if scenario == "postjoin-change" {
						return errors.New("original complete plan changed")
					}
					return nil
				})
			})
			success := scenario == "nxdomain-a" || scenario == "nxdomain-aaaa" || scenario == "nodata-a" || scenario == "nodata-aaaa" || positiveSibling || scenario == "normal-winner"
			if (err == nil) != success {
				t.Fatal(scenario, err)
			}
			if success {
				if result[3]&0x20 != 0 {
					t.Fatal("invented AD")
				}
				if positiveSibling {
					if binary.BigEndian.Uint16(result[6:8]) != 1 {
						t.Fatal("negative beat positive scope")
					}
				} else if scenario != "normal-winner" && (result[3]&15 != code || binary.BigEndian.Uint16(result[6:8]) != 0) {
					t.Fatal("changed original negative")
				}
			}
			if scenario == "normal-winner" || scenario == "capacity" || scenario == "original-retirement" {
				if calls != 0 {
					t.Fatal("forbidden auxiliary cohort")
				}
			} else if calls != 1 {
				t.Fatal("missing bounded proof")
			}
			if positiveSibling && arrivals != 2 {
				t.Fatal("not all original scopes executed")
			}
		})
	}
}
