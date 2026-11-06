//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
)

type resolvedAliasModel struct {
	current func(context.Context) error
	query   func(context.Context, string, []byte, bool) ([]byte, error)
	accept  func(context.Context) error
}

func (m *resolvedAliasModel) Current(ctx context.Context) error {
	if m.current != nil {
		return m.current(ctx)
	}
	return ctx.Err()
}
func (m *resolvedAliasModel) Query(ctx context.Context, n string, q []byte, proof bool) ([]byte, error) {
	return m.query(ctx, n, q, proof)
}
func (m *resolvedAliasModel) Accept(ctx context.Context) error { return m.accept(ctx) }
func resolvedAliasModelName(n string) []byte {
	var r []byte
	for _, label := range strings.Split(n, ".") {
		r = append(r, byte(len(label)))
		r = append(r, label...)
	}
	return append(r, 0)
}
func resolvedAliasModelPacket(q []byte, name, target string, secure bool, dname bool) []byte {
	// Model queries use no EDNS. Native crypto/IPC tests separately prove signed
	// and tampered CNAME/DNAME records with the actual pinned validator.
	r := resolvedScopeAnswer(q, 0)
	if secure {
		r[3] |= 0x20
	}
	r[7] = 1
	owner, kind, data := name, uint16(5), resolvedAliasModelName(target)
	if dname {
		owner, kind, data = "entry.example", 39, resolvedAliasModelName("exit.example")
	}
	r = append(r, resolvedAliasModelName(owner)...)
	r = append(r, byte(kind>>8), byte(kind), 0, 1, 0, 0, 0, 30, byte(len(data)>>8), byte(len(data)))
	return append(r, data...)
}

func TestResolvedAliasChainFreshTarget(t *testing.T) {
	for _, scenario := range []string{"secure-cname", "secure-dname", "original-nta", "plain-original", "target-no", "target-local", "target-nxdomain"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			q, err := dnsmeasure.TransportBootstrapQuery("host.entry.example", false)
			if err != nil {
				t.Fatal(err)
			}
			var calls []string
			accepted := false
			model := &resolvedAliasModel{accept: func(context.Context) error { accepted = true; return nil }}
			model.query = func(work context.Context, name string, question []byte, proof bool) ([]byte, error) {
				calls = append(calls, fmt.Sprintf("%s/%t", name, proof))
				if name == "host.entry.example" {
					packet := resolvedAliasModelPacket(question, name, "host.exit.example", scenario != "original-nta", scenario == "secure-dname")
					if scenario == "plain-original" {
						packet[3] &^= 0x20
						return packet, nil
					}
					if !proof {
						return nil, &resolvedDNSSECAliasProofRequired{packet}
					}
					return packet, nil
				}
				if name != "host.exit.example" || proof || !systembootstrap.QuestionMatchesName(question, name) {
					t.Fatal("target escaped fresh exact-name address query", name, proof)
				}
				if scenario == "target-nxdomain" {
					return resolvedScopeAnswer(question, 3), nil
				}
				answer, err := systembootstrap.ResolvedLocalAddressAnswer(question, []netip.Addr{netip.MustParseAddr("192.0.2.7")})
				if scenario != "target-local" && scenario != "target-no" {
					answer[3] |= 0x20
				}
				return answer, err
			}
			answer, err := resolveCapturedAliasChain(ctx, "host.entry.example", q, model)
			if err != nil || !accepted {
				t.Fatal("captured alias did not complete final owner recheck", err)
			}
			want := []string{"host.entry.example/false", "host.entry.example/true", "host.exit.example/false"}
			if scenario == "plain-original" {
				want = []string{"host.entry.example/false", "host.exit.example/false"}
			}
			if strings.Join(calls, ",") != strings.Join(want, ",") {
				t.Fatal("alias did not create fresh target cohort", calls)
			}
			secure := scenario == "secure-cname" || scenario == "secure-dname" || scenario == "target-nxdomain"
			// An unsigned terminal denial has no local AD proof in this model.
			if scenario == "target-nxdomain" {
				secure = false
			}
			if (answer[3]&0x20 != 0) != secure {
				t.Fatal("authentication crossed original NTA/plain/local boundary")
			}
			if scenario == "target-nxdomain" && answer[3]&15 != 3 {
				t.Fatal("target denial became success")
			}
		})
	}
}

func TestResolvedAliasChainRefusals(t *testing.T) {
	for _, scenario := range []string{"bogus-proof", "missing-proof", "unjoined-original", "changed-original", "cancelled-before-proof", "changed-ancestor-final", "target-failure", "cycle", "bound"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			name := "host.entry.example"
			q, _ := dnsmeasure.TransportBootstrapQuery(name, false)
			calls, proofs := 0, 0
			accepted := false
			model := &resolvedAliasModel{accept: func(context.Context) error {
				if scenario == "changed-ancestor-final" {
					return errors.New("original loaded NTA changed")
				}
				accepted = true
				return nil
			}}
			model.query = func(work context.Context, n string, question []byte, proof bool) ([]byte, error) {
				calls++
				if proof {
					proofs++
				}
				target := "host.exit.example"
				if scenario == "cycle" {
					if n == target {
						target = name
					}
				}
				if scenario == "bound" {
					target = fmt.Sprintf("hop%d.example", calls)
				}
				if n == name || scenario == "cycle" || scenario == "bound" {
					packet := resolvedAliasModelPacket(question, n, target, true, false)
					if !proof {
						pending := &resolvedDNSSECAliasProofRequired{packet}
						switch scenario {
						case "unjoined-original":
							return nil, &resolvedGroupRetirementError{pending}
						case "changed-original":
							return nil, &resolvedAliasAuthorityError{pending}
						case "cancelled-before-proof":
							cancel()
						}
						return nil, pending
					}
					if scenario == "bogus-proof" {
						return nil, errors.New("actual validator refused alias signature")
					}
					if scenario == "missing-proof" {
						return resolvedScopeAnswer(question, 0), nil
					}
					return packet, nil
				}
				if scenario == "target-failure" {
					return nil, errors.New("target has no captured positive anchor or NTA")
				}
				return systembootstrap.ResolvedLocalAddressAnswer(question, []netip.Addr{netip.MustParseAddr("192.0.2.8")})
			}
			answer, err := resolveCapturedAliasChain(ctx, name, q, model)
			if err == nil || answer != nil || accepted {
				t.Fatal("unproved/retired/stale alias path adopted", err)
			}
			if (scenario == "unjoined-original" || scenario == "changed-original" || scenario == "cancelled-before-proof") && (calls != 1 || proofs != 0) {
				t.Fatal("failed original admitted replacement cohort", calls, proofs)
			}
			if scenario == "bound" && (calls != 31 || proofs != 15) {
				t.Fatal("alias cohort bound changed", calls, proofs)
			}
		})
	}
}

func TestResolvedAliasProofCannotInheritNTA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	policy := resolvedAdapterPolicy()
	policy.Manager.DNSSEC = "yes"
	policy.Manager.NegativeTrustAnchors = []string{"entry.example"}
	owner := &resolvedDNSSECOwnerFixture{policy: policy}
	first, err := captureLinuxResolvedDNSSECPlan(ctx, ctx, owner, policy, "host.entry.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	input, err := first.ValidatorInputs()
	if err != nil || len(input.InsecureDomains) != 1 {
		t.Fatal("original explicit NTA missing", err)
	}
	target, err := captureLinuxResolvedDNSSECPlan(ctx, ctx, owner, policy, "host.exit.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = target.ValidatorInputs(); err == nil {
		t.Fatal("unrelated target inherited original NTA instead of requiring its own trust")
	}
	if first.Name() == target.Name() || standardengine.ResolvedPolicySHA256(first.Canonical()) == standardengine.ResolvedPolicySHA256(target.Canonical()) {
		t.Fatal("distinct target reused captured source plan")
	}
}

func TestResolvedAliasPendingSurvivesNegativeScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q, _ := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
	f := &resolvedScopeFixture{}
	scopes := []resolvedQueryScope{{validate: func(context.Context) ([]byte, error) { return resolvedScopeAnswer(q, 3), nil }}, {validate: func(context.Context) ([]byte, error) {
		return nil, &resolvedDNSSECAliasProofRequired{[]byte("untrusted discovery")}
	}}}
	answer, err := resolveOriginalScopesOwned(ctx, f, scopes, q, nil)
	var pending *resolvedDNSSECAliasProofRequired
	if !errors.As(err, &pending) || answer != nil || !f.closed {
		t.Fatal("negative scope erased alias or bypassed joined retirement", err)
	}
}

func TestResolvedAliasProofClassifierWaitsForAlias(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q, _ := dnsmeasure.TransportBootstrapQuery("host.entry.example", false)
	q, _ = systembootstrap.ResolvedAliasQuery(q, "host.entry.example", 5)
	first := make(chan struct{})
	f := &resolvedScopeFixture{}
	scopes := []resolvedQueryScope{{validate: func(context.Context) ([]byte, error) { close(first); return resolvedScopeAnswer(q, 0), nil }}, {validate: func(work context.Context) ([]byte, error) {
		<-first
		if work.Err() != nil {
			return nil, work.Err()
		}
		return resolvedAliasModelPacket(q, "host.entry.example", "host.exit.example", true, false), nil
	}}}
	classify := func(question, answer []byte) (bool, error) {
		step, err := systembootstrap.ResolvedAliasStep(question, answer)
		return step != nil, err
	}
	answer, err := resolveOriginalScopesClassified(ctx, f, scopes, q, nil, classify)
	if err != nil || len(answer) < 12 || binary.BigEndian.Uint16(answer[6:8]) != 1 || !f.closed {
		t.Fatal("early NODATA cancelled a proved alias", err)
	}
}

func TestResolvedAliasTrustCheckpoint(t *testing.T) {
	for _, scenario := range []string{"unchanged", "absent-to-present", "present-to-absent", "daemon-lost", "local-decision", "cancelled", "wrong-name", "duplicate-scope"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			policy := resolvedAdapterPolicy()
			policy.Manager.DNSSEC = "yes"
			policy.Manager.NegativeTrustAnchors = []string{"example"}
			owner := &resolvedDNSSECOwnerFixture{policy: policy, changed: scenario == "present-to-absent"}
			plan, err := captureLinuxResolvedDNSSECPlan(ctx, ctx, owner, policy, "vpn.example", 0)
			if err != nil {
				t.Fatal(err)
			}
			plans := []*standardengine.ResolvedDNSSECPlan{plan}
			name := "vpn.example"
			if scenario == "wrong-name" {
				name = "other.example"
			}
			if scenario == "duplicate-scope" {
				plans = append(plans, plan)
			}
			check, err := resolvedAliasTrustRecheck(ctx, owner, policy, name, plans)
			if scenario == "wrong-name" || scenario == "duplicate-scope" {
				if err == nil || check != nil {
					t.Fatal("changed checkpoint admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// A completed cohort may discard its plans. Final checks must use
			// sealed complete-state digests, not a borrowed slice of old plans.
			plans[0] = nil
			switch scenario {
			case "absent-to-present":
				owner.changed = true
			case "present-to-absent":
				owner.changed = false
			case "daemon-lost":
				owner.lost = true
			case "local-decision":
				owner.local = true
			case "cancelled":
				cancel()
			}
			err = check(ctx)
			if scenario == "unchanged" {
				if err != nil || owner.reads != 12 || owner.observations != 4 {
					t.Fatal("checkpoint omitted complete fresh observations", err, owner.reads, owner.observations)
				}
			} else if err == nil {
				t.Fatal("changed original checkpoint accepted")
			}
		})
	}
}
