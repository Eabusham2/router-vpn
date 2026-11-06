//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/standardengine"
	"testing"
	"time"
)

type resolvedRootCollectorFixture struct {
	*resolvedDNSSECOwnerFixture
	rootReads int
	failRoot  bool
}

func (f *resolvedRootCollectorFixture) anchorScoped(ctx, original context.Context, index int32, name string, kind uint16) (standardengine.ResolvedAnchorResult, error) {
	if name == "." && kind == 43 {
		return standardengine.ResolvedAnchorResult{}, errors.New("ordinary root DS read forbidden")
	}
	return f.resolvedDNSSECOwnerFixture.anchorScoped(ctx, original, index, name, kind)
}
func (f *resolvedRootCollectorFixture) rootDSScoped(ctx, original context.Context, index int32, name string) (standardengine.ResolvedRootDSDecision, error) {
	f.rootReads++
	if f.failRoot {
		return standardengine.ResolvedRootDSDecision{}, errors.New("original root owner disappeared")
	}
	return f.resolvedDNSSECOwnerFixture.rootDSScoped(ctx, original, index, name)
}
func TestResolvedDNSSECTypedRootCollector(t *testing.T) {
	for _, scenario := range []string{"zero-anchor", "strict-no-trust", "root-owner-lost", "root-changed", "final-recheck"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			policy := resolvedAdapterPolicy()
			policy.Manager.DNSSEC = "allow-downgrade"
			if scenario == "strict-no-trust" {
				policy.Manager.DNSSEC = "yes"
			}
			owner := &resolvedRootCollectorFixture{resolvedDNSSECOwnerFixture: &resolvedDNSSECOwnerFixture{policy: policy}}
			if scenario == "root-owner-lost" {
				owner.failRoot = true
			}
			plan, err := captureLinuxResolvedDNSSECPlan(ctx, ctx, owner, policy, "vpn.example", 0)
			if scenario == "root-owner-lost" {
				if err == nil {
					t.Fatal("lost original root decision ignored")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if owner.reads != 6 || owner.rootReads != 1 || owner.observations != 2 {
				t.Fatal("root DS did not replace exactly one original read", owner.reads, owner.rootReads, owner.observations)
			}
			inputs, err := plan.ValidatorInputs()
			if scenario == "strict-no-trust" {
				if err == nil {
					t.Fatal("strict no-trust became unsigned")
				}
				return
			}
			if err != nil || len(inputs.TrustAnchors) != 0 || len(inputs.InsecureDomains) != 0 {
				t.Fatal("original zeroTA required fake NTA", inputs, err)
			}
			if scenario == "root-changed" {
				owner.changed = true
			}
			err = recheckLinuxResolvedDNSSECPlan(ctx, ctx, owner, policy, plan)
			if scenario == "root-changed" {
				if err == nil {
					t.Fatal("replacement positive root ignored")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "final-recheck" {
				if err = recheckLinuxResolvedDNSSECPlan(ctx, ctx, owner, policy, plan); err != nil {
					t.Fatal(err)
				}
				if owner.reads != 18 || owner.rootReads != 3 || owner.observations != 6 {
					t.Fatal("capture/postjoin/adoption did not repeat complete typed plan", owner.reads, owner.rootReads, owner.observations)
				}
			}
		})
	}
}
