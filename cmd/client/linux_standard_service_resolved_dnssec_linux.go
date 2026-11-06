//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/standardengine"
)

// The shipping resolver helper implements this interface with its retained
// authenticated daemon/process/namespace owner. A decoded plan alone cannot
// implement these observations or authorize a protected upstream exchange.
type linuxResolvedDNSSECOwner interface {
	observeScoped(context.Context, context.Context, string) (standardengine.ResolvedPolicy, standardengine.ResolvedLocalResult, error)
	anchorScoped(context.Context, context.Context, int32, string, uint16) (standardengine.ResolvedAnchorResult, error)
	rootDSScoped(context.Context, context.Context, int32, string) (standardengine.ResolvedRootDSDecision, error)
}

func observeResolvedDNSSECPolicy(ctx, original context.Context, owner linuxResolvedDNSSECOwner, policy standardengine.ResolvedPolicy, name string) error {
	if owner == nil {
		return errors.New("DNSSEC capture omitted original helper")
	}
	observed, local, err := owner.observeScoped(ctx, original, name)
	if err != nil {
		return err
	}
	want, err := policy.Canonical()
	if err != nil {
		return err
	}
	got, err := observed.Canonical()
	if err != nil {
		return err
	}
	if local.Local || standardengine.ResolvedPolicySHA256(want) != standardengine.ResolvedPolicySHA256(got) {
		return errors.New("DNSSEC capture changed original policy or local-only decision")
	}
	return ctx.Err()
}

// captureLinuxResolvedDNSSECPlan retains the typed original trust decision. The caller must
// supply the same live owner at recheck and separately join its native validator
// and protected group before adopting any cryptographic result.
func captureLinuxResolvedDNSSECPlan(ctx, original context.Context, owner linuxResolvedDNSSECOwner, policy standardengine.ResolvedPolicy, name string, index int32) (*standardengine.ResolvedDNSSECPlan, error) {
	if err := observeResolvedDNSSECPolicy(ctx, original, owner, policy, name); err != nil {
		return nil, err
	}
	questions, err := standardengine.ResolvedDNSSECQuestions(policy, name, index)
	if err != nil {
		return nil, err
	}
	root, rows, err := collectResolvedDNSSECWithRoot(ctx, original, owner, index, name, questions)
	if err != nil {
		return nil, err
	}
	plan, err := standardengine.BuildResolvedDNSSECPlanWithRootDS(policy, name, index, root, rows)
	if err != nil {
		return nil, err
	}
	if err = observeResolvedDNSSECPolicy(ctx, original, owner, policy, name); err != nil {
		return nil, err
	}
	return plan, nil
}
func recheckLinuxResolvedDNSSECPlan(ctx, original context.Context, owner linuxResolvedDNSSECOwner, policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan) error {
	if plan == nil || !plan.MatchesPolicy(policy) {
		return errors.New("DNSSEC recheck changed original captured plan")
	}
	if err := observeResolvedDNSSECPolicy(ctx, original, owner, policy, plan.Name()); err != nil {
		return err
	}
	root, rows, err := collectResolvedDNSSECWithRoot(ctx, original, owner, plan.Index(), plan.Name(), plan.Questions())
	if err != nil {
		return err
	}
	if err = plan.RecheckWithRootDS(root, rows); err != nil {
		return err
	}
	return observeResolvedDNSSECPolicy(ctx, original, owner, policy, plan.Name())
}

func collectResolvedDNSSECWithRoot(ctx, original context.Context, owner linuxResolvedDNSSECOwner, index int32, name string, questions []standardengine.ResolvedDNSSECQuestion) (standardengine.ResolvedRootDSDecision, []standardengine.ResolvedAnchorResult, error) {
	var root standardengine.ResolvedRootDSDecision
	var rows []standardengine.ResolvedAnchorResult
	found := false
	for _, q := range questions {
		if q.Name == "." && q.Type == 43 {
			if found {
				return root, nil, errors.New("duplicate original root DS question")
			}
			found = true
			observed, err := owner.rootDSScoped(ctx, original, index, name)
			if err != nil {
				return root, nil, err
			}
			root = observed
		} else {
			observed, err := owner.anchorScoped(ctx, original, index, q.Name, q.Type)
			if err != nil {
				return root, nil, err
			}
			rows = append(rows, observed)
		}
		if err := ctx.Err(); err != nil {
			return root, nil, err
		}
	}
	if !found {
		return root, nil, errors.New("DNSSEC collection omitted typed original root DS")
	}
	return root, rows, nil
}
