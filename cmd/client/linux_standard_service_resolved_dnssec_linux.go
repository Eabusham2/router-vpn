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
func collectResolvedDNSSECAnchors(ctx, original context.Context, owner linuxResolvedDNSSECOwner, index int32, questions []standardengine.ResolvedDNSSECQuestion) ([]standardengine.ResolvedAnchorResult, error) {
	rows := make([]standardengine.ResolvedAnchorResult, 0, len(questions))
	for _, question := range questions {
		// A cancelled competing scope never strands the shared helper halfway
		// through an authenticated anchor frame. Original cancellation/deadline
		// still bounds the frame; no physical DNS or deadline renewal occurs here.
		observation, err := owner.anchorScoped(ctx, original, index, question.Name, question.Type)
		if err != nil {
			return nil, err
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		rows = append(rows, observation)
	}
	return rows, nil
}

// captureLinuxResolvedDNSSECPlan captures a prerequisite only. The caller must
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
	rows, err := collectResolvedDNSSECAnchors(ctx, original, owner, index, questions)
	if err != nil {
		return nil, err
	}
	plan, err := standardengine.BuildResolvedDNSSECPlan(policy, name, index, rows)
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
	rows, err := collectResolvedDNSSECAnchors(ctx, original, owner, plan.Index(), plan.Questions())
	if err != nil {
		return err
	}
	if err = plan.Recheck(rows); err != nil {
		return err
	}
	return observeResolvedDNSSECPolicy(ctx, original, owner, policy, plan.Name())
}
