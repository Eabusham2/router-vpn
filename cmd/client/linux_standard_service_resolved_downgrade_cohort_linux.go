//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/standardengine"
	"sync"
)

// One original cohort has at most 257 selected scopes. Workers may retain an
// immutable guard; only the joined caller seals/adopts it. No worker mutates
// the alias chain's remember slice or enters the physical baseline gate.
type resolvedDowngradeCohort struct {
	mu      sync.Mutex
	sealed  bool
	allowed map[int32]bool
	checks  map[int32]func(context.Context) error
}

func newResolvedDowngradeCohort(plans []*standardengine.ResolvedDNSSECPlan) (*resolvedDowngradeCohort, error) {
	if len(plans) == 0 || len(plans) > 257 {
		return nil, errors.New("compatibility cohort omitted bounded original plans")
	}
	c := &resolvedDowngradeCohort{allowed: make(map[int32]bool)}
	for _, plan := range plans {
		if plan == nil || plan.Index() < 0 || c.allowed[plan.Index()] {
			return nil, errors.New("compatibility cohort repeated original scope")
		}
		c.allowed[plan.Index()] = true
	}
	return c, nil
}
func (c *resolvedDowngradeCohort) retain(index int32, check func(context.Context) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealed || !c.allowed[index] || index < 0 || check == nil || len(c.checks) >= 257 || c.checks[index] != nil {
		return errors.New("compatibility cohort changed or exceeded original scope ownership")
	}
	if c.checks == nil {
		c.checks = make(map[int32]func(context.Context) error)
	}
	c.checks[index] = check
	return nil
}
func (c *resolvedDowngradeCohort) SealAndRecheck(ctx context.Context) error {
	c.mu.Lock()
	c.sealed = true
	c.mu.Unlock()
	return c.Recheck(ctx)
}
func (c *resolvedDowngradeCohort) Recheck(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if !c.sealed {
		c.mu.Unlock()
		return errors.New("compatibility cohort has not joined")
	}
	checks := make([]func(context.Context) error, 0, len(c.checks))
	for _, check := range c.checks {
		checks = append(checks, check)
	}
	c.mu.Unlock()
	for _, check := range checks {
		if err := check(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// This is the actual shipping dispatch after child.Validate, whose successful
// return includes the authenticated terminal receipt and natural joined exit.
func resolveResolvedTerminal(ctx context.Context, policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan, network string, question []byte, verdict standardengine.DNSSECVerdict, validationError error, aliasProof bool, group resolvedDNSSECExchangeGroup, current func(context.Context) error, observe func(context.Context) (standardengine.ResolvedServerState, error), cohort *resolvedDowngradeCohort) ([]byte, error) {
	if validationError != nil {
		return nil, validationError
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if verdict.State != 3 || plan == nil || plan.Mode() != "allow-downgrade" {
		return resolvedValidatedPacket(question, verdict, aliasProof)
	}
	if cohort == nil {
		return nil, errors.New("terminal compatibility continuation omitted original cohort")
	}
	index := plan.Index()
	return resolveOriginalDNSSECDowngradePurpose(ctx, policy, plan, network, question, verdict, nil, group, current, observe, aliasProof,
		func(check func(context.Context) error) error { return cohort.retain(index, check) })
}

// Only this joined collector may seal the ledger. Retained cleanup must not
// make it appear complete, including when another worker found a valid answer.
func resolveResolvedCompatibilityCohort(ctx context.Context, group resolvedQueryGroup, scopes []resolvedQueryScope, question []byte, retire func(context.Context) error, classify func([]byte, []byte) (bool, error), cohort *resolvedDowngradeCohort) ([]byte, error) {
	if cohort == nil {
		return nil, errors.New("resolver cohort omitted compatibility ownership")
	}
	answer, err := resolveOriginalScopesClassified(ctx, group, scopes, question, retire, classify)
	var retained *resolvedGroupRetirementError
	if errors.As(err, &retained) {
		return nil, err
	}
	if check := cohort.SealAndRecheck(ctx); check != nil {
		return nil, &resolvedAliasAuthorityError{errors.Join(err, check)}
	}
	return answer, err
}
