//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"

	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
)

type resolvedAliasAuthorityError struct{ err error }

func (e *resolvedAliasAuthorityError) Error() string { return e.err.Error() }
func (e *resolvedAliasAuthorityError) Unwrap() error { return e.err }

type resolvedAliasQueries interface {
	Current(context.Context) error
	Query(context.Context, string, []byte, bool) ([]byte, error)
	Accept(context.Context) error
}

// resolveCapturedAliasChain never changes the selected node or the original
// owner's name. An authenticated alias is a new DNS question, not permission
// to reuse its original resolver, NTA or positive anchor for another domain.
func resolveCapturedAliasChain(ctx context.Context, name string, original []byte, owner resolvedAliasQueries) ([]byte, error) {
	if owner == nil || !systembootstrap.QuestionMatchesName(original, name) {
		return nil, errors.New("alias resolution omitted original address owner")
	}
	query, err := standardengine.ResolvedDNSSECQuestionFromWire(name, 1, original)
	if err != nil {
		query, err = standardengine.ResolvedDNSSECQuestionFromWire(name, 28, original)
	}
	if err != nil {
		return nil, err
	}
	kind := query.Type
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	question := bytes.Clone(original)
	var steps []systembootstrap.ResolvedAlias
	seen := map[string]bool{}
	secure := true
	for hop := 0; hop < 16; hop++ {
		if seen[name] {
			return nil, errors.New("captured alias chain repeated a name")
		}
		seen[name] = true
		if err := owner.Current(ctx); err != nil {
			return nil, err
		}
		answer, err := owner.Query(ctx, name, question, false)
		var pending *resolvedDNSSECAliasProofRequired
		var unjoined *resolvedGroupRetirementError
		var changed *resolvedAliasAuthorityError
		if errors.As(err, &unjoined) || errors.As(err, &changed) {
			return nil, err
		}
		if errors.As(err, &pending) {
			if hop == 15 {
				return nil, errors.New("captured alias chain exceeds original bound")
			}
			if check := owner.Current(ctx); check != nil {
				return nil, check
			}
			proofQuestion, e := systembootstrap.ResolvedAliasQuery(original, name, 5)
			if e != nil {
				return nil, e
			}
			proof, e := owner.Query(ctx, name, proofQuestion, true)
			if e != nil {
				return nil, e
			}
			step, e := systembootstrap.ResolvedAliasStep(proofQuestion, proof)
			if e != nil || step == nil {
				return nil, errors.Join(e, errors.New("original alias was not independently proved"))
			}
			steps = append(steps, *step)
			secure = secure && proof[3]&0x20 != 0
			name = step.Target
			question, err = systembootstrap.ResolvedAliasQuery(original, name, kind)
			if err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		step, err := systembootstrap.ResolvedAliasStep(question, answer)
		if err != nil {
			return nil, err
		}
		if step != nil {
			// Only a captured DNSSEC=no scope returns an alias directly. Its AD
			// bit is cleared by the owned scope collector before reaching here.
			if hop == 15 {
				return nil, errors.New("captured alias chain exceeds original bound")
			}
			steps = append(steps, *step)
			secure = false
			name = step.Target
			question, err = systembootstrap.ResolvedAliasQuery(original, name, kind)
			if err != nil {
				return nil, err
			}
			continue
		}
		if err := owner.Accept(ctx); err != nil {
			return nil, err
		}
		if len(steps) == 0 {
			return answer, nil
		}
		return systembootstrap.ResolvedAliasAnswer(original, steps, question, answer, secure && answer[3]&0x20 != 0)
	}
	return nil, errors.New("captured alias chain exceeds original bound")
}

type linuxResolvedAliasChain struct {
	owner   *linuxBootBootstrapExchange
	network string
	checks  []func(context.Context) error
}

// Keep only each complete plan's immutable digest between alias cohorts. The
// active cohort owns the full records until its children and grants join;
// retaining those records for every prior name would multiply their storage by
// the alias bound. Final adoption still recaptures every present/absent anchor
// and the original policy, then compares the complete canonical plan.
func resolvedAliasTrustRecheck(original context.Context, owner linuxResolvedDNSSECOwner, policy standardengine.ResolvedPolicy, name string, plans []*standardengine.ResolvedDNSSECPlan) (func(context.Context) error, error) {
	if original == nil || owner == nil || len(plans) == 0 || len(plans) > 257 {
		return nil, errors.New("alias checkpoint omitted original bounded trust owner")
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	type checkpoint struct {
		index  int32
		digest string
	}
	checks := make([]checkpoint, 0, len(plans))
	seen := map[int32]bool{}
	for _, plan := range plans {
		if plan == nil || plan.Name() != name || !plan.MatchesPolicy(policy) || seen[plan.Index()] {
			return nil, errors.New("alias checkpoint changed original trust plan")
		}
		seen[plan.Index()] = true
		checks = append(checks, checkpoint{plan.Index(), standardengine.ResolvedPolicySHA256(plan.Canonical())})
	}
	return func(ctx context.Context) error {
		for _, check := range checks {
			plan, err := captureLinuxResolvedDNSSECPlan(ctx, original, owner, policy, name, check.index)
			if err != nil {
				return err
			}
			if standardengine.ResolvedPolicySHA256(plan.Canonical()) != check.digest {
				return errors.New("original alias trust checkpoint changed before adoption")
			}
		}
		return ctx.Err()
	}, nil
}

func (c *linuxResolvedAliasChain) Current(ctx context.Context) error {
	if ctx == nil || c == nil || c.owner == nil {
		return errors.New("alias chain lost original service owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.owner.Current(ctx)
}
func (c *linuxResolvedAliasChain) remember(check func(context.Context) error) {
	c.checks = append(c.checks, check)
}
func (c *linuxResolvedAliasChain) Accept(ctx context.Context) error {
	if err := c.Current(ctx); err != nil {
		return err
	}
	for _, check := range c.checks {
		if err := check(ctx); err != nil {
			return err
		}
	}
	return c.Current(ctx)
}
func (c *linuxResolvedAliasChain) Query(ctx context.Context, name string, question []byte, aliasProof bool) ([]byte, error) {
	if err := c.Current(ctx); err != nil {
		return nil, err
	}
	if len(c.checks) >= 32 {
		return nil, errors.New("alias chain exceeded its captured cohort bound")
	}
	if aliasProof {
		q, err := standardengine.ResolvedDNSSECAliasQuestionFromWire(name, question)
		if err != nil || q.Type != 5 || !strings.EqualFold(strings.TrimSuffix(q.Name, "."), strings.TrimSuffix(name, ".")) {
			return nil, errors.New("alias cohort changed original proof question")
		}
	} else if !systembootstrap.QuestionMatchesName(question, name) {
		return nil, errors.New("alias target changed original address question")
	}
	o := c.owner
	helper := o.original.resolver.helper
	policy, local, err := helper.observeScoped(ctx, o.operation, name)
	if err != nil {
		return nil, err
	}
	if local.Local {
		if aliasProof || strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(o.resolvedName, ".")) {
			return nil, errors.New("original alias source changed to a local-only decision")
		}
		want, err := local.Canonical()
		if err != nil {
			return nil, err
		}
		c.remember(func(check context.Context) error {
			_, got, err := helper.observeScoped(check, o.operation, name)
			if err != nil {
				return err
			}
			raw, err := got.Canonical()
			if err != nil || !bytes.Equal(want, raw) {
				return errors.Join(err, errors.New("alias target changed original local-only answer"))
			}
			return check.Err()
		})
		var addresses []netip.Addr
		for _, row := range local.Addresses {
			address, err := netip.ParseAddr(row.Address)
			if err != nil {
				return nil, err
			}
			addresses = append(addresses, address)
		}
		return systembootstrap.ResolvedLocalAddressAnswer(question, addresses)
	}
	routes, err := policy.ResolvedRoutes(name)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if route.DNSSEC == "yes" || route.DNSSEC == "allow-downgrade" {
			return o.exchangeResolvedDNSSECName(ctx, policy, c.network, name, question, aliasProof, c.remember)
		}
	}
	if aliasProof {
		return nil, errors.New("original alias proof lost its validating scope")
	}
	c.remember(func(check context.Context) error {
		return observeResolvedDNSSECPolicy(check, o.operation, helper, policy, name)
	})
	return o.exchangeResolvedPlain(ctx, policy, name, c.network, question)
}
