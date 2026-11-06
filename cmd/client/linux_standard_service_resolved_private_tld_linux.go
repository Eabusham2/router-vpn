//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
	"strings"
	"sync"
)

type resolvedPrivateCandidate struct {
	plan   *standardengine.ResolvedDNSSECPlan
	proof  *standardengine.ResolvedPrivateTLDProof
	answer *systembootstrap.ResolvedPrivateTLDCandidate
}
type resolvedPrivateCandidates struct {
	mu     sync.Mutex
	sealed bool
	rows   map[int32]resolvedPrivateCandidate
}

// This ledger never converts State3 into success. Only joined original workers
// can hand its inert candidates to the separate, bounded denial-proof cohort.
func (c *resolvedPrivateCandidates) retain(policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan, question []byte, v standardengine.DNSSECVerdict, validationErr error) {
	if c == nil || validationErr != nil || plan == nil || v.State != 3 || v.RCode != 0 || v.NXDomain != 0 || v.HaveData != 1 || len(v.Packet) < 12 || len(question) < 12 {
		return
	}
	packet := bytes.Clone(v.Packet)
	copy(packet[:2], question[:2])
	candidate, err := systembootstrap.NewResolvedPrivateTLDCandidate(question, packet)
	if err != nil || candidate.Name() != plan.Name() {
		return
	}
	proof, err := standardengine.NewResolvedPrivateTLDProof(policy, plan, candidate.Type(), candidate.SHA256())
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealed || len(c.rows) >= 257 {
		return
	}
	if c.rows == nil {
		c.rows = map[int32]resolvedPrivateCandidate{}
	}
	if _, exists := c.rows[plan.Index()]; exists {
		return
	}
	c.rows[plan.Index()] = resolvedPrivateCandidate{plan, proof, candidate}
}
func (c *resolvedPrivateCandidates) seal() []resolvedPrivateCandidate {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sealed = true
	out := make([]resolvedPrivateCandidate, 0, len(c.rows))
	for _, r := range c.rows {
		out = append(out, r)
	}
	return out
}
func resolvedPrivateTLDQuestion(proof *standardengine.ResolvedPrivateTLDProof, id []byte) []byte {
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	copy(q[:2], id)
	label := strings.TrimSuffix(proof.TLD(), ".")
	q = append(q, byte(len(label)))
	q = append(q, label...)
	return append(q, 0, 0, 1, 0, 1)
}

// Proof winners cancel siblings only after exact secure NXDOMAIN acceptance.
// Every child retires before the group closes; postjoin original-plan checks
// must succeed before the unsigned candidate leaves this function.
func resolvePrivateTLDJoined(ctx context.Context, policy standardengine.ResolvedPolicy, question []byte, group resolvedQueryGroup, rows []resolvedPrivateCandidate, validate func(context.Context, resolvedPrivateCandidate) (standardengine.DNSSECVerdict, error), retire func(context.Context) error, recheck func(context.Context) error) ([]byte, error) {
	if len(question) < 12 || len(rows) == 0 || len(rows) > 257 || validate == nil || retire == nil || recheck == nil {
		return nil, errors.New("private-TLD cohort omitted bounded original ownership")
	}
	scopes := make([]resolvedQueryScope, 0, len(rows))
	for _, row := range rows {
		row := row
		scopes = append(scopes, resolvedQueryScope{validate: func(work context.Context) ([]byte, error) {
			if row.proof == nil || row.answer == nil || !row.proof.Matches(policy, row.plan, row.answer.Type(), row.answer.SHA256()) {
				return nil, errors.New("private-TLD candidate changed original proof association")
			}
			v, err := validate(work, row)
			if err != nil {
				return nil, err
			}
			if err = work.Err(); err != nil {
				return nil, err
			}
			if row.proof == nil || row.answer == nil {
				return nil, errors.New("private-TLD lost candidate association")
			}
			q := resolvedPrivateTLDQuestion(row.proof, question[:2])
			v.Packet = bytes.Clone(v.Packet)
			if len(v.Packet) >= 2 {
				copy(v.Packet[:2], q[:2])
			}
			if err = row.proof.CheckVerdict(q, v); err != nil {
				return nil, err
			}
			return row.answer.UnsignedAnswer(), nil
		}})
	}
	answer, err := resolveOriginalScopesClassified(ctx, group, scopes, question, retire, systembootstrap.ResolvedResponseSuccess)
	var retained *resolvedGroupRetirementError
	if errors.As(err, &retained) {
		return nil, err
	}
	if check := recheck(ctx); check != nil {
		return nil, &resolvedAliasAuthorityError{errors.Join(err, check)}
	}
	return answer, err
}

func (o *linuxBootBootstrapExchange) exchangeResolvedPrivateTLD(ctx context.Context, policy standardengine.ResolvedPolicy, network string, question []byte, rows []resolvedPrivateCandidate, recheck func(context.Context) error) ([]byte, error) {
	// This is auxiliary read one of three: before admission, after joined close,
	// and final alias-chain adoption. It consumes its own reserved cohort slot.
	if err := recheck(ctx); err != nil {
		return nil, &resolvedAliasAuthorityError{err}
	}
	if err := o.Current(ctx); err != nil {
		return nil, &resolvedAliasAuthorityError{err}
	}
	proofs := make([]*standardengine.ResolvedPrivateTLDProof, 0, len(rows))
	for _, r := range rows {
		if !r.proof.Matches(policy, r.plan, r.answer.Type(), r.answer.SHA256()) {
			return nil, errors.New("private-TLD candidate changed before proof admission")
		}
		proofs = append(proofs, r.proof)
	}
	group, err := o.native.BeginBootstrapPrivateTLDGroup(o.operation, o.lease.lock, policy, proofs)
	if err != nil {
		return nil, err
	}
	resolver := o.original.resolver
	validate := func(work context.Context, row resolvedPrivateCandidate) (standardengine.DNSSECVerdict, error) {
		var zero standardengine.DNSSECVerdict
		deadline, ok := work.Deadline()
		if !ok {
			return zero, errors.New("private-TLD omitted original deadline")
		}
		inputs := row.proof.Inputs()
		capture := standardengine.DNSSECCapture{Schema: 1, Session: o.original.session, DeadlineNS: deadline.UnixNano(), PlanSHA256: standardengine.SHA256(row.proof.Canonical()), Name: row.proof.TLD(), Type: 1, Anchors: inputs.TrustAnchors, Insecure: inputs.InsecureDomains}
		raw, err := capture.Canonical()
		if err != nil {
			return zero, err
		}
		captureSHA := standardengine.SHA256(raw)
		child, err := resolver.startDNSSECChild(work, o.service.root, capture)
		if err != nil {
			return zero, err
		}
		return child.Validate(work, func(check context.Context, request standardengine.DNSSECQuery) ([]byte, error) {
			if request.CaptureSHA256 != captureSHA || request.PlanSHA256 != capture.PlanSHA256 || request.Name != capture.Name || request.Type != 1 {
				return nil, errors.New("private-TLD child changed original purpose")
			}
			typed, err := mobiletor.NewDesktopLinuxBootstrapPrivateTLDQuestion(policy, row.proof, request.Packet)
			if err != nil {
				return nil, err
			}
			current := func(guard context.Context) error {
				return observeResolvedDNSSECPolicy(guard, o.operation, resolver.helper, policy, row.plan.Name())
			}
			routes, err := policy.ResolvedRoutes(row.plan.Name())
			if err != nil {
				return nil, err
			}
			for _, route := range routes {
				if route.Index != row.plan.Index() {
					continue
				}
				if route.DNSOverTLS == "opportunistic" {
					selected, err := mobiletor.NewDesktopLinuxOpportunisticDNS(policy, row.plan.Name(), route.Index, network)
					if err != nil {
						return nil, err
					}
					return group.ExchangeOpportunisticDNSSEC(check, selected, typed, current)
				}
				upstream, err := resolvedRouteTransport(route, network)
				if err != nil {
					return nil, err
				}
				return group.ExchangeDNSSEC(check, upstream, typed, current)
			}
			return nil, errors.New("private-TLD original scope disappeared")
		})
	}
	answer, err := resolvePrivateTLDJoined(ctx, policy, question, group, rows, validate, resolver.closeDNSSECChildren, recheck)
	var retained *resolvedGroupRetirementError
	if errors.As(err, &retained) {
		return nil, err
	}
	if check := o.Current(ctx); check != nil {
		return nil, &resolvedAliasAuthorityError{errors.Join(err, check)}
	}
	if len(answer) >= 12 {
		answer[2] = (answer[2] &^ 1) | (question[2] & 1)
		answer[3] = (answer[3] &^ 0x30) | (question[3] & 0x10)
	}
	return answer, err
}

// Capacity is optional: it must never reject the normal query or consume an
// unused exception slot. The original cohort will add its normal checkpoint.
func resolvedPrivateTLDSlot(used int, aliasProof bool) bool {
	return !aliasProof && used >= 0 && used < 31
}

// This is the shipping branch after the original joined cohort and its full
// authority checkpoints. Normal positive AND negative answers take priority;
// a deferred exception cannot replace an alias proof or an ownership failure.
func resolvePrivateTLDAfterOriginal(ctx context.Context, answer []byte, originalErr error, private *resolvedPrivateCandidates, run func([]resolvedPrivateCandidate) ([]byte, error)) ([]byte, error) {
	if originalErr == nil || answer != nil || private == nil {
		return answer, originalErr
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(originalErr, err)
	}
	var alias *resolvedDNSSECAliasProofRequired
	var authority *resolvedAliasAuthorityError
	var retained *resolvedGroupRetirementError
	if errors.As(originalErr, &alias) || errors.As(originalErr, &authority) || errors.As(originalErr, &retained) {
		return nil, originalErr
	}
	rows := private.seal()
	if len(rows) == 0 {
		return nil, originalErr
	}
	if run == nil {
		return nil, errors.Join(originalErr, errors.New("private-TLD omitted joined proof owner"))
	}
	proved, err := run(rows)
	if err != nil {
		return nil, errors.Join(originalErr, err)
	}
	return proved, nil
}
