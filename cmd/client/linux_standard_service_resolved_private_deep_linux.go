//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
	"strings"
	"sync"
	"time"
)

type resolvedPrivateDeepCandidate struct {
	plan       *standardengine.ResolvedDNSSECPlan
	capability *standardengine.ResolvedPrivateDSDependencies
	answer     *systembootstrap.ResolvedPrivateTLDCandidate
	chain      *mobiletor.DesktopLinuxPrivateDSChain
}
type resolvedPrivateDeepCandidates struct {
	mu     sync.Mutex
	sealed bool
	rows   map[int32]resolvedPrivateDeepCandidate
}

func (c *resolvedPrivateDeepCandidates) retain(policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan, question []byte, v standardengine.DNSSECVerdict, validationErr error) {
	if c == nil || plan == nil || validationErr != nil || v.State != 3 || len(v.Packet) < 12 || len(question) < 12 || v.NXDomain > 1 || v.HaveData > 1 {
		return
	}
	packet := bytes.Clone(v.Packet)
	copy(packet[:2], question[:2])
	if v.RCode != uint32(packet[3]&15) || (v.NXDomain == 1) != (v.RCode == 3) || (v.HaveData == 0) != (binary.BigEndian.Uint16(packet[6:8]) == 0) {
		return
	}
	answer, err := systembootstrap.NewResolvedPrivateDeepCandidate(question, packet)
	if err != nil || answer.Name() != plan.Name() {
		return
	}
	capability, err := standardengine.NewResolvedPrivateDSDependencies(policy, plan, answer.Type(), answer.SHA256())
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealed || len(c.rows) >= 257 {
		return
	}
	if c.rows == nil {
		c.rows = map[int32]resolvedPrivateDeepCandidate{}
	}
	if _, ok := c.rows[plan.Index()]; ok {
		return
	}
	c.rows[plan.Index()] = resolvedPrivateDeepCandidate{plan: plan, capability: capability, answer: answer}
}
func (c *resolvedPrivateDeepCandidates) seal() []resolvedPrivateDeepCandidate {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sealed = true
	out := make([]resolvedPrivateDeepCandidate, 0, len(c.rows))
	for _, r := range c.rows {
		out = append(out, r)
	}
	return out
}
func resolvedPrivateDeepSlot(used int, aliasProof bool) bool {
	return !aliasProof && used >= 0 && used < 30
}
func resolvedPrivateDSQuestion(name string, kind uint16, id []byte) []byte {
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	copy(q[:2], id)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label != "" {
			q = append(q, byte(len(label)))
			q = append(q, label...)
		}
	}
	return append(q, 0, byte(kind>>8), byte(kind), 0, 1)
}
func resolvePrivateDeepAfterOriginal(ctx context.Context, answer []byte, originalErr error, private *resolvedPrivateDeepCandidates, run func([]resolvedPrivateDeepCandidate) ([]byte, error)) ([]byte, error) {
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
		return nil, errors.Join(originalErr, errors.New("private DS omitted original joined continuation"))
	}
	proved, err := run(rows)
	if err != nil {
		return nil, errors.Join(originalErr, err)
	}
	return proved, nil
}

// All dependency workers finish before Close, including failed sibling scopes.
// Success here is an opaque protected receipt pair, never a synthetic DNS reply.
func resolvePrivateDSDependenciesJoined(ctx context.Context, group resolvedQueryGroup, rows []resolvedPrivateDeepCandidate, fetch func(context.Context, resolvedPrivateDeepCandidate) ([]*mobiletor.DesktopLinuxPrivateDSReply, error), seal func(resolvedPrivateDeepCandidate, []*mobiletor.DesktopLinuxPrivateDSReply) (*mobiletor.DesktopLinuxPrivateDSChain, error), recheck func(context.Context) error) ([]resolvedPrivateDeepCandidate, error) {
	if ctx == nil || group == nil || len(rows) == 0 || len(rows) > 257 || fetch == nil || seal == nil || recheck == nil {
		return nil, errors.New("private DS omitted bounded original dependency ownership")
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		row     resolvedPrivateDeepCandidate
		replies []*mobiletor.DesktopLinuxPrivateDSReply
		err     error
	}
	results := make(chan result, len(rows))
	var workers sync.WaitGroup
	for _, row := range rows {
		workers.Add(1)
		go func(r resolvedPrivateDeepCandidate) {
			defer workers.Done()
			replies, err := fetch(work, r)
			results <- result{r, replies, err}
		}(row)
	}
	joined := make(chan struct{})
	go func() { workers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-ctx.Done():
		cancel()
	}
	cleanup, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer end()
	select {
	case <-joined:
	case <-cleanup.Done():
		return nil, &resolvedGroupRetirementError{cleanup.Err()}
	}
	if err := group.Close(cleanup); err != nil {
		return nil, &resolvedGroupRetirementError{err}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := recheck(ctx); err != nil {
		return nil, &resolvedAliasAuthorityError{err}
	}
	out := make([]resolvedPrivateDeepCandidate, 0, len(rows))
	var failures error
	for range rows {
		r := <-results
		if r.err != nil {
			failures = errors.Join(failures, r.err)
			continue
		}
		chain, err := seal(r.row, r.replies)
		if err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		r.row.chain = chain
		out = append(out, r.row)
	}
	if len(out) == 0 {
		return nil, errors.Join(failures, errors.New("private DS has no complete original dependency chain"))
	}
	return out, nil
}

func (o *linuxBootBootstrapExchange) exchangeResolvedPrivateDeep(ctx context.Context, policy standardengine.ResolvedPolicy, network string, question []byte, rows []resolvedPrivateDeepCandidate, recheck func(context.Context) error, remember func(func(context.Context) error)) ([]byte, error) {
	if len(question) < 12 || len(rows) == 0 || len(rows) > 257 || recheck == nil || remember == nil {
		return nil, errors.New("private DS omitted original bounded candidate cohort")
	}
	physicalCheck := func(check context.Context) error {
		if err := recheck(check); err != nil {
			return err
		}
		return o.Current(check)
	}
	if err := physicalCheck(ctx); err != nil {
		return nil, &resolvedAliasAuthorityError{err}
	}
	caps := make([]*standardengine.ResolvedPrivateDSDependencies, 0, len(rows))
	for _, r := range rows {
		if r.capability == nil || r.answer == nil || !r.capability.Matches(policy, r.plan, r.answer.Type(), r.answer.SHA256()) {
			return nil, errors.New("private DS changed original candidate")
		}
		caps = append(caps, r.capability)
	}
	// One checkpoint per actually admitted auxiliary cohort; no unused exception
	// steals normal/alias capacity. Each receives the existing three trust reads.
	remember(recheck)
	dsGroup, err := o.native.BeginBootstrapPrivateDSGroup(o.operation, o.lease.lock, policy, caps)
	if err != nil {
		return nil, err
	}
	resolver := o.original.resolver
	routeFor := func(row resolvedPrivateDeepCandidate) (standardengine.ResolvedRoute, error) {
		routes, err := policy.ResolvedRoutes(row.plan.Name())
		if err != nil {
			return standardengine.ResolvedRoute{}, err
		}
		for _, r := range routes {
			if r.Index == row.plan.Index() {
				return r, nil
			}
		}
		return standardengine.ResolvedRoute{}, errors.New("private DS lost original selected scope")
	}
	fetch := func(work context.Context, row resolvedPrivateDeepCandidate) ([]*mobiletor.DesktopLinuxPrivateDSReply, error) {
		route, err := routeFor(row)
		if err != nil {
			return nil, err
		}
		guard := func(check context.Context) error {
			return observeResolvedDNSSECPolicy(check, o.operation, resolver.helper, policy, row.plan.Name())
		}
		replies := make([]*mobiletor.DesktopLinuxPrivateDSReply, 0, 2)
		for _, want := range row.capability.Questions() {
			wire := resolvedPrivateDSQuestion(want.Name, want.Type, question[:2])
			typed, err := mobiletor.NewDesktopLinuxBootstrapPrivateDSQuestion(policy, row.capability, wire)
			if err != nil {
				return nil, err
			}
			var reply *mobiletor.DesktopLinuxPrivateDSReply
			if route.DNSOverTLS == "opportunistic" {
				selected, e := mobiletor.NewDesktopLinuxOpportunisticDNS(policy, row.plan.Name(), route.Index, network)
				if e != nil {
					return nil, e
				}
				reply, err = dsGroup.ExchangeOpportunisticPrivateDS(work, selected, typed, guard)
			} else {
				upstream, e := resolvedRouteTransport(route, network)
				if e != nil {
					return nil, e
				}
				reply, err = dsGroup.ExchangePrivateDS(work, upstream, typed, guard)
			}
			if err != nil {
				return nil, err
			}
			replies = append(replies, reply)
		}
		return replies, nil
	}
	rows, err = resolvePrivateDSDependenciesJoined(ctx, dsGroup, rows, fetch, func(row resolvedPrivateDeepCandidate, replies []*mobiletor.DesktopLinuxPrivateDSReply) (*mobiletor.DesktopLinuxPrivateDSChain, error) {
		return dsGroup.SealPrivateDSReplies(row.capability, replies)
	}, physicalCheck)
	if err != nil {
		return nil, err
	}
	// A fresh full checkpoint before the root owner supplies its first read;
	// the dependency cohort's joined check above supplied its second read.
	if err = physicalCheck(ctx); err != nil {
		return nil, &resolvedAliasAuthorityError{err}
	}
	chains := make([]*mobiletor.DesktopLinuxPrivateDSChain, 0, len(rows))
	for _, r := range rows {
		chains = append(chains, r.chain)
	}
	remember(recheck)
	rootGroup, err := dsGroup.BeginPrivateDSRootGroup(policy, chains)
	if err != nil {
		return nil, err
	}
	validate := func(work context.Context, row resolvedPrivateDeepCandidate) (standardengine.DNSSECVerdict, error) {
		deadline, ok := work.Deadline()
		if !ok {
			return standardengine.DNSSECVerdict{}, errors.New("private DS root omitted original deadline")
		}
		inputs := row.capability.Inputs()
		capture := standardengine.DNSSECCapture{Schema: 1, Session: o.original.session, DeadlineNS: deadline.UnixNano(), PlanSHA256: standardengine.SHA256(row.chain.Canonical()), Name: row.capability.TLD(), Type: 1, Anchors: inputs.TrustAnchors, Insecure: inputs.InsecureDomains}
		raw, err := capture.Canonical()
		if err != nil {
			return standardengine.DNSSECVerdict{}, err
		}
		captureSHA := standardengine.SHA256(raw)
		child, err := resolver.startDNSSECChild(work, o.service.root, capture)
		if err != nil {
			return standardengine.DNSSECVerdict{}, err
		}
		return child.Validate(work, func(check context.Context, request standardengine.DNSSECQuery) ([]byte, error) {
			if request.CaptureSHA256 != captureSHA || request.PlanSHA256 != capture.PlanSHA256 || request.Name != capture.Name || request.Type != 1 {
				return nil, errors.New("private DS root child changed original purpose")
			}
			typed, err := mobiletor.NewDesktopLinuxBootstrapPrivateDSRootQuestion(policy, row.chain, request.Packet)
			if err != nil {
				return nil, err
			}
			route, err := routeFor(row)
			if err != nil {
				return nil, err
			}
			guard := func(c context.Context) error {
				return observeResolvedDNSSECPolicy(c, o.operation, resolver.helper, policy, row.plan.Name())
			}
			if route.DNSOverTLS == "opportunistic" {
				selected, e := mobiletor.NewDesktopLinuxOpportunisticDNS(policy, row.plan.Name(), route.Index, network)
				if e != nil {
					return nil, e
				}
				return rootGroup.ExchangeOpportunisticDNSSEC(check, selected, typed, guard)
			}
			upstream, err := resolvedRouteTransport(route, network)
			if err != nil {
				return nil, err
			}
			return rootGroup.ExchangeDNSSEC(check, upstream, typed, guard)
		})
	}
	return resolvePrivateDeepRootJoined(ctx, policy, question, rootGroup, rows, validate, func(row resolvedPrivateDeepCandidate, q []byte, v standardengine.DNSSECVerdict) error {
		return rootGroup.CheckPrivateDSRootVerdict(row.chain, q, v)
	}, func(row resolvedPrivateDeepCandidate, q []byte, v standardengine.DNSSECVerdict) (*standardengine.ResolvedPrivateDSProof, error) {
		return rootGroup.CompletePrivateDSProof(row.chain, q, v)
	}, resolver.closeDNSSECChildren, physicalCheck)
}

func resolvePrivateDeepRootJoined(ctx context.Context, policy standardengine.ResolvedPolicy, question []byte, group resolvedQueryGroup, rows []resolvedPrivateDeepCandidate, validate func(context.Context, resolvedPrivateDeepCandidate) (standardengine.DNSSECVerdict, error), preview func(resolvedPrivateDeepCandidate, []byte, standardengine.DNSSECVerdict) error, complete func(resolvedPrivateDeepCandidate, []byte, standardengine.DNSSECVerdict) (*standardengine.ResolvedPrivateDSProof, error), retire, recheck func(context.Context) error) ([]byte, error) {
	if len(question) < 12 || len(rows) == 0 || len(rows) > 257 || group == nil || validate == nil || preview == nil || complete == nil || retire == nil || recheck == nil {
		return nil, errors.New("private DS root omitted bounded ownership")
	}
	type accepted struct {
		row      resolvedPrivateDeepCandidate
		question []byte
		verdict  standardengine.DNSSECVerdict
	}
	var mu sync.Mutex
	var acceptedRows []accepted
	scopes := make([]resolvedQueryScope, 0, len(rows))
	for _, row := range rows {
		row := row
		scopes = append(scopes, resolvedQueryScope{validate: func(work context.Context) ([]byte, error) {
			if row.capability == nil || row.answer == nil || !row.capability.Matches(policy, row.plan, row.answer.Type(), row.answer.SHA256()) {
				return nil, errors.New("private DS root changed candidate association")
			}
			v, err := validate(work, row)
			if err != nil {
				return nil, err
			}
			if err = work.Err(); err != nil {
				return nil, err
			}
			q := resolvedPrivateDSQuestion(row.capability.TLD(), 1, question[:2])
			v.Packet = bytes.Clone(v.Packet)
			if len(v.Packet) >= 2 {
				copy(v.Packet[:2], q[:2])
			}
			if err = preview(row, q, v); err != nil {
				return nil, err
			}
			mu.Lock()
			acceptedRows = append(acceptedRows, accepted{row, q, v})
			mu.Unlock()
			return row.answer.UnsignedAnswer(), nil
		}})
	}
	answer, err := resolveOriginalScopesClassified(ctx, group, scopes, question, retire, func(q, a []byte) (bool, error) {
		positive, e := systembootstrap.ResolvedResponseSuccess(q, a)
		return positive && len(a) >= 12 && binary.BigEndian.Uint16(a[6:8]) > 0, e
	})
	var retained *resolvedGroupRetirementError
	if errors.As(err, &retained) {
		return nil, err
	}
	if check := recheck(ctx); check != nil {
		return nil, &resolvedAliasAuthorityError{errors.Join(err, check)}
	}
	if err != nil {
		return nil, err
	}
	// Preview is not adoption. Complete requires the original root owner closed.
	for _, r := range acceptedRows {
		if !bytes.Equal(answer, r.row.answer.UnsignedAnswer()) {
			continue
		}
		proof, e := complete(r.row, r.question, r.verdict)
		if e != nil {
			return nil, e
		}
		if proof == nil || !proof.Matches(policy, r.row.plan, r.row.answer.Type(), r.row.answer.SHA256()) {
			return nil, errors.New("private DS final candidate association changed")
		}
		if len(answer) >= 12 {
			answer[2] = (answer[2] &^ 1) | (question[2] & 1)
			answer[3] = (answer[3] &^ 0x30) | (question[3] & 0x10)
		}
		return answer, nil
	}
	return nil, errors.New("private DS winner lost joined original proof")
}
