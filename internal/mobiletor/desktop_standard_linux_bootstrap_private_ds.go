//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
)

// Replies are minted only after a protected exchange and its current-owner
// guard finish. Wire-only model observations cannot construct these tokens.
type DesktopLinuxPrivateDSReply struct {
	group              *DesktopLinuxBootstrapDNSGroup
	authority          string
	question, response []byte
}

// A chain retains the original closed dependency owner. The following proof
// owner inherits that exact operation, lease and protection, never a new timeout.
type DesktopLinuxPrivateDSChain struct {
	group      *DesktopLinuxBootstrapDNSGroup
	capability *standardengine.ResolvedPrivateDSDependencies
	replies    []standardengine.ResolvedPrivateDSReply
	canonical  []byte
}

func (c *DesktopLinuxPrivateDSChain) Canonical() []byte {
	if c == nil {
		return nil
	}
	return bytes.Clone(c.canonical)
}
func desktopLinuxBindPrivateDS(policy standardengine.ResolvedPolicy, caps []*standardengine.ResolvedPrivateDSDependencies) (*desktopLinuxBootstrapDNSSECBinding, error) {
	if len(caps) == 0 || len(caps) > desktopLinuxBootstrapGroupActive || caps[0] == nil {
		return nil, errors.New("private DS omitted original cohort")
	}
	raw, err := policy.Canonical()
	if err != nil {
		return nil, err
	}
	b := &desktopLinuxBootstrapDNSSECBinding{privateDS: 1, policy: bytes.Clone(raw), name: caps[0].Name(), kind: 43, plans: map[int32]string{}}
	for _, c := range caps {
		if c == nil || !c.MatchesPolicy(policy) || c.Name() != b.name || b.plans[c.Index()] != "" || len(c.Questions()) != 2 {
			return nil, errors.New("private DS changed original cohort")
		}
		b.plans[c.Index()] = standardengine.ResolvedPolicySHA256(c.Canonical())
	}
	// Exactly two questions per scope; TLS-first/UDP/TCP is at most three
	// attempts per question. Existing active/retained resource limits stand.
	b.admissions = 3 * 2 * len(caps)
	return b, nil
}
func (p *DesktopLinuxStandardProtection) BeginBootstrapPrivateDSGroup(original context.Context, lease *os.File, policy standardengine.ResolvedPolicy, caps []*standardengine.ResolvedPrivateDSDependencies) (*DesktopLinuxBootstrapDNSGroup, error) {
	b, err := desktopLinuxBindPrivateDS(policy, caps)
	if err != nil {
		return nil, err
	}
	return p.beginBootstrapDNSGroup(original, lease, b)
}
func newDesktopLinuxPrivateDSQuestion(policy standardengine.ResolvedPolicy, c *standardengine.ResolvedPrivateDSDependencies, chain *DesktopLinuxPrivateDSChain, wire []byte) (*DesktopLinuxBootstrapDNSSECQuestion, error) {
	if c == nil || !c.MatchesPolicy(policy) {
		return nil, errors.New("private DS changed original policy")
	}
	kind := uint16(43)
	sha := standardengine.ResolvedPolicySHA256(c.Canonical())
	if chain == nil {
		if _, err := c.Question(wire); err != nil {
			return nil, err
		}
	} else {
		if chain.capability != c {
			return nil, errors.New("private DS substituted completed chain")
		}
		if _, err := c.RootQuestion(wire); err != nil {
			return nil, err
		}
		kind = 1
		sha = standardengine.ResolvedPolicySHA256(chain.canonical)
	}
	raw, err := policy.Canonical()
	if err != nil {
		return nil, err
	}
	routes, err := policy.ResolvedRoutes(c.Name())
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.Index == c.Index() && r.CurrentDNS != nil && r.DNSSEC == "allow-downgrade" {
			q := &DesktopLinuxBootstrapDNSSECQuestion{privateDS: c, privateChain: chain, policy: bytes.Clone(raw), wire: bytes.Clone(wire), name: c.Name(), planSHA: sha, index: c.Index(), kind: kind, selected: *r.CurrentDNS, tls: r.DNSOverTLS}
			if _, err = q.upstream("udp", q.tls != "no"); err != nil {
				return nil, err
			}
			return q, nil
		}
	}
	return nil, errors.New("private DS lost original selected scope")
}
func NewDesktopLinuxBootstrapPrivateDSQuestion(policy standardengine.ResolvedPolicy, c *standardengine.ResolvedPrivateDSDependencies, wire []byte) (*DesktopLinuxBootstrapDNSSECQuestion, error) {
	return newDesktopLinuxPrivateDSQuestion(policy, c, nil, wire)
}
func NewDesktopLinuxBootstrapPrivateDSRootQuestion(policy standardengine.ResolvedPolicy, c *DesktopLinuxPrivateDSChain, wire []byte) (*DesktopLinuxBootstrapDNSSECQuestion, error) {
	if c == nil {
		return nil, errors.New("private DS omitted joined chain")
	}
	return newDesktopLinuxPrivateDSQuestion(policy, c.capability, c, wire)
}
func (q *DesktopLinuxBootstrapDNSSECQuestion) matchesPrivateDS(g *DesktopLinuxBootstrapDNSGroup, wire []byte) error {
	if q.privateChain == nil {
		if g.dnssec.privateDS != 1 || q.planSHA != standardengine.ResolvedPolicySHA256(q.privateDS.Canonical()) {
			return errors.New("private DS changed dependency owner")
		}
		_, err := q.privateDS.Question(wire)
		return err
	}
	if g.dnssec.privateDS != 2 || g.dnssec.privateChains[q.index] != q.privateChain || q.planSHA != standardengine.ResolvedPolicySHA256(q.privateChain.canonical) {
		return errors.New("private DS changed joined root owner")
	}
	_, err := q.privateDS.RootQuestion(wire)
	return err
}
func (g *DesktopLinuxBootstrapDNSGroup) privateDSReply(q *DesktopLinuxBootstrapDNSSECQuestion, answer []byte) (*DesktopLinuxPrivateDSReply, error) {
	if q == nil || q.privateDS == nil || q.privateChain != nil || g == nil || g.dnssec == nil || g.dnssec.privateDS != 1 {
		return nil, errors.New("private DS reply omitted dependency owner")
	}
	if err := common.ValidateUnsignedDSNegativeResponse(q.wire, answer); err != nil {
		return nil, err
	}
	return &DesktopLinuxPrivateDSReply{group: g, authority: q.planSHA, question: bytes.Clone(q.wire), response: bytes.Clone(answer)}, nil
}
func (g *DesktopLinuxBootstrapDNSGroup) ExchangePrivateDS(ctx context.Context, u DesktopLinuxBootstrapDNSUpstream, q *DesktopLinuxBootstrapDNSSECQuestion, current func(context.Context) error) (*DesktopLinuxPrivateDSReply, error) {
	if q == nil || q.privateDS == nil || q.privateChain != nil {
		return nil, errors.New("private DS exchange omitted dependency purpose")
	}
	answer, err := g.ExchangeDNSSEC(ctx, u, q, current)
	if err != nil {
		return nil, err
	}
	return g.privateDSReply(q, answer)
}
func (g *DesktopLinuxBootstrapDNSGroup) ExchangeOpportunisticPrivateDS(ctx context.Context, u *DesktopLinuxOpportunisticDNS, q *DesktopLinuxBootstrapDNSSECQuestion, current func(context.Context) error) (*DesktopLinuxPrivateDSReply, error) {
	if q == nil || q.privateDS == nil || q.privateChain != nil {
		return nil, errors.New("private DS exchange omitted dependency purpose")
	}
	answer, err := g.ExchangeOpportunisticDNSSEC(ctx, u, q, current)
	if err != nil {
		return nil, err
	}
	return g.privateDSReply(q, answer)
}
func (g *DesktopLinuxBootstrapDNSGroup) privateDSJoined() error {
	if g == nil || g.original == nil {
		return errors.New("private DS omitted owner")
	}
	if err := desktopnetwork.LockContext(g.original, &g.mu); err != nil {
		return err
	}
	closed := g.closed
	g.mu.Unlock()
	if !closed || g.original == nil || g.original.Err() != nil {
		return errors.New("private DS original owner unjoined or expired")
	}
	return nil
}
func (g *DesktopLinuxBootstrapDNSGroup) SealPrivateDSReplies(c *standardengine.ResolvedPrivateDSDependencies, tokens []*DesktopLinuxPrivateDSReply) (*DesktopLinuxPrivateDSChain, error) {
	if err := g.privateDSJoined(); err != nil {
		return nil, err
	}
	if c == nil || g.dnssec == nil || g.dnssec.privateDS != 1 || len(tokens) != 2 || g.dnssec.plans[c.Index()] != standardengine.ResolvedPolicySHA256(c.Canonical()) {
		return nil, errors.New("private DS omitted exact original chain")
	}
	result := &DesktopLinuxPrivateDSChain{group: g, capability: c}
	hashes := []string{}
	for i, t := range tokens {
		if t == nil || t.group != g || t.authority != g.dnssec.plans[c.Index()] {
			return nil, errors.New("private DS foreign reply owner")
		}
		q, err := c.Question(t.question)
		if err != nil || q != c.Questions()[i] {
			return nil, errors.New("private DS changed dependency order")
		}
		if err = common.ValidateUnsignedDSNegativeResponse(t.question, t.response); err != nil {
			return nil, err
		}
		result.replies = append(result.replies, standardengine.ResolvedPrivateDSReply{AuthoritySHA256: t.authority, Question: bytes.Clone(t.question), Response: bytes.Clone(t.response)})
		hashes = append(hashes, standardengine.ResolvedPolicySHA256(t.question), standardengine.ResolvedPolicySHA256(t.response))
	}
	result.canonical, _ = json.Marshal(struct {
		Purpose, Authority string
		Replies            []string
	}{"protected-private-ds-chain", standardengine.ResolvedPolicySHA256(c.Canonical()), hashes})
	return result, nil
}

// BeginPrivateDSRootGroup consumes only chains from this joined original
// cohort. There is no caller-provided replacement operation or lease.
func (g *DesktopLinuxBootstrapDNSGroup) BeginPrivateDSRootGroup(policy standardengine.ResolvedPolicy, chains []*DesktopLinuxPrivateDSChain) (*DesktopLinuxBootstrapDNSGroup, error) {
	if err := g.privateDSJoined(); err != nil {
		return nil, err
	}
	if len(chains) == 0 || len(chains) > desktopLinuxBootstrapGroupActive || g.owner == nil || g.lease == nil {
		return nil, errors.New("private DS omitted original root cohort")
	}
	caps := make([]*standardengine.ResolvedPrivateDSDependencies, 0, len(chains))
	for _, c := range chains {
		if c == nil || c.group != g {
			return nil, errors.New("private DS root mixed original dependency owners")
		}
		caps = append(caps, c.capability)
	}
	b, err := desktopLinuxBindPrivateDS(policy, caps)
	if err != nil {
		return nil, err
	}
	b.privateDS = 2
	b.kind = 1
	b.privateChains = map[int32]*DesktopLinuxPrivateDSChain{}
	for _, c := range chains {
		b.plans[c.capability.Index()] = standardengine.ResolvedPolicySHA256(c.canonical)
		b.privateChains[c.capability.Index()] = c
	}
	b.admissions = 3 * desktopLinuxBootstrapDNSSECQueries * len(chains)
	return g.owner.beginBootstrapDNSGroup(g.original, g.lease, b)
}

// The authenticated child must naturally exit and join before this call. This
// checks protected ownership, not child authentication or final policy freshness.
func (g *DesktopLinuxBootstrapDNSGroup) CompletePrivateDSProof(c *DesktopLinuxPrivateDSChain, question []byte, verdict standardengine.DNSSECVerdict) (*standardengine.ResolvedPrivateDSProof, error) {
	if err := g.privateDSJoined(); err != nil {
		return nil, err
	}
	if c == nil || g.dnssec == nil || g.dnssec.privateDS != 2 || g.dnssec.privateChains[c.capability.Index()] != c {
		return nil, errors.New("private DS proof changed joined root owner")
	}
	return c.capability.Complete(c.replies, question, verdict)
}
