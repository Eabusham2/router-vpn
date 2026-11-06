//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/standardengine"
)

const desktopLinuxBootstrapDNSSECQueries = int(standardengine.MaxDNSSECQueries)

// This immutable binding authorizes only plans captured before the original
// group reservation. It does not turn ordinary address-query admission into a
// general DNS proxy, and cannot be installed on an already active group.
type desktopLinuxBootstrapDNSSECBinding struct {
	policy     []byte
	name       string
	kind       uint16
	plans      map[int32]string
	admissions int
}

func desktopLinuxBindDNSSEC(policy standardengine.ResolvedPolicy, plans []*standardengine.ResolvedDNSSECPlan, kind uint16) (*desktopLinuxBootstrapDNSSECBinding, error) {
	if kind != 1 && kind != 28 {
		return nil, errors.New("address validation requires its original A or AAAA purpose")
	}
	return desktopLinuxBindDNSSECQuestion(policy, plans, kind)
}

func desktopLinuxBindDNSSECQuestion(policy standardengine.ResolvedPolicy, plans []*standardengine.ResolvedDNSSECPlan, kind uint16) (*desktopLinuxBootstrapDNSSECBinding, error) {
	if len(plans) == 0 || len(plans) > desktopLinuxBootstrapGroupActive || kind != 1 && kind != 28 && kind != 5 || plans[0] == nil {
		return nil, errors.New("DNSSEC group omitted original complete plan cohort")
	}
	raw, err := policy.Canonical()
	if err != nil {
		return nil, err
	}
	b := &desktopLinuxBootstrapDNSSECBinding{policy: bytes.Clone(raw), name: plans[0].Name(), kind: kind, plans: map[int32]string{}}
	routes, err := policy.ResolvedRoutes(b.name)
	if err != nil || len(routes) > desktopLinuxBootstrapGroupActive {
		return nil, errors.New("DNSSEC group changed original selected scopes")
	}
	for _, plan := range plans {
		if plan == nil || plan.Name() != b.name || !plan.MatchesPolicy(policy) || b.plans[plan.Index()] != "" {
			return nil, errors.New("DNSSEC group mixed, duplicated or changed captured plans")
		}
		b.plans[plan.Index()] = standardengine.ResolvedPolicySHA256(plan.Canonical())
	}
	validating := 0
	for _, route := range routes {
		switch route.DNSSEC {
		case "yes", "allow-downgrade":
			validating++
			if b.plans[route.Index] == "" {
				return nil, errors.New("DNSSEC group omitted a validating original scope")
			}
		case "no":
			if b.plans[route.Index] != "" {
				return nil, errors.New("DNSSEC group substituted a nonvalidating scope")
			}
		default:
			return nil, errors.New("DNSSEC group encountered unknown original validation policy")
		}
	}
	if validating != len(plans) {
		return nil, errors.New("DNSSEC group includes a foreign validation scope")
	}
	// Each pinned validator admits at most 256 queries. A query may require
	// TLS-first, plaintext UDP and matching TCP. Active/retained FD and native
	// inventory limits remain unchanged; joined exact retirement recycles them.
	b.admissions = 3*len(routes) + 3*desktopLinuxBootstrapDNSSECQueries*len(plans)
	return b, nil
}

func (p *DesktopLinuxStandardProtection) BeginBootstrapDNSSECGroup(original context.Context, lease *os.File, policy standardengine.ResolvedPolicy, plans []*standardengine.ResolvedDNSSECPlan, kind uint16) (*DesktopLinuxBootstrapDNSGroup, error) {
	binding, err := desktopLinuxBindDNSSEC(policy, plans, kind)
	if err != nil {
		return nil, err
	}
	return p.beginBootstrapDNSGroup(original, lease, binding)
}

// BeginBootstrapDNSSECAliasGroup admits only an exact-name CNAME proof and
// its DS/DNSKEY ancestors. Address queries and the alias target require a new
// captured cohort; an existing address group cannot be promoted to this owner.
func (p *DesktopLinuxStandardProtection) BeginBootstrapDNSSECAliasGroup(original context.Context, lease *os.File, policy standardengine.ResolvedPolicy, plans []*standardengine.ResolvedDNSSECPlan) (*DesktopLinuxBootstrapDNSGroup, error) {
	binding, err := desktopLinuxBindDNSSECQuestion(policy, plans, 5)
	if err != nil {
		return nil, err
	}
	return p.beginBootstrapDNSGroup(original, lease, binding)
}

// DesktopLinuxBootstrapDNSSECQuestion retains one exact child query and its
// original loaded trust plan. Its private fields cannot be fabricated through
// an ordinary Exchange call or changed by editing the caller's byte slice.
type DesktopLinuxBootstrapDNSSECQuestion struct {
	policy, wire  []byte
	name, planSHA string
	index         int32
	kind          uint16
	selected      standardengine.ResolvedDNS
	tls           string
}

func NewDesktopLinuxBootstrapDNSSECQuestion(policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan, kind uint16, wire []byte) (*DesktopLinuxBootstrapDNSSECQuestion, error) {
	if kind != 1 && kind != 28 {
		return nil, errors.New("address validation cannot acquire alias proof authority")
	}
	return newDesktopLinuxBootstrapDNSSECQuestion(policy, plan, kind, wire)
}

func NewDesktopLinuxBootstrapDNSSECAliasQuestion(policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan, wire []byte) (*DesktopLinuxBootstrapDNSSECQuestion, error) {
	return newDesktopLinuxBootstrapDNSSECQuestion(policy, plan, 5, wire)
}

func desktopLinuxDNSSECQuestion(name string, kind uint16, wire []byte) error {
	if kind == 5 {
		_, err := standardengine.ResolvedDNSSECAliasQuestionFromWire(name, wire)
		return err
	}
	_, err := standardengine.ResolvedDNSSECQuestionFromWire(name, kind, wire)
	return err
}

func newDesktopLinuxBootstrapDNSSECQuestion(policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan, kind uint16, wire []byte) (*DesktopLinuxBootstrapDNSSECQuestion, error) {
	if plan == nil || !plan.MatchesPolicy(policy) {
		return nil, errors.New("DNSSEC question omitted original loaded trust plan")
	}
	if err := desktopLinuxDNSSECQuestion(plan.Name(), kind, wire); err != nil {
		return nil, err
	}
	raw, err := policy.Canonical()
	if err != nil {
		return nil, err
	}
	routes, err := policy.ResolvedRoutes(plan.Name())
	if err != nil {
		return nil, err
	}
	var selected *standardengine.ResolvedRoute
	for _, route := range routes {
		if route.Index == plan.Index() {
			copy := route
			selected = &copy
		}
	}
	if selected == nil || selected.CurrentDNS == nil || selected.DNSSEC != plan.Mode() {
		return nil, errors.New("DNSSEC question changed original selected validation scope")
	}
	question := &DesktopLinuxBootstrapDNSSECQuestion{policy: bytes.Clone(raw), wire: bytes.Clone(wire), name: plan.Name(), planSHA: standardengine.ResolvedPolicySHA256(plan.Canonical()), index: plan.Index(), kind: kind, selected: *selected.CurrentDNS, tls: selected.DNSOverTLS}
	if _, err = question.upstream("udp", question.tls == "yes" || question.tls == "opportunistic"); err != nil {
		return nil, err
	}
	return question, nil
}

func (q *DesktopLinuxBootstrapDNSSECQuestion) upstream(network string, secure bool) (DesktopLinuxBootstrapDNSUpstream, error) {
	var upstream DesktopLinuxBootstrapDNSUpstream
	if q == nil || network != "udp" && network != "tcp" || q.tls != "no" && q.tls != "yes" && q.tls != "opportunistic" || q.tls == "yes" && !secure || q.tls == "no" && secure {
		return upstream, errors.New("DNSSEC transport changed original policy")
	}
	address, err := netip.ParseAddr(q.selected.Address)
	if err != nil {
		return upstream, err
	}
	upstream.Network, upstream.InterfaceIndex = network, int(q.selected.Index)
	port := q.selected.Port
	if secure {
		upstream.Network, upstream.TLSServerName = "tls", q.selected.ServerName
		if port == 0 {
			port = 853
		}
	} else if port == 0 {
		port = 53
	}
	upstream.Endpoint = netip.AddrPortFrom(address, port)
	return upstream, upstream.Validate()
}

func (q *DesktopLinuxBootstrapDNSSECQuestion) matches(g *DesktopLinuxBootstrapDNSGroup, upstream DesktopLinuxBootstrapDNSUpstream, wire []byte) error {
	if q == nil || g == nil || g.dnssec == nil || q.name != g.dnssec.name || q.kind != g.dnssec.kind || q.planSHA == "" || g.dnssec.plans[q.index] != q.planSHA || !bytes.Equal(q.policy, g.dnssec.policy) || !bytes.Equal(wire, q.wire) {
		return errors.New("DNSSEC query lost its original admitted group/plan")
	}
	if err := desktopLinuxDNSSECQuestion(q.name, q.kind, wire); err != nil {
		return err
	}
	network := upstream.Network
	if network == "tls" {
		network = "tcp"
	}
	want, err := q.upstream(network, upstream.Network == "tls")
	if err != nil || upstream != want {
		return errors.New("DNSSEC query changed original resolver tuple or transport")
	}
	return nil
}

func (g *DesktopLinuxBootstrapDNSGroup) ExchangeDNSSEC(ctx context.Context, upstream DesktopLinuxBootstrapDNSUpstream, q *DesktopLinuxBootstrapDNSSECQuestion, current func(context.Context) error) ([]byte, error) {
	if ctx == nil || q == nil || current == nil || q.tls == "opportunistic" {
		return nil, errors.New("DNSSEC exchange omitted its original policy guard or TLS-first owner")
	}
	if err := q.matches(g, upstream, q.wire); err != nil {
		return nil, err
	}
	if err := current(ctx); err != nil {
		return nil, err
	}
	answer, err := g.exchangeOwnedAttempt(ctx, upstream, q.wire, nil, q)
	if observed := current(ctx); observed != nil {
		return nil, errors.Join(err, observed)
	}
	if err != nil {
		return nil, err
	}
	if err = common.ValidateDNSForwardResponse(q.wire, answer); err != nil {
		return nil, err
	}
	if upstream.Network == "udp" && answer[2]&2 != 0 {
		upstream.Network = "tcp"
		answer, err = g.exchangeOwnedAttempt(ctx, upstream, q.wire, nil, q)
		if observed := current(ctx); observed != nil {
			return nil, errors.Join(err, observed)
		}
	}
	if err != nil {
		return nil, err
	}
	if err = common.ValidateDNSForwardResponse(q.wire, answer); err != nil || answer[2]&2 != 0 {
		return nil, errors.Join(err, errors.New("DNSSEC reply remained malformed or truncated"))
	}
	return answer, nil
}

func (g *DesktopLinuxBootstrapDNSGroup) ExchangeOpportunisticDNSSEC(ctx context.Context, selected *DesktopLinuxOpportunisticDNS, q *DesktopLinuxBootstrapDNSSECQuestion, current func(context.Context) error) ([]byte, error) {
	if q == nil || selected == nil || q.tls != "opportunistic" || selected.routeIndex != q.index || !strings.EqualFold(strings.TrimSuffix(selected.name, "."), q.name) || !bytes.Equal(selected.policy, q.policy) {
		return nil, errors.New("DNSSEC opportunistic query lost its exact captured policy")
	}
	answer, err := g.exchangeOpportunistic(ctx, selected, q.wire, current, q)
	if err != nil {
		return nil, err
	}
	if err = common.ValidateDNSForwardResponse(q.wire, answer); err != nil || answer[2]&2 != 0 {
		return nil, errors.Join(err, errors.New("DNSSEC opportunistic reply remained malformed or truncated"))
	}
	return answer, nil
}
