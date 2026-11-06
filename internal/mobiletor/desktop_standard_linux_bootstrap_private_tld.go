//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"router-vpn/internal/standardengine"
)

// The auxiliary has a separate purpose and immutable cohort; no live ordinary
// group can be promoted. The caller must join its original cohort first.
func desktopLinuxBindPrivateTLD(policy standardengine.ResolvedPolicy, proofs []*standardengine.ResolvedPrivateTLDProof) (*desktopLinuxBootstrapDNSSECBinding, error) {
	if len(proofs) == 0 || len(proofs) > desktopLinuxBootstrapGroupActive || proofs[0] == nil {
		return nil, errors.New("private-TLD omitted original candidate cohort")
	}
	raw, err := policy.Canonical()
	if err != nil {
		return nil, err
	}
	b := &desktopLinuxBootstrapDNSSECBinding{privateTLD: true, policy: bytes.Clone(raw), name: proofs[0].Name(), kind: 1, plans: map[int32]string{}}
	for _, proof := range proofs {
		if proof == nil || !proof.MatchesPolicy(policy) || proof.Name() != b.name || b.plans[proof.Index()] != "" {
			return nil, errors.New("private-TLD mixed original scopes or policy")
		}
		b.plans[proof.Index()] = standardengine.ResolvedPolicySHA256(proof.Canonical())
	}
	b.admissions = 3 * desktopLinuxBootstrapDNSSECQueries * len(proofs)
	return b, nil
}
func (p *DesktopLinuxStandardProtection) BeginBootstrapPrivateTLDGroup(original context.Context, lease *os.File, policy standardengine.ResolvedPolicy, proofs []*standardengine.ResolvedPrivateTLDProof) (*DesktopLinuxBootstrapDNSGroup, error) {
	b, err := desktopLinuxBindPrivateTLD(policy, proofs)
	if err != nil {
		return nil, err
	}
	return p.beginBootstrapDNSGroup(original, lease, b)
}
func NewDesktopLinuxBootstrapPrivateTLDQuestion(policy standardengine.ResolvedPolicy, proof *standardengine.ResolvedPrivateTLDProof, wire []byte) (*DesktopLinuxBootstrapDNSSECQuestion, error) {
	if proof == nil || !proof.MatchesPolicy(policy) {
		return nil, errors.New("private-TLD changed original policy")
	}
	if _, err := proof.Question(wire); err != nil {
		return nil, err
	}
	// Routing is deliberately keyed by the ORIGINAL qualified name, not TLD.
	routes, err := policy.ResolvedRoutes(proof.Name())
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if route.Index == proof.Index() && route.CurrentDNS != nil && route.DNSSEC == "allow-downgrade" {
			raw, err := policy.Canonical()
			if err != nil {
				return nil, err
			}
			q := &DesktopLinuxBootstrapDNSSECQuestion{privateTLD: proof, policy: bytes.Clone(raw), wire: bytes.Clone(wire), name: proof.Name(), planSHA: standardengine.ResolvedPolicySHA256(proof.Canonical()), index: proof.Index(), kind: 1, selected: *route.CurrentDNS, tls: route.DNSOverTLS}
			if _, err = q.upstream("udp", q.tls == "yes" || q.tls == "opportunistic"); err != nil {
				return nil, err
			}
			return q, nil
		}
	}
	return nil, errors.New("private-TLD lost original selected scope")
}
