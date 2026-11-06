//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
)

// resolveOriginalDNSSECDowngrade is a narrowly scoped continuation after the
// authenticated validator's successful terminal exchange and natural exit.
// Its caller must pass the original Validate error, retain all partial owners,
// and still join the complete cohort and recheck trust/physical policy before
// adopting an answer. An IPC, cancellation or retirement failure is never a
// compatibility observation. The shipping terminal dispatcher retains a cohort
// ledger so this observation
// is rechecked after joined cleanup and again at final alias adoption.
func resolveOriginalDNSSECDowngrade(ctx context.Context, policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan, network string, question []byte, verdict standardengine.DNSSECVerdict, validationError error, group resolvedDNSSECExchangeGroup, current func(context.Context) error, observe func(context.Context) (standardengine.ResolvedServerState, error)) ([]byte, error) {
	return resolveOriginalDNSSECDowngradePurpose(ctx, policy, plan, network, question, verdict, validationError, group, current, observe, false, nil)
}

func resolveOriginalDNSSECDowngradePurpose(ctx context.Context, policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan, network string, question []byte, verdict standardengine.DNSSECVerdict, validationError error, group resolvedDNSSECExchangeGroup, current func(context.Context) error, observe func(context.Context) (standardengine.ResolvedServerState, error), aliasProof bool, retain func(func(context.Context) error) error) ([]byte, error) {
	if validationError != nil {
		return nil, validationError
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, bounded := ctx.Deadline(); !bounded || verdict.State != 3 || plan == nil || plan.Mode() != "allow-downgrade" || !plan.MatchesPolicy(policy) || group == nil || current == nil || observe == nil {
		return nil, errors.New("downgrade omitted original bounded terminal verdict and authority")
	}
	if network != "udp" && network != "tcp" {
		return nil, errors.New("downgrade changed original address transport")
	}
	parsed, err := standardengine.ResolvedDNSSECQuestionFromWire(plan.Name(), 1, question)
	if err != nil {
		parsed, err = standardengine.ResolvedDNSSECQuestionFromWire(plan.Name(), 28, question)
	}
	if aliasProof {
		parsed, err = standardengine.ResolvedDNSSECAliasQuestionFromWire(plan.Name(), question)
	}
	if err != nil {
		return nil, err
	}
	// Do not turn an alias discovered by the original validator into an unsigned
	// target answer under the original owner's possibly unrelated policy.
	if alias, err := resolvedDNSSECHasAlias(verdict.Packet); err != nil {
		return nil, err
	} else if alias && !aliasProof {
		return nil, &resolvedDNSSECAliasProofRequired{Packet: bytes.Clone(verdict.Packet)}
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
	if selected == nil || selected.DNSSEC != "allow-downgrade" || selected.CurrentDNS == nil {
		return nil, errors.New("downgrade lost original selected validating route")
	}
	// Retained guards keep only the original question identity and state digest,
	// not the full anchor plan from every prior alias cohort.
	name, index := plan.Name(), plan.Index()
	var originalDigest string
	var guard func(context.Context) error
	guard = func(check context.Context) error {
		if err := check.Err(); err != nil {
			return err
		}
		if err := current(check); err != nil {
			return err
		}
		state, err := observe(check)
		if err != nil {
			return err
		}
		if !resolvedStableCompatibility(state, policy, name, index) {
			return errors.New("original server has no stable observed incompatibility")
		}
		raw, err := state.Canonical()
		if err != nil {
			return err
		}
		if originalDigest == "" {
			originalDigest = standardengine.SHA256(raw)
			if retain != nil {
				if err := retain(guard); err != nil {
					return err
				}
			}
		} else if originalDigest != standardengine.SHA256(raw) {
			return errors.New("original server compatibility state changed during continuation")
		}
		return check.Err()
	}
	if err = guard(ctx); err != nil {
		return nil, err
	}
	var typed *mobiletor.DesktopLinuxBootstrapDNSSECQuestion
	if aliasProof {
		typed, err = mobiletor.NewDesktopLinuxBootstrapDNSSECAliasQuestion(policy, plan, question)
	} else {
		typed, err = mobiletor.NewDesktopLinuxBootstrapDNSSECQuestion(policy, plan, parsed.Type, question)
	}
	if err != nil {
		return nil, err
	}
	var answer []byte
	if selected.DNSOverTLS == "opportunistic" {
		capability, e := mobiletor.NewDesktopLinuxOpportunisticDNS(policy, plan.Name(), plan.Index(), network)
		if e != nil {
			return nil, e
		}
		answer, err = group.ExchangeOpportunisticDNSSEC(ctx, capability, typed, guard)
	} else {
		upstream, e := resolvedRouteTransport(*selected, network)
		if e != nil {
			return nil, e
		}
		answer, err = group.ExchangeDNSSEC(ctx, upstream, typed, guard)
	}
	if err != nil {
		return nil, err
	}
	if err = guard(ctx); err != nil {
		return nil, err
	}
	if err = common.ValidateDNSForwardResponse(question, answer); err != nil {
		return nil, err
	}
	alias, err := resolvedDNSSECHasAlias(answer)
	if err != nil {
		return nil, err
	}
	if alias && !aliasProof {
		return nil, &resolvedDNSSECAliasProofRequired{Packet: bytes.Clone(answer)}
	}
	if aliasProof {
		step, check := systembootstrap.ResolvedAliasStep(question, answer)
		if check != nil || step == nil {
			return nil, errors.Join(check, errors.New("compatibility response omitted exact original alias proof"))
		}
	}
	if _, err = systembootstrap.ResolvedResponseSuccess(question, answer); err != nil {
		return nil, err
	}
	answer = bytes.Clone(answer)
	answer[3] &^= 0x20 // Compatibility acceptance never grants authenticated data.
	return answer, nil
}

// The monitor's current support flag alone cannot predict private grace expiry.
// v257 resolved-dns-server.c:425–446 consults that timer only below the policy's
// best level. At exactly best, other feature-selection branches preserve BadOpt
// and RRSIGMissing (counter reset:236–255,580–588), so support remains false.
// PacketDoOff retains its independent sticky-until-reset admission. Every use
// still requires the original whole-state digest before and after owned IO and
// again after joined cleanup and at adoption; this is not a general State3 rule.
func resolvedStableCompatibility(state standardengine.ResolvedServerState, policy standardengine.ResolvedPolicy, name string, index int32) bool {
	if !state.Matches(policy, name, index) || !state.AllowsCurrentIncompatibility() {
		return false
	}
	routes, err := policy.ResolvedRoutes(name)
	if err != nil {
		return false
	}
	dnsOverTLS := ""
	for _, route := range routes {
		if route.Index == index && route.CurrentDNS != nil && *route.CurrentDNS == state.Selected && route.DNSSEC == "allow-downgrade" {
			dnsOverTLS = route.DNSOverTLS
		}
	}
	var best string
	switch dnsOverTLS {
	case "no":
		best = "UDP+EDNS0+DO"
	case "yes", "opportunistic":
		best = "TLS+EDNS0+DO"
	default:
		return false
	}
	if state.Row.PacketDoOff {
		return true
	}
	return (state.Row.PacketBadOpt || state.Row.PacketRRSIGMissing) && state.Row.PossibleFeatureLevel == best
}
