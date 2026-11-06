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
// compatibility observation. This function does not activate the continuation
// in the shipping caller by itself.
func resolveOriginalDNSSECDowngrade(ctx context.Context, policy standardengine.ResolvedPolicy, plan *standardengine.ResolvedDNSSECPlan, network string, question []byte, verdict standardengine.DNSSECVerdict, validationError error, group resolvedDNSSECExchangeGroup, current func(context.Context) error, observe func(context.Context) (standardengine.ResolvedServerState, error)) ([]byte, error) {
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
	if err != nil {
		return nil, err
	}
	// Do not turn an alias discovered by the original validator into an unsigned
	// target answer under the original owner's possibly unrelated policy.
	if alias, err := resolvedDNSSECHasAlias(verdict.Packet); err != nil {
		return nil, err
	} else if alias {
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
	var original []byte
	guard := func(check context.Context) error {
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
		// v257 resets BadOpt/RRSIGMissing and failure counters on private grace
		// expiry. PacketDoOff is sticky until explicit feature reset; therefore
		// only this observed incompatibility can authorize this continuation.
		if !state.Matches(policy, plan.Name(), plan.Index()) || !state.AllowsCurrentIncompatibility() || !state.Row.PacketDoOff {
			return errors.New("original server has no stable observed DO incompatibility")
		}
		raw, err := state.Canonical()
		if err != nil {
			return err
		}
		if original == nil {
			original = raw
		} else if !bytes.Equal(original, raw) {
			return errors.New("original server compatibility state changed during continuation")
		}
		return check.Err()
	}
	if err = guard(ctx); err != nil {
		return nil, err
	}
	typed, err := mobiletor.NewDesktopLinuxBootstrapDNSSECQuestion(policy, plan, parsed.Type, question)
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
	if alias {
		return nil, &resolvedDNSSECAliasProofRequired{Packet: bytes.Clone(answer)}
	}
	if _, err = systembootstrap.ResolvedResponseSuccess(question, answer); err != nil {
		return nil, err
	}
	answer = bytes.Clone(answer)
	answer[3] &^= 0x20 // Compatibility acceptance never grants authenticated data.
	return answer, nil
}
