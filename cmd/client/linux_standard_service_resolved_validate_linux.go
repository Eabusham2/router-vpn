//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
	"strings"
	"time"
)

// Partial children belong to the original resolver, including failed launch or
// failed callback retirement. Cleanup never loses them behind a local error.
func (r *linuxBootResolver) startDNSSECChild(ctx context.Context, root string, capture standardengine.DNSSECCapture) (*linuxDNSSECChild, error) {
	if err := desktopnetwork.LockContext(ctx, &r.dnssecMu); err != nil {
		return nil, err
	}
	defer r.dnssecMu.Unlock()
	child, err := startLinuxDNSSECChild(ctx, root, capture)
	if child != nil {
		r.dnssecChildren = append(r.dnssecChildren, child)
	}
	return child, err
}
func (r *linuxBootResolver) closeDNSSECChildren(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if err := desktopnetwork.LockContext(ctx, &r.dnssecMu); err != nil {
		return err
	}
	defer r.dnssecMu.Unlock()
	for _, child := range r.dnssecChildren {
		if err := child.Close(ctx); err != nil {
			return err
		}
	}
	r.dnssecChildren = nil
	return nil
}

type resolvedDNSSECExchangeGroup interface {
	ExchangeDNSSEC(context.Context, mobiletor.DesktopLinuxBootstrapDNSUpstream, *mobiletor.DesktopLinuxBootstrapDNSSECQuestion, func(context.Context) error) ([]byte, error)
	ExchangeOpportunisticDNSSEC(context.Context, *mobiletor.DesktopLinuxOpportunisticDNS, *mobiletor.DesktopLinuxBootstrapDNSSECQuestion, func(context.Context) error) ([]byte, error)
}

// resolvedValidatedAnswer preserves the validator's secure/insecure distinction.
// Insecure is a cryptographic result under the captured positive/NTA inputs;
// the upstream AD bit and a bogus verdict can never grant this result.
func resolvedValidatedAnswer(question []byte, v standardengine.DNSSECVerdict) ([]byte, error) {
	if len(v.Packet) < 12 || len(question) < 12 {
		return nil, errors.New("validator omitted original DNS message")
	}
	alias, err := resolvedDNSSECHasAlias(v.Packet)
	if err != nil {
		return nil, err
	}
	if alias {
		return nil, &resolvedDNSSECAliasProofRequired{append([]byte(nil), v.Packet...)}
	}
	if v.State != 1 && v.State != 2 {
		return nil, errors.New("original validator did not prove a secure or legitimately insecure answer")
	}
	if v.RCode != uint32(v.Packet[3]&15) || v.NXDomain > 1 || (v.NXDomain == 1) != (v.RCode == 3) {
		return nil, errors.New("validator verdict metadata differs from its actual packet")
	}
	answer := append([]byte(nil), v.Packet...)
	copy(answer[:2], question[:2])
	// The local validator uses CD for chain retrieval; the caller response keeps
	// the captured client's CD/RD bits and sets AD only on a secure local proof.
	answer[2] = (answer[2] &^ 1) | (question[2] & 1)
	answer[3] = (answer[3] &^ 0x30) | (question[3] & 0x10)
	if v.State == 1 {
		answer[3] |= 0x20
	}
	if err := common.ValidateDNSForwardResponse(question, answer); err != nil {
		return nil, err
	}
	if _, err := systembootstrap.ResolvedResponseSuccess(question, answer); err != nil {
		return nil, err
	}
	return answer, nil
}

func (o *linuxBootBootstrapExchange) exchangeResolvedDNSSEC(ctx context.Context, policy standardengine.ResolvedPolicy, network string, question []byte) ([]byte, error) {
	resolver := o.original.resolver
	if network != "udp" && network != "tcp" {
		return nil, errors.New("DNSSEC caller changed original transport")
	}
	name := o.resolvedName
	query, err := standardengine.ResolvedDNSSECQuestionFromWire(name, 1, question)
	if err != nil {
		query, err = standardengine.ResolvedDNSSECQuestionFromWire(name, 28, question)
	}
	if err != nil {
		return nil, err
	}
	kind := query.Type
	routes, err := policy.ResolvedRoutes(name)
	if err != nil {
		return nil, err
	}
	plans := make([]*standardengine.ResolvedDNSSECPlan, 0, len(routes))
	byIndex := map[int32]*standardengine.ResolvedDNSSECPlan{}
	for _, route := range routes {
		if route.DNSSEC == "no" {
			continue
		}
		plan, err := captureLinuxResolvedDNSSECPlan(ctx, o.operation, resolver.helper, policy, name, route.Index)
		if err != nil {
			return nil, err
		}
		if _, err = plan.ValidatorInputs(); err != nil {
			return nil, err
		}
		plans = append(plans, plan)
		byIndex[route.Index] = plan
	}
	if len(plans) == 0 {
		return nil, errors.New("DNSSEC cohort omitted validating scopes")
	}
	if err = o.Current(ctx); err != nil {
		return nil, err
	}
	group, err := o.native.BeginBootstrapDNSSECGroup(o.operation, o.lease.lock, policy, plans, kind)
	if err != nil {
		return nil, err
	}
	scopes := make([]resolvedQueryScope, 0, len(routes))
	for _, route := range routes {
		route := route
		current := func(check context.Context) error {
			return observeResolvedDNSSECPolicy(check, o.operation, resolver.helper, policy, name)
		}
		scope := resolvedQueryScope{current: current}
		if route.DNSSEC == "no" {
			if route.DNSOverTLS == "opportunistic" {
				scope.opportunistic, err = mobiletor.NewDesktopLinuxOpportunisticDNS(policy, name, route.Index, network)
			} else {
				scope.DesktopLinuxBootstrapDNSUpstream, err = resolvedRouteTransport(route, network)
			}
		} else {
			plan := byIndex[route.Index]
			scope.validate = func(work context.Context) ([]byte, error) {
				inputs, err := plan.ValidatorInputs()
				if err != nil {
					return nil, err
				}
				deadline, ok := work.Deadline()
				if !ok {
					return nil, errors.New("DNSSEC scope omitted original deadline")
				}
				captured := standardengine.DNSSECCapture{Schema: 1, Session: o.original.session, DeadlineNS: deadline.UnixNano(), PlanSHA256: standardengine.ResolvedPolicySHA256(plan.Canonical()), Name: strings.TrimSuffix(strings.ToLower(name), ".") + ".", Type: kind, Anchors: inputs.TrustAnchors, Insecure: inputs.InsecureDomains}
				sealedCapture, err := captured.Canonical()
				if err != nil {
					return nil, err
				}
				expectedCapture := standardengine.SHA256(sealedCapture)
				child, err := resolver.startDNSSECChild(work, o.service.root, captured)
				if err != nil {
					return nil, err
				}
				verdict, err := child.Validate(work, func(check context.Context, request standardengine.DNSSECQuery) ([]byte, error) {
					if request.CaptureSHA256 != expectedCapture || request.PlanSHA256 != captured.PlanSHA256 || request.Name != captured.Name || request.Type != kind {
						return nil, errors.New("validator callback changed original plan or question")
					}
					typed, err := mobiletor.NewDesktopLinuxBootstrapDNSSECQuestion(policy, plan, kind, request.Packet)
					if err != nil {
						return nil, err
					}
					guard := func(guarded context.Context) error {
						return observeResolvedDNSSECPolicy(guarded, o.operation, resolver.helper, policy, name)
					}
					if route.DNSOverTLS == "opportunistic" {
						selected, err := mobiletor.NewDesktopLinuxOpportunisticDNS(policy, name, route.Index, network)
						if err != nil {
							return nil, err
						}
						answer, err := group.ExchangeOpportunisticDNSSEC(check, selected, typed, guard)
						return resolvedDNSSECOriginalReply(answer, err)
					}
					upstream, err := resolvedRouteTransport(route, network)
					if err != nil {
						return nil, err
					}
					answer, err := group.ExchangeDNSSEC(check, upstream, typed, guard)
					return resolvedDNSSECOriginalReply(answer, err)
				})
				if err != nil {
					return nil, err
				}
				return resolvedValidatedAnswer(question, verdict)
			}
		}
		if err != nil {
			cleanup, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer end()
			return nil, errors.Join(err, group.Close(cleanup))
		}
		scopes = append(scopes, scope)
	}
	answer, err := resolveOriginalScopesOwned(ctx, group, scopes, question, resolver.closeDNSSECChildren)
	var retained *resolvedGroupRetirementError
	if errors.As(err, &retained) {
		return nil, err
	}
	// The group baseline is released here. Only now may physical Current run.
	for _, plan := range plans {
		if check := recheckLinuxResolvedDNSSECPlan(ctx, o.operation, resolver.helper, policy, plan); check != nil {
			return nil, errors.Join(err, check)
		}
	}
	if check := o.Current(ctx); check != nil {
		return nil, errors.Join(err, check)
	}
	return answer, err
}

// Alias RR validation requires its own original plan. An original-domain NTA
// must never disable validation or change routing for an unrelated target.
type resolvedDNSSECAliasProofRequired struct{ Packet []byte }

func (e *resolvedDNSSECAliasProofRequired) Error() string {
	return "original alias requires separate validated CNAME/DNAME RR proof and target policy"
}
func resolvedDNSSECHasAlias(packet []byte) (bool, error) {
	if len(packet) < 12 || len(packet) > standardengine.MaxDNSSECPacket {
		return false, errors.New("alias inspection omitted complete bounded DNS packet")
	}
	// Only locate bounded resource headers here. The common whole-response
	// validator separately proves compression targets, question and RR framing.
	skip := func(offset int) (int, error) {
		for labels := 0; labels <= 127; labels++ {
			if offset >= len(packet) {
				break
			}
			length := int(packet[offset])
			offset++
			if length == 0 {
				return offset, nil
			}
			if length&0xc0 == 0xc0 {
				if offset < len(packet) {
					return offset + 1, nil
				}
				break
			}
			if length > 63 || offset+length > len(packet) {
				break
			}
			offset += length
		}
		return 0, errors.New("alias record has malformed bounded name")
	}
	offset := 12
	for count := int(binary.BigEndian.Uint16(packet[4:6])); count > 0; count-- {
		next, err := skip(offset)
		if err != nil || next+4 > len(packet) {
			return false, errors.New("alias response omitted original question")
		}
		offset = next + 4
	}
	for count := int(binary.BigEndian.Uint16(packet[6:8])); count > 0; count-- {
		next, err := skip(offset)
		if err != nil || next+10 > len(packet) {
			return false, errors.New("alias response omitted complete record")
		}
		kind, class := binary.BigEndian.Uint16(packet[next:]), binary.BigEndian.Uint16(packet[next+2:])
		end := next + 10 + int(binary.BigEndian.Uint16(packet[next+8:]))
		if end > len(packet) {
			return false, errors.New("alias response truncated record data")
		}
		if class == 1 && (kind == 5 || kind == 39) {
			return true, nil
		}
		offset = end
	}
	return false, nil
}

func resolvedDNSSECOriginalReply(packet []byte, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	alias, err := resolvedDNSSECHasAlias(packet)
	if err != nil {
		return nil, err
	}
	if alias {
		return nil, &resolvedDNSSECAliasProofRequired{append([]byte(nil), packet...)}
	}
	return packet, nil
}
