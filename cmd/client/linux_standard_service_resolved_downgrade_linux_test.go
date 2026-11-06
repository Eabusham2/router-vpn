//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/standardengine"
	"testing"
	"time"
)

type resolvedDowngradeTransport struct {
	question, answer []byte
	calls, guards    int
	upstream         mobiletor.DesktopLinuxBootstrapDNSUpstream
	opportunistic    bool
	failure          error
	during           func()
}

func (f *resolvedDowngradeTransport) exchange(ctx context.Context, guard func(context.Context) error) ([]byte, error) {
	f.calls++
	f.guards++
	if err := guard(ctx); err != nil {
		return nil, err
	}
	if f.during != nil {
		f.during()
	}
	f.guards++
	if err := guard(ctx); err != nil {
		return nil, err
	}
	if f.failure != nil {
		return nil, f.failure
	}
	return append([]byte(nil), f.answer...), nil
}
func (f *resolvedDowngradeTransport) ExchangeDNSSEC(ctx context.Context, upstream mobiletor.DesktopLinuxBootstrapDNSUpstream, q *mobiletor.DesktopLinuxBootstrapDNSSECQuestion, guard func(context.Context) error) ([]byte, error) {
	f.upstream = upstream
	return f.exchange(ctx, guard)
}
func (f *resolvedDowngradeTransport) ExchangeOpportunisticDNSSEC(ctx context.Context, selected *mobiletor.DesktopLinuxOpportunisticDNS, q *mobiletor.DesktopLinuxBootstrapDNSSECQuestion, guard func(context.Context) error) ([]byte, error) {
	f.opportunistic = true
	return f.exchange(ctx, guard)
}
func TestResolvedDowngradeOriginalIncompatibility(t *testing.T) {
	for _, scenario := range []string{"udp", "tcp", "strict-tls", "opportunistic", "validator-error", "retained-child", "secure", "strict-dnssec", "bad-opt-only", "missing-rrsig-only", "tcp-failure-only", "changed-server", "changed-state", "lost-daemon", "cancelled", "transport-error", "changed-answer", "original-alias", "fallback-alias", "reset-do", "cancelled-before"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			policy := resolvedAdapterPolicy()
			policy.Manager.DNSSEC = "allow-downgrade"
			network := "udp"
			if scenario == "tcp" {
				network = "tcp"
			}
			if scenario == "strict-tls" {
				policy.Manager.DNSOverTLS = "yes"
			}
			if scenario == "opportunistic" {
				policy.Manager.DNSOverTLS = "opportunistic"
			}
			if scenario == "strict-dnssec" {
				policy.Manager.DNSSEC = "yes"
			}
			owner := &resolvedDNSSECOwnerFixture{policy: policy}
			plan, err := captureLinuxResolvedDNSSECPlan(ctx, ctx, owner, policy, "vpn.example", 0)
			if err != nil {
				t.Fatal(err)
			}
			question, err := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
			if err != nil {
				t.Fatal(err)
			}
			packet := resolvedScopeAnswer(question, 0)
			packet[3] |= 0x20
			verdict := standardengine.DNSSECVerdict{State: 3, Packet: packet}
			var validationError error
			if scenario == "validator-error" {
				validationError = errors.New("foreign terminal receipt")
			}
			if scenario == "retained-child" {
				validationError = &resolvedGroupRetirementError{errors.New("unjoined original worker")}
			}
			if scenario == "secure" {
				verdict.State = 1
			}
			raw, _ := policy.Canonical()
			state := standardengine.ResolvedServerState{PolicySHA256: standardengine.ResolvedPolicySHA256(raw), Name: "vpn.example", Selected: *policy.Manager.CurrentDNS, Row: standardengine.ResolvedServerRow{Server: "192.0.2.53:5353#original.example", Type: "system", DNSSECMode: "allow-downgrade", VerifiedFeatureLevel: "n/a", PossibleFeatureLevel: "UDP+EDNS0", PacketDoOff: true}}
			switch scenario {
			case "bad-opt-only":
				state.Row.PacketDoOff = false
				state.Row.PacketBadOpt = true
			case "missing-rrsig-only":
				state.Row.PacketDoOff = false
				state.Row.PacketRRSIGMissing = true
			case "tcp-failure-only":
				state.Row.PacketDoOff = false
				state.Row.FailedTCPAttempts = 3
			case "changed-server":
				state.Selected.Port++
			}
			f := &resolvedDowngradeTransport{question: question, answer: packet}
			if scenario == "changed-state" {
				f.during = func() { state.Row.FailedUDPAttempts++ }
			}
			if scenario == "cancelled" {
				f.during = stop
			}
			if scenario == "transport-error" {
				f.failure = errors.New("original grant cleanup failed")
			}
			if scenario == "changed-answer" {
				f.answer = append([]byte(nil), packet...)
				f.answer[13] ^= 1
			}
			if scenario == "original-alias" || scenario == "fallback-alias" {
				alias := append([]byte(nil), packet...)
				binary.BigEndian.PutUint16(alias[6:8], 1)
				alias = append(alias, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, 2, 0xc0, 12)
				if scenario == "original-alias" {
					verdict.Packet = alias
				} else {
					f.answer = alias
				}
			}
			if scenario == "reset-do" {
				f.during = func() { state.Row.PacketDoOff = false; state.Row.DNSSECSupported = true }
			}
			if scenario == "cancelled-before" {
				stop()
			}
			observations := 0
			observe := func(check context.Context) (standardengine.ResolvedServerState, error) {
				observations++
				return state, check.Err()
			}
			current := func(check context.Context) error {
				if scenario == "lost-daemon" {
					return errors.New("original daemon changed")
				}
				return check.Err()
			}
			answer, err := resolveOriginalDNSSECDowngrade(ctx, policy, plan, network, question, verdict, validationError, f, current, observe)
			accepted := scenario == "udp" || scenario == "tcp" || scenario == "strict-tls" || scenario == "opportunistic"
			if !accepted {
				if err == nil || answer != nil {
					t.Fatal("unproved continuation admitted", scenario)
				}
				if (scenario == "validator-error" || scenario == "retained-child" || scenario == "secure" || scenario == "strict-dnssec" || scenario == "bad-opt-only" || scenario == "missing-rrsig-only" || scenario == "tcp-failure-only" || scenario == "changed-server" || scenario == "lost-daemon" || scenario == "original-alias" || scenario == "cancelled-before") && f.calls != 0 {
					t.Fatal("refusal sent physical DNS")
				}
				if scenario == "original-alias" || scenario == "fallback-alias" {
					var alias *resolvedDNSSECAliasProofRequired
					if !errors.As(err, &alias) {
						t.Fatal("alias escaped separate proof path", err)
					}
				}
				return
			}
			if err != nil || len(answer) < 12 || answer[3]&0x20 != 0 || packet[3]&0x20 == 0 || observations != 4 || f.calls != 1 {
				t.Fatal("original guarded insecure result lost", err, observations, f.calls)
			}
			if scenario == "opportunistic" {
				if !f.opportunistic {
					t.Fatal("captured TLS policy bypassed")
				}
				return
			}
			wantNetwork := network
			if scenario == "strict-tls" {
				wantNetwork = "tls"
			}
			if f.upstream.Network != wantNetwork || f.upstream.Endpoint.String() != "192.0.2.53:5353" || f.upstream.InterfaceIndex != 0 {
				t.Fatal("selected original tuple changed", f.upstream)
			}
			if scenario == "strict-tls" && f.upstream.TLSServerName != "original.example" {
				t.Fatal("strict TLS identity lost")
			}
		})
	}
}
