//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
	"strings"
	"testing"
	"time"
)

func TestResolvedDowngradeBestLevelShipping(t *testing.T) {
	for _, scenario := range []string{"address-badopt", "alias-badopt", "address-rrsig", "alias-rrsig", "tls-badopt", "tls-rrsig", "opportunistic-badopt", "opportunistic-rrsig", "lowered-badopt", "lowered-rrsig", "above-best", "wrong-tls-best", "tcp-only", "strict-dnssec", "unknown-level", "validator-error", "reset-during-query", "reset-on-join", "lowered-on-join", "reset-before-adoption", "lowered-before-adoption"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			policy := resolvedAdapterPolicy()
			policy.Manager.DNSSEC = "allow-downgrade"
			if strings.HasPrefix(scenario, "tls-") || scenario == "wrong-tls-best" {
				policy.Manager.DNSOverTLS = "yes"
			}
			if strings.HasPrefix(scenario, "opportunistic-") {
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
			cohort, err := newResolvedDowngradeCohort([]*standardengine.ResolvedDNSSECPlan{plan})
			if err != nil {
				t.Fatal(err)
			}
			question, err := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
			if err != nil {
				t.Fatal(err)
			}
			alias := strings.HasPrefix(scenario, "alias-")
			if alias {
				question, err = systembootstrap.ResolvedAliasQuery(question, "vpn.example", 5)
				if err != nil {
					t.Fatal(err)
				}
			}
			packet := resolvedScopeAnswer(question, 0)
			if alias {
				binary.BigEndian.PutUint16(packet[6:8], 1)
				target := []byte{5, 'o', 't', 'h', 'e', 'r', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
				packet = append(packet, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, byte(len(target)))
				packet = append(packet, target...)
			}
			packet[3] |= 0x20
			verdict := standardengine.DNSSECVerdict{State: 3, Packet: packet}
			raw, _ := policy.Canonical()
			state := standardengine.ResolvedServerState{PolicySHA256: standardengine.SHA256(raw), Name: "vpn.example", Selected: *policy.Manager.CurrentDNS, Row: standardengine.ResolvedServerRow{Server: "192.0.2.53:5353#original.example", Type: "system", DNSSECMode: policy.Manager.DNSSEC, VerifiedFeatureLevel: "n/a", PossibleFeatureLevel: "UDP+EDNS0+DO", PacketBadOpt: true}}
			if strings.Contains(scenario, "rrsig") {
				state.Row.PacketBadOpt = false
				state.Row.PacketRRSIGMissing = true
			}
			if policy.Manager.DNSOverTLS != "no" {
				state.Row.PossibleFeatureLevel = "TLS+EDNS0+DO"
			}
			switch scenario {
			case "lowered-badopt", "lowered-rrsig":
				state.Row.PossibleFeatureLevel = "UDP+EDNS0"
			case "above-best":
				state.Row.PossibleFeatureLevel = "TLS+EDNS0+DO"
			case "wrong-tls-best":
				state.Row.PossibleFeatureLevel = "UDP+EDNS0+DO"
			case "tcp-only":
				state.Row.PacketBadOpt = false
				state.Row.FailedTCPAttempts = 3
			case "strict-dnssec":
				state.Row.DNSSECSupported = true
			case "unknown-level":
				state.Row.PossibleFeatureLevel = "unknown"
			}
			reset := func() {
				state.Row.PacketBadOpt = false
				state.Row.PacketRRSIGMissing = false
				state.Row.DNSSECSupported = true
			}
			lower := func() { state.Row.PossibleFeatureLevel = "UDP+EDNS0" }
			transport := &resolvedDowngradeTransport{answer: packet}
			if scenario == "reset-during-query" {
				transport.during = reset
			}
			group := &resolvedDowngradeJoinedFixture{}
			childJoined := false
			group.close = func() {
				if !childJoined {
					t.Error("physical group retired before original child")
				}
				if scenario == "reset-on-join" {
					reset()
				}
				if scenario == "lowered-on-join" {
					lower()
				}
			}
			var terminalError error
			if scenario == "validator-error" {
				terminalError = errors.New("authenticated child did not complete")
			}
			observe := func(check context.Context) (standardengine.ResolvedServerState, error) { return state, check.Err() }
			current := func(check context.Context) error { return check.Err() }
			scopes := []resolvedQueryScope{{validate: func(work context.Context) ([]byte, error) {
				return resolveResolvedTerminal(work, policy, plan, "udp", question, verdict, terminalError, alias, transport, current, observe, cohort)
			}}}
			classify := systembootstrap.ResolvedResponseSuccess
			if alias {
				classify = func(q, r []byte) (bool, error) {
					step, e := systembootstrap.ResolvedAliasStep(q, r)
					return step != nil, e
				}
			}
			answer, err := resolveResolvedCompatibilityCohort(ctx, group, scopes, question, func(context.Context) error { childJoined = true; return nil }, classify, cohort)
			if scenario == "reset-before-adoption" {
				reset()
			}
			if scenario == "lowered-before-adoption" {
				lower()
			}
			if check := cohort.Recheck(ctx); check != nil {
				err = errors.Join(err, check)
				answer = nil
			}
			accepted := strings.HasPrefix(scenario, "address-") || strings.HasPrefix(scenario, "alias-") || strings.HasPrefix(scenario, "tls-") || strings.HasPrefix(scenario, "opportunistic-")
			if !accepted {
				if scenario == "lowered-badopt" || scenario == "lowered-rrsig" || scenario == "above-best" || scenario == "wrong-tls-best" || scenario == "tcp-only" || scenario == "strict-dnssec" || scenario == "unknown-level" || scenario == "validator-error" {
					if transport.calls != 0 {
						t.Fatal("refused compatibility state sent physical query")
					}
				}
				if err == nil || answer != nil {
					t.Fatal("unproved best-level continuation adopted", scenario)
				}
				return
			}
			if err != nil || len(answer) < 12 || answer[3]&0x20 != 0 || packet[3]&0x20 == 0 || transport.calls != 1 {
				t.Fatal("shipping continuation lost original result/AD ownership", err, transport.calls)
			}
			if policy.Manager.DNSOverTLS == "yes" && (transport.upstream.Network != "tls" || transport.upstream.TLSServerName != "original.example" || transport.upstream.Endpoint.Port() != 5353) {
				t.Fatal("DNSSEC compatibility weakened strict TLS", transport.upstream)
			}
			if policy.Manager.DNSOverTLS == "opportunistic" && !transport.opportunistic {
				t.Fatal("captured opportunistic policy bypassed")
			}
		})
	}
}

func TestResolvedBestLevelOriginalBinding(t *testing.T) {
	for _, scenario := range []string{"original", "foreign-policy", "foreign-name", "foreign-scope", "foreign-server", "changed-tls", "unknown-tls"} {
		t.Run(scenario, func(t *testing.T) {
			p := resolvedAdapterPolicy()
			p.Manager.DNSSEC = "allow-downgrade"
			raw, _ := p.Canonical()
			s := standardengine.ResolvedServerState{PolicySHA256: standardengine.SHA256(raw), Name: "vpn.example", Selected: *p.Manager.CurrentDNS, Row: standardengine.ResolvedServerRow{Server: "192.0.2.53:5353#original.example", Type: "system", DNSSECMode: "allow-downgrade", VerifiedFeatureLevel: "n/a", PossibleFeatureLevel: "UDP+EDNS0+DO", PacketBadOpt: true}}
			name := "vpn.example"
			index := int32(0)
			switch scenario {
			case "foreign-policy":
				p.Authority.PID++
			case "foreign-name":
				name = "foreign.example"
			case "foreign-scope":
				index = 7
			case "foreign-server":
				s.Selected.Port++
			case "changed-tls":
				p.Manager.DNSOverTLS = "yes"
			case "unknown-tls":
				p.Manager.DNSOverTLS = "unknown"
			}
			if resolvedStableCompatibility(s, p, name, index) != (scenario == "original") {
				t.Fatal("bare incompatibility escaped original route binding")
			}
		})
	}
}
