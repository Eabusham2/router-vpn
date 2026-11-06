//go:build linux

package mobiletor

import (
	"testing"

	"router-vpn/internal/standardengine"
)

func TestLinuxStandardBootstrapDNSSECAliasCapability(t *testing.T) {
	for _, transport := range []string{"no", "yes", "opportunistic"} {
		t.Run(transport, func(t *testing.T) {
			policy, plan, addressGroup := bootstrapDNSSECFixture(t, transport)
			binding, err := desktopLinuxBindDNSSECQuestion(policy, []*standardengine.ResolvedDNSSECPlan{plan}, 5)
			if err != nil {
				t.Fatal(err)
			}
			group := &DesktopLinuxBootstrapDNSGroup{dnssec: binding}
			for _, query := range []struct {
				name string
				kind uint16
			}{{"node.example", 5}, {"node.example", 43}, {"example", 48}, {".", 43}} {
				wire := bootstrapDNSSECWire(query.name, query.kind)
				question, err := NewDesktopLinuxBootstrapDNSSECAliasQuestion(policy, plan, wire)
				if err != nil {
					t.Fatal(err)
				}
				upstream, err := question.upstream("udp", transport != "no")
				if err != nil || question.matches(group, upstream, wire) != nil {
					t.Fatal("original alias proof lost its scope", err)
				}
				if question.matches(addressGroup, upstream, wire) == nil {
					t.Fatal("alias purpose acquired address group")
				}
				if desktopLinuxBootstrapQuestion(wire) == nil {
					t.Fatal("ordinary address API admitted alias proof")
				}
				wire[0] ^= 1
				if question.matches(group, upstream, wire) == nil || question.matches(group, upstream, question.wire) != nil {
					t.Fatal("alias capture followed caller mutation")
				}
			}
		})
	}
}

func TestLinuxStandardBootstrapDNSSECAliasPurpose(t *testing.T) {
	for _, fault := range []string{"address-api", "address-group", "address-question", "target-question", "dname-owner", "ancestor-purpose"} {
		t.Run(fault, func(t *testing.T) {
			policy, plan, _ := bootstrapDNSSECFixture(t, "no")
			wire := bootstrapDNSSECWire("node.example", 5)
			switch fault {
			case "address-api":
				if _, err := NewDesktopLinuxBootstrapDNSSECQuestion(policy, plan, 5, wire); err == nil {
					t.Fatal("ordinary constructor upgraded validation purpose")
				}
				return
			case "address-group":
				if _, err := desktopLinuxBindDNSSEC(policy, []*standardengine.ResolvedDNSSECPlan{plan}, 5); err == nil {
					t.Fatal("ordinary group upgraded validation purpose")
				}
				return
			case "address-question":
				wire = bootstrapDNSSECWire("node.example", 1)
			case "target-question":
				wire = bootstrapDNSSECWire("target.other", 5)
			case "dname-owner":
				wire = bootstrapDNSSECWire("example", 39)
			case "ancestor-purpose":
				wire = bootstrapDNSSECWire("example", 48)
				question, err := NewDesktopLinuxBootstrapDNSSECQuestion(policy, plan, 1, wire)
				if err != nil {
					t.Fatal(err)
				}
				binding, err := desktopLinuxBindDNSSECQuestion(policy, []*standardengine.ResolvedDNSSECPlan{plan}, 5)
				if err != nil {
					t.Fatal(err)
				}
				upstream, err := question.upstream("udp", false)
				if err != nil {
					t.Fatal(err)
				}
				if question.matches(&DesktopLinuxBootstrapDNSGroup{dnssec: binding}, upstream, wire) == nil {
					t.Fatal("shared ancestor query crossed captured proof purpose")
				}
				return
			}
			if _, err := NewDesktopLinuxBootstrapDNSSECAliasQuestion(policy, plan, wire); err == nil {
				t.Fatal("alias proof acquired target or address authority")
			}
		})
	}
}
