//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/standardengine"
)

func bootstrapDNSSECPlan(t *testing.T, policy standardengine.ResolvedPolicy, name string, index int32) *standardengine.ResolvedDNSSECPlan {
	t.Helper()
	raw, err := policy.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	questions, err := standardengine.ResolvedDNSSECQuestions(policy, name, index)
	if err != nil {
		t.Fatal(err)
	}
	var rows []standardengine.ResolvedAnchorResult
	for _, q := range questions {
		rows = append(rows, standardengine.ResolvedAnchorResult{PolicySHA256: standardengine.ResolvedPolicySHA256(raw), Name: q.Name, Type: q.Type, Index: index})
	}
	plan, err := standardengine.BuildResolvedDNSSECPlan(policy, name, index, rows)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func bootstrapDNSSECWire(name string, kind uint16) []byte {
	wire := []byte{0x31, 0x62, 1, 0x10, 0, 1, 0, 0, 0, 0, 0, 1}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label != "" {
			wire = append(wire, byte(len(label)))
			wire = append(wire, label...)
		}
	}
	wire = append(wire, 0, byte(kind>>8), byte(kind), 0, 1)
	return append(wire, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0)
}
func bootstrapDNSSECFixture(t *testing.T, transport string) (standardengine.ResolvedPolicy, *standardengine.ResolvedDNSSECPlan, *DesktopLinuxBootstrapDNSGroup) {
	t.Helper()
	policy := bootstrapOpportunisticPolicy("192.0.2.53", 2053, "resolver.example")
	policy.Manager.DNSOverTLS, policy.Manager.DNSSEC = transport, "yes"
	plan := bootstrapDNSSECPlan(t, policy, "node.example", 0)
	binding, err := desktopLinuxBindDNSSEC(policy, []*standardengine.ResolvedDNSSECPlan{plan}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return policy, plan, &DesktopLinuxBootstrapDNSGroup{dnssec: binding}
}

func TestLinuxStandardBootstrapDNSSECOriginalCapability(t *testing.T) {
	for _, transport := range []string{"no", "yes", "opportunistic"} {
		t.Run(transport, func(t *testing.T) {
			policy, plan, group := bootstrapDNSSECFixture(t, transport)
			for _, name := range []string{"node.example", "example", "."} {
				for _, kind := range []uint16{43, 48} {
					wire := bootstrapDNSSECWire(name, kind)
					question, err := NewDesktopLinuxBootstrapDNSSECQuestion(policy, plan, 1, wire)
					if err != nil {
						t.Fatal(err)
					}
					upstream, err := question.upstream("udp", transport != "no")
					if err != nil || question.matches(group, upstream, wire) != nil {
						t.Fatal("original DNSSEC scope rejected", err)
					}
					if desktopLinuxBootstrapQuestion(wire) == nil {
						t.Fatal("ordinary address API admitted validation query")
					}
					wire[0] ^= 1
					if question.matches(group, upstream, wire) == nil || question.matches(group, upstream, question.wire) != nil {
						t.Fatal("caller mutation changed retained immutable query")
					}
				}
			}
		})
	}
}

func TestLinuxStandardBootstrapDNSSECRejectsForeignOwner(t *testing.T) {
	for _, fault := range []string{"port", "address", "link", "tls-identity", "transport", "ordinary-group", "changed-plan", "missing-guard", "direct-opportunistic", "sibling", "type"} {
		t.Run(fault, func(t *testing.T) {
			transport := "yes"
			if fault == "direct-opportunistic" {
				transport = "opportunistic"
			}
			policy, plan, group := bootstrapDNSSECFixture(t, transport)
			wire := bootstrapDNSSECWire("example", 48)
			if fault == "sibling" {
				wire = bootstrapDNSSECWire("sibling.example", 48)
			}
			if fault == "type" {
				wire = bootstrapDNSSECWire("node.example", 28)
			}
			question, err := NewDesktopLinuxBootstrapDNSSECQuestion(policy, plan, 1, wire)
			if fault == "sibling" || fault == "type" {
				if err == nil {
					t.Fatal("foreign child query acquired physical authority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			upstream, _ := question.upstream("udp", true)
			guardCalls := 0
			guard := func(context.Context) error { guardCalls++; return nil }
			switch fault {
			case "port":
				upstream.Endpoint = netip.AddrPortFrom(upstream.Endpoint.Addr(), 9999)
			case "address":
				upstream.Endpoint = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.54"), upstream.Endpoint.Port())
			case "link":
				upstream.InterfaceIndex++
			case "tls-identity":
				upstream.TLSServerName = "foreign.example"
			case "transport":
				upstream.Network = "udp"
			case "ordinary-group":
				group.dnssec = nil
			case "changed-plan":
				group.dnssec.plans[0] = strings.Repeat("f", 64)
			case "missing-guard":
				guard = nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err = group.ExchangeDNSSEC(ctx, upstream, question, guard); err == nil || guardCalls != 0 {
				t.Fatal("foreign authority passed pre-socket validation", err, guardCalls)
			}
		})
	}
}

func TestLinuxStandardBootstrapDNSSECCompleteCohort(t *testing.T) {
	for _, fault := range []string{"missing", "duplicate", "foreign-policy", "other-name", "wrong-type"} {
		t.Run(fault, func(t *testing.T) {
			policy, plan, _ := bootstrapDNSSECFixture(t, "no")
			plans := []*standardengine.ResolvedDNSSECPlan{plan}
			kind := uint16(1)
			switch fault {
			case "missing":
				plans = nil
			case "duplicate":
				plans = append(plans, plan)
			case "foreign-policy":
				policy.Manager.DNSOverTLS = "yes"
			case "other-name":
				plans = append(plans, bootstrapDNSSECPlan(t, policy, "sibling.example", 0))
			case "wrong-type":
				kind = 43
			}
			if _, err := desktopLinuxBindDNSSEC(policy, plans, kind); err == nil {
				t.Fatal("incomplete or foreign cohort reserved original baseline")
			}
		})
	}
}

func TestLinuxStandardBootstrapDNSSECFramedBounds(t *testing.T) {
	for _, size := range []int{16 << 10, 40000, 65535} {
		client, peer := net.Pipe()
		deadline := time.Now().Add(time.Second)
		client.SetDeadline(deadline)
		peer.SetDeadline(deadline)
		wire := bootstrapDNSSECWire("example", 48)
		answer := bytes.Repeat([]byte{0x5a}, size)
		done := make(chan error, 1)
		go func() {
			defer peer.Close()
			var header [2]byte
			if _, err := io.ReadFull(peer, header[:]); err != nil {
				done <- err
				return
			}
			question := make([]byte, binary.BigEndian.Uint16(header[:]))
			if _, err := io.ReadFull(peer, question); err != nil {
				done <- err
				return
			}
			if !bytes.Equal(question, wire) {
				done <- io.ErrUnexpectedEOF
				return
			}
			binary.BigEndian.PutUint16(header[:], uint16(len(answer)))
			_, err := peer.Write(append(header[:], answer...))
			done <- err
		}()
		actual, err := desktopLinuxBootstrapFramedExchange(client, wire, 65535)
		client.Close()
		joined := <-done
		if err != nil || joined != nil || !bytes.Equal(actual, answer) {
			t.Fatal("bounded DNSSEC frame changed", size, err, joined)
		}
	}
}

func TestLinuxStandardBootstrapDNSSECBoundedCohort(t *testing.T) {
	policy, _, _ := bootstrapDNSSECFixture(t, "no")
	selected := standardengine.ResolvedDNS{Index: 7, Address: "192.0.2.54", Port: 2053}
	policy.Links = []standardengine.ResolvedScope{{Index: 7, DNS: []standardengine.ResolvedDNS{selected}, CurrentDNS: &selected, Domains: []standardengine.ResolvedDomain{{Index: 7, Name: ".", RoutingOnly: true}}, DNSSEC: "yes", DNSOverTLS: "no"}}
	policy.Manager.DNS = append(policy.Manager.DNS, selected)
	policy.Manager.Domains = append(policy.Manager.Domains, policy.Links[0].Domains...)
	plans := []*standardengine.ResolvedDNSSECPlan{bootstrapDNSSECPlan(t, policy, "node.example", 0), bootstrapDNSSECPlan(t, policy, "node.example", 7)}
	binding, err := desktopLinuxBindDNSSEC(policy, plans, 1)
	if err != nil || binding.admissions != 6+6*int(standardengine.MaxDNSSECQueries) {
		t.Fatal("complete original child query budget changed", err)
	}
	for _, fault := range []string{"history", "active", "retained", "inventory", "descriptors"} {
		t.Run(fault, func(t *testing.T) {
			group := &DesktopLinuxBootstrapDNSGroup{dnssec: binding, initialDescriptors: 32, inventoryBytes: 16 << 10, admitted: binding.admissions - 1}
			if err := group.capacityFor(32, 4096); err != nil {
				t.Fatal("bounded final admission refused", err)
			}
			switch fault {
			case "history":
				group.admitted++
			case "active":
				group.active = desktopLinuxBootstrapGroupActive
			case "retained":
				group.members = make([]*desktopLinuxStandardBootstrap, desktopLinuxBootstrapGroupTotal)
			case "inventory":
				group.inventoryBytes = desktopLinuxBootstrapGroupInventory
			case "descriptors":
				group.initialDescriptors = 4096
			}
			if group.capacityFor(32, 4096) == nil {
				t.Fatal("DNSSEC query history widened a live resource bound")
			}
		})
	}
	ordinary := &DesktopLinuxBootstrapDNSGroup{admitted: desktopLinuxBootstrapGroupAdmissions}
	if ordinary.capacityFor(32, 4096) == nil {
		t.Fatal("ordinary address group inherited DNSSEC query authority")
	}
}
