//go:build linux

package mobiletor

import (
	"context"
	"router-vpn/internal/standardengine"
	"strings"
	"testing"
	"time"
)

func bootstrapPrivateDSFixture(t *testing.T) (standardengine.ResolvedPolicy, *standardengine.ResolvedPrivateDSDependencies) {
	t.Helper()
	p := bootstrapOpportunisticPolicy("192.0.2.53", 2053, "original.example")
	p.Manager.DNSSEC = "allow-downgrade"
	p.Manager.DNSOverTLS = "no"
	raw, _ := p.Canonical()
	sha := standardengine.ResolvedPolicySHA256(raw)
	qs, err := standardengine.ResolvedDNSSECQuestions(p, "host.node.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	var rows []standardengine.ResolvedAnchorResult
	for _, q := range qs {
		r := standardengine.ResolvedAnchorResult{PolicySHA256: sha, Name: q.Name, Type: q.Type}
		if q.Name == "." && q.Type == 43 {
			r.Present = true
			r.Flags = standardengine.ResolvedAnchorFlags
			r.Records = [][]byte{{0, 0, 43, 0, 1, 0, 0, 0, 60, 0, 5, 1, 2, 13, 2, 1}}
		}
		rows = append(rows, r)
	}
	plan, err := standardengine.BuildResolvedDNSSECPlan(p, "host.node.example", 0, rows)
	if err != nil {
		t.Fatal(err)
	}
	c, err := standardengine.NewResolvedPrivateDSDependencies(p, plan, 1, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	return p, c
}
func TestLinuxStandardBootstrapPrivateDSPurpose(t *testing.T) {
	p, c := bootstrapPrivateDSFixture(t)
	b, err := desktopLinuxBindPrivateDS(p, []*standardengine.ResolvedPrivateDSDependencies{c})
	if err != nil {
		t.Fatal(err)
	}
	if b.admissions != 6 || b.kind != 43 || b.privateDS != 1 {
		t.Fatal("dependency budget or purpose changed")
	}
	for _, name := range []string{"host.node.example", "node.example"} {
		t.Run(name, func(t *testing.T) {
			wire := bootstrapDNSSECWire(name, 43)
			q, err := NewDesktopLinuxBootstrapPrivateDSQuestion(p, c, wire)
			if err != nil {
				t.Fatal(err)
			}
			u, err := q.upstream("udp", false)
			if err != nil {
				t.Fatal(err)
			}
			if err = q.matches(&DesktopLinuxBootstrapDNSGroup{dnssec: b}, u, wire); err != nil {
				t.Fatal(err)
			}
			if u.Endpoint.Port() != 2053 || u.TLSServerName != "" {
				t.Fatal("original tuple changed")
			}
			foreign := *b
			foreign.privateDS = 2
			if q.matches(&DesktopLinuxBootstrapDNSGroup{dnssec: &foreign}, u, wire) == nil {
				t.Fatal("dependency used root owner")
			}
			ordinary := *b
			ordinary.privateDS = 0
			if q.matches(&DesktopLinuxBootstrapDNSGroup{dnssec: &ordinary}, u, wire) == nil {
				t.Fatal("dependency used ordinary owner")
			}
		})
	}
	for _, q := range []struct {
		name string
		kind uint16
	}{{"host.node.example", 1}, {"example", 43}, {".", 43}, {"node.example", 48}} {
		if _, err := NewDesktopLinuxBootstrapPrivateDSQuestion(p, c, bootstrapDNSSECWire(q.name, q.kind)); err == nil {
			t.Fatal("foreign purpose admitted", q)
		}
	}
	if _, err := desktopLinuxBindPrivateDS(p, []*standardengine.ResolvedPrivateDSDependencies{c, c}); err == nil {
		t.Fatal("duplicate original scope")
	}
}
func TestLinuxStandardBootstrapPrivateDSJoinedChain(t *testing.T) {
	for _, scenario := range []string{"original", "unjoined", "expired", "foreign-group", "foreign-authority", "reversed", "missing", "positive"} {
		t.Run(scenario, func(t *testing.T) {
			p, c := bootstrapPrivateDSFixture(t)
			b, _ := desktopLinuxBindPrivateDS(p, []*standardengine.ResolvedPrivateDSDependencies{c})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			g := &DesktopLinuxBootstrapDNSGroup{dnssec: b, original: ctx, closed: true}
			var replies []*DesktopLinuxPrivateDSReply
			for _, want := range c.Questions() {
				wire := bootstrapDNSSECWire(strings.TrimSuffix(want.Name, "."), 43)
				q, err := NewDesktopLinuxBootstrapPrivateDSQuestion(p, c, wire)
				if err != nil {
					t.Fatal(err)
				}
				answer := append([]byte(nil), wire...)
				answer[2] = 0x81
				answer[3] = 0x83
				r, err := g.privateDSReply(q, answer)
				if err != nil {
					t.Fatal(err)
				}
				replies = append(replies, r)
			}
			switch scenario {
			case "unjoined":
				g.closed = false
			case "expired":
				cancel()
			case "foreign-group":
				replies[0].group = &DesktopLinuxBootstrapDNSGroup{}
			case "foreign-authority":
				replies[0].authority = strings.Repeat("f", 64)
			case "reversed":
				replies[0], replies[1] = replies[1], replies[0]
			case "missing":
				replies = replies[:1]
			case "positive":
				replies[0].response[7] = 1
			}
			chain, err := g.SealPrivateDSReplies(c, replies)
			if scenario != "original" {
				if err == nil {
					t.Fatal("invalid chain sealed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			saved := chain.Canonical()
			copy := chain.Canonical()
			copy[0] ^= 1
			if string(saved) != string(chain.Canonical()) {
				t.Fatal("mutable chain bytes")
			}
			root := bootstrapDNSSECWire("example", 1)
			q, err := NewDesktopLinuxBootstrapPrivateDSRootQuestion(p, chain, root)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := q.upstream("udp", false)
			rb := *b
			rb.privateDS = 2
			rb.kind = 1
			rb.plans = map[int32]string{0: standardengine.ResolvedPolicySHA256(chain.canonical)}
			rb.privateChains = map[int32]*DesktopLinuxPrivateDSChain{0: chain}
			rg := &DesktopLinuxBootstrapDNSGroup{dnssec: &rb, original: ctx, closed: true}
			if err = q.matches(rg, u, root); err != nil {
				t.Fatal(err)
			}
			if q.matches(g, u, root) == nil {
				t.Fatal("root admitted by DS owner")
			}

			denial := append([]byte(nil), root...)
			denial[2], denial[3] = 0x81, 0x83
			verdict := standardengine.DNSSECVerdict{State: 1, RCode: 3, NXDomain: 1, Packet: denial}
			rg.closed = false
			if err = rg.CheckPrivateDSRootVerdict(chain, root, verdict); err != nil {
				t.Fatal("inert preview rejected", err)
			}
			if _, err = rg.CompletePrivateDSProof(chain, root, verdict); err == nil {
				t.Fatal("preview adopted before original root join")
			}
			rg.closed = true
			if _, err = rg.CompletePrivateDSProof(chain, root, verdict); err != nil {
				t.Fatal("joined proof rejected", err)
			}
			clone := *chain
			rb.privateChains[0] = &clone
			if q.matches(rg, u, root) == nil {
				t.Fatal("foreign chain token accepted")
			}
			if _, err = rg.CompletePrivateDSProof(chain, root, standardengine.DNSSECVerdict{}); err == nil {
				t.Fatal("foreign root owner completed proof")
			}
		})
	}
}
func TestLinuxStandardBootstrapPrivateDSRejectsOrdinary(t *testing.T) {
	for _, stage := range []uint8{1, 2} {
		for _, opportunistic := range []bool{false, true} {
			p, c := bootstrapPrivateDSFixture(t)
			b, _ := desktopLinuxBindPrivateDS(p, []*standardengine.ResolvedPrivateDSDependencies{c})
			b.privateDS = stage
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			g := &DesktopLinuxBootstrapDNSGroup{dnssec: b, ctx: ctx, deadline: deadline}
			wire := bootstrapDNSSECWire("host.node.example", 1)
			wire[3], wire[11] = 0, 0
			wire = wire[:len(wire)-11]
			var err error
			if opportunistic {
				p.Manager.DNSOverTLS = "opportunistic"
				selected, e := NewDesktopLinuxOpportunisticDNS(p, "host.node.example", 0, "udp")
				if e != nil {
					t.Fatal(e)
				}
				_, err = g.ExchangeOpportunistic(ctx, selected, wire, func(context.Context) error { return nil })
			} else {
				_, err = g.Exchange(ctx, DesktopLinuxBootstrapDNSUpstream{}, wire)
			}
			if err == nil || !strings.Contains(err.Error(), "private DS group requires") {
				t.Fatalf("ordinary bypass stage=%d opportunistic=%v: %v", stage, opportunistic, err)
			}
			if len(g.members) != 0 || g.admitted != 0 {
				t.Fatal("rejected purpose allocated owner")
			}
		}
	}
}

func TestLinuxStandardBootstrapPrivateDSHeldOwnerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := &DesktopLinuxBootstrapDNSGroup{original: ctx, closed: true}
	g.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- g.privateDSJoined() }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			g.mu.Unlock()
			t.Fatal("cancelled owner accepted")
		}
	case <-time.After(time.Second):
		g.mu.Unlock()
		<-done
		t.Fatal("cancelled operation waited for held cleanup mutex")
	}
	// The observation joined before releasing the original cleanup lock.
	g.mu.Unlock()
}
