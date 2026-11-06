package standardengine

import "testing"

func routePolicy() ResolvedPolicy {
	p := resolvedPolicyFixture()
	p.Manager.DNSOverTLS = "no"
	p.Manager.DNSSEC = "no"
	p.Manager.Domains = nil
	p.Manager.CurrentDNS = nil
	p.Links[0].Domains = nil
	p.Links[0].DNSOverTLS = ""
	p.Links[0].DNSSEC = ""
	return p
}
func routeDomain(p *ResolvedPolicy, index int32, name string) {
	row := ResolvedDomain{Index: index, Name: name, RoutingOnly: true}
	p.Manager.Domains = append(p.Manager.Domains, row)
	if index != 0 {
		for i := range p.Links {
			if p.Links[i].Index == index {
				p.Links[i].Domains = append(p.Links[i].Domains, row)
			}
		}
	}
}
func TestResolvedRoutesOriginalScope(t *testing.T) {
	t.Run("longest-suffix", func(t *testing.T) {
		p := routePolicy()
		routeDomain(&p, 0, "example")
		routeDomain(&p, 7, "private.example")
		routes, err := p.ResolvedRoutes("VPN.PRIVATE.EXAMPLE.")
		if err != nil || len(routes) != 1 || routes[0].Index != 7 || routes[0].CurrentDNS == nil || *routes[0].CurrentDNS != p.Links[0].DNS[1] || routes[0].DNSOverTLS != "no" || routes[0].DNSSEC != "no" {
			t.Fatalf("lost selected scope: %+v %v", routes, err)
		}
		routes[0].DNS[0].Port = 1
		if p.Links[0].DNS[0].Port == 1 {
			t.Fatal("route aliases original source")
		}
	})
	t.Run("equal-best-remain-independent", func(t *testing.T) {
		p := routePolicy()
		routeDomain(&p, 0, "example")
		routeDomain(&p, 7, "example")
		routes, err := p.ResolvedRoutes("vpn.example")
		if err != nil || len(routes) != 2 || routes[0].Index != 0 || routes[1].Index != 7 || len(routes[0].DNS) != 2 || len(routes[1].DNS) != 2 {
			t.Fatalf("flattened parallel scopes: %+v %v", routes, err)
		}
	})
	t.Run("default-route", func(t *testing.T) {
		p := routePolicy()
		p.Links[0].DefaultRoute = false
		routes, err := p.ResolvedRoutes("vpn.example")
		if err != nil || len(routes) != 1 || routes[0].Index != 0 {
			t.Fatalf("ignored default route: %+v %v", routes, err)
		}
		p.Links[0].DefaultRoute = true
		routes, err = p.ResolvedRoutes("vpn.example")
		if err != nil || len(routes) != 2 {
			t.Fatalf("lost default scope: %+v %v", routes, err)
		}
	})
	t.Run("root-route", func(t *testing.T) {
		p := routePolicy()
		routeDomain(&p, 7, ".")
		routes, err := p.ResolvedRoutes("vpn.example")
		if err != nil || len(routes) != 1 || routes[0].Index != 7 {
			t.Fatalf("ignored root route: %+v %v", routes, err)
		}
	})
	t.Run("local-not-globalized", func(t *testing.T) {
		p := routePolicy()
		routeDomain(&p, 7, ".")
		if _, err := p.ResolvedRoutes("printer.local"); err == nil {
			t.Fatal("root route leaked multicast name")
		}
		routeDomain(&p, 7, "local")
		routes, err := p.ResolvedRoutes("printer.local")
		if err != nil || len(routes) != 1 || routes[0].Index != 7 {
			t.Fatalf("lost explicit local route: %+v %v", routes, err)
		}
	})
	t.Run("fallback-without-eligible-default", func(t *testing.T) {
		p := routePolicy()
		p.Manager.DNS = nil
		p.Links = nil
		routes, err := p.ResolvedRoutes("vpn.example")
		if err != nil || len(routes) != 1 || !routes[0].Fallback {
			t.Fatalf("fallback lost: %+v %v", routes, err)
		}
		p = routePolicy()
		p.Manager.DNS = p.Manager.DNS[2:]
		p.Links[0].DefaultRoute = false
		routeDomain(&p, 7, "private.example")
		routes, err = p.ResolvedRoutes("vpn.example")
		if err != nil || len(routes) != 1 || !routes[0].Fallback {
			t.Fatalf("private-only scope suppressed captured fallback: %+v %v", routes, err)
		}
		routes, err = p.ResolvedRoutes("vpn.private.example")
		if err != nil || len(routes) != 1 || routes[0].Fallback || routes[0].Index != 7 {
			t.Fatalf("matching split query escaped its original scope: %+v %v", routes, err)
		}
	})
	t.Run("selected-not-replaced", func(t *testing.T) {
		p := routePolicy()
		routeDomain(&p, 7, "example")
		selected := *p.Links[0].CurrentDNS
		selected.Port++
		p.Links[0].CurrentDNS = &selected
		if _, err := p.ResolvedRoutes("vpn.example"); err == nil {
			t.Fatal("lost selected server was silently replaced")
		}
	})
	t.Run("short-name-needs-search", func(t *testing.T) {
		if _, err := routePolicy().ResolvedRoutes("printer"); err == nil {
			t.Fatal("single label escaped original search policy")
		}
	})
}
