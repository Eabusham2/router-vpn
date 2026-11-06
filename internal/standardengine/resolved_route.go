package standardengine

import (
	"errors"
	"strings"
)

// ResolvedRoute is one daemon DNS scope. Equal-best routes remain separate:
// flattening them would silently replace the daemon's parallel scope policy.
// This is an observation, never permission to bypass the live native owner.
type ResolvedRoute struct {
	Index                      int32
	DNS                        []ResolvedDNS
	CurrentDNS                 *ResolvedDNS
	DNSOverTLS                 string
	DNSSEC                     string
	NegativeTrustAnchors       []string
	GlobalNegativeTrustAnchors []string
	Fallback                   bool
}

// ResolvedRoutes applies resolved's longest suffix routing to an already
// qualified question. Search expansion belongs to the original caller's NSS
// policy; a single-label name must not become an unsolicited public DNS query.
// https://www.freedesktop.org/software/systemd/man/259/systemd-resolved.service.html
func (p ResolvedPolicy) ResolvedRoutes(name string) ([]ResolvedRoute, error) {
	if _, err := p.Canonical(); err != nil {
		return nil, err
	}
	if !ResolvedName(name, false) {
		return nil, errors.New("resolved route omitted exact question")
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if !strings.Contains(name, ".") {
		return nil, errors.New("single-label resolved question requires original search or multicast policy")
	}
	type candidate struct {
		scope         ResolvedScope
		labels        int
		explicitLocal bool
	}
	scopes := []ResolvedScope{p.Manager}
	scopes = append(scopes, p.Links...)
	var candidates []candidate
	best := -1
	for _, scope := range scopes {
		filtered := scope
		filtered.DNS = nil
		filtered.Domains = nil
		for _, server := range scope.DNS {
			if server.Index == scope.Index {
				filtered.DNS = append(filtered.DNS, server)
			}
		}
		for _, domain := range scope.Domains {
			if domain.Index == scope.Index {
				filtered.Domains = append(filtered.Domains, domain)
			}
		}
		if len(filtered.DNS) == 0 {
			continue
		}
		score := -1
		explicitLocal := false
		for _, domain := range filtered.Domains {
			suffix := strings.ToLower(strings.TrimSuffix(domain.Name, "."))
			labels := 0
			if suffix != "" {
				if name != suffix && !strings.HasSuffix(name, "."+suffix) {
					continue
				}
				labels = strings.Count(suffix, ".") + 1
				if suffix == "local" || strings.HasSuffix(suffix, ".local") {
					explicitLocal = true
				}
			}
			if labels > score {
				score = labels
			}
		}
		if score > best {
			best = score
		}
		candidates = append(candidates, candidate{filtered, score, explicitLocal})
	}
	localName := name == "local" || strings.HasSuffix(name, ".local")
	var routes []ResolvedRoute
	for _, candidate := range candidates {
		scope := candidate.scope
		if best >= 0 && candidate.labels != best || best < 0 && scope.Index != 0 && !scope.DefaultRoute {
			continue
		}
		if localName && !candidate.explicitLocal {
			continue
		}
		route := ResolvedRoute{Index: scope.Index, DNS: append([]ResolvedDNS(nil), scope.DNS...), DNSOverTLS: scope.DNSOverTLS, DNSSEC: scope.DNSSEC, NegativeTrustAnchors: append([]string(nil), scope.NegativeTrustAnchors...), GlobalNegativeTrustAnchors: append([]string(nil), p.Manager.NegativeTrustAnchors...)}
		if route.DNSOverTLS == "" {
			route.DNSOverTLS = p.Manager.DNSOverTLS
		}
		if route.DNSSEC == "" {
			route.DNSSEC = p.Manager.DNSSEC
		}
		if scope.CurrentDNS != nil && scope.CurrentDNS.Index == scope.Index {
			selected := *scope.CurrentDNS
			found := false
			for _, server := range scope.DNS {
				if server == selected {
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New("resolved selected server is absent from its original scope")
			}
			route.CurrentDNS = &selected
		}
		routes = append(routes, route)
	}
	if len(routes) == 0 && best < 0 && !localName && len(p.FallbackDNS) > 0 {
		// With no matching route, fallback applies when neither a global DNS
		// server nor a default-route link can handle this question. A private
		// non-default split-DNS link must not suppress the original fallback.
		// Its index is retained; an unexpected per-link fallback is not globalized.
		route := ResolvedRoute{DNSOverTLS: p.Manager.DNSOverTLS, DNSSEC: p.Manager.DNSSEC, Fallback: true, NegativeTrustAnchors: append([]string(nil), p.Manager.NegativeTrustAnchors...), GlobalNegativeTrustAnchors: append([]string(nil), p.Manager.NegativeTrustAnchors...)}
		for _, server := range p.FallbackDNS {
			if server.Index != 0 {
				return nil, errors.New("resolved fallback requires original per-link routing")
			}
			route.DNS = append(route.DNS, server)
		}
		if p.Manager.CurrentDNS != nil {
			selected := *p.Manager.CurrentDNS
			found := false
			for _, server := range route.DNS {
				if server == selected {
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New("resolved fallback current server is outside original fallback inventory")
			}
			route.CurrentDNS = &selected
		}
		routes = append(routes, route)
	}
	if len(routes) == 0 {
		return nil, errors.New("original resolved policy has no unicast route for this question")
	}
	return routes, nil
}
