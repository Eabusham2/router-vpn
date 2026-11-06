//go:build linux

package main

import (
	"context"
	"errors"
	"net/netip"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/standardengine"
	"router-vpn/internal/systembootstrap"
)

func (o *linuxBootBootstrapExchange) PreflightResolvedName(ctx context.Context, name string, ipv6 bool) ([]netip.Addr, bool, error) {
	if err := o.Current(ctx); err != nil {
		return nil, false, err
	}
	resolver := o.original.resolver
	if !resolver.policy.ResolvedStub() {
		return nil, false, errors.New("resolved preflight has no captured original stub")
	}
	if resolver.helper == nil {
		var err error
		resolver.helper, err = startLinuxResolvedHelper(o.operation, o.service.root, o.original.session, name)
		if err != nil {
			return nil, false, err
		}
	}
	_, local, err := resolver.helper.observe(ctx, name)
	if err != nil {
		return nil, false, err
	}
	if err = o.Current(ctx); err != nil {
		return nil, false, err
	}
	o.resolvedName = name
	if !local.Local {
		return nil, false, nil
	}
	var addresses []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, row := range local.Addresses {
		address, err := netip.ParseAddr(row.Address)
		if err != nil || !address.IsGlobalUnicast() || address.IsLoopback() || address.Is4In6() || address.Zone() != "" {
			return nil, true, errors.New("original local endpoint is not usable unicast")
		}
		if (ipv6 || address.Is4()) && !seen[address] {
			addresses = append(addresses, address)
			seen[address] = true
		}
	}
	if len(addresses) > 32 {
		return nil, true, errors.New("original local endpoint exceeds address bound")
	}
	return addresses, true, nil
}

// The transport primitive receives only this exact selected tuple. DNSSEC is
// deliberately not inferred from AD: local validation for validating modes is
// still required before those policies can be executed by this adapter.
func resolvedSelectedUpstreams(policy standardengine.ResolvedPolicy, name, network string) ([]resolvedQueryScope, error) {
	if network != "udp" && network != "tcp" {
		return nil, errors.New("resolved caller changed captured DNS transport")
	}
	routes, err := policy.ResolvedRoutes(name)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 || len(routes) > 257 {
		return nil, errors.New("resolved scope count exceeds original bound")
	}
	upstreams := make([]resolvedQueryScope, 0, len(routes))
	for _, route := range routes {
		var upstream resolvedQueryScope
		var err error
		if route.DNSOverTLS == "opportunistic" && route.DNSSEC == "no" {
			upstream.opportunistic, err = mobiletor.NewDesktopLinuxOpportunisticDNS(policy, name, route.Index, network)
		} else {
			upstream.DesktopLinuxBootstrapDNSUpstream, err = resolvedRouteUpstream(route, network)
		}
		if err != nil {
			return nil, err
		}
		upstreams = append(upstreams, upstream)
	}
	return upstreams, nil
}
func resolvedRouteUpstream(route standardengine.ResolvedRoute, network string) (mobiletor.DesktopLinuxBootstrapDNSUpstream, error) {
	var upstream mobiletor.DesktopLinuxBootstrapDNSUpstream
	if route.DNSSEC != "no" {
		return upstream, errors.New("original resolved DNSSEC policy requires local validation before scoped admission")
	}
	return resolvedRouteTransport(route, network)
}
func resolvedRouteTransport(route standardengine.ResolvedRoute, network string) (mobiletor.DesktopLinuxBootstrapDNSUpstream, error) {
	var upstream mobiletor.DesktopLinuxBootstrapDNSUpstream
	if route.CurrentDNS == nil {
		return upstream, errors.New("original resolved scope has no selected server; daemon selection cannot be invented")
	}
	selected := *route.CurrentDNS
	address, err := netip.ParseAddr(selected.Address)
	if err != nil {
		return upstream, err
	}
	port := selected.Port
	upstream.InterfaceIndex = int(selected.Index)
	switch route.DNSOverTLS {
	case "no":
		upstream.Network = network
		if port == 0 {
			port = 53
		}
	case "yes":
		upstream.Network = "tls"
		upstream.TLSServerName = selected.ServerName
		if port == 0 {
			port = 853
		}
	default:
		return upstream, errors.New("original resolved TLS policy requires its unsupported negotiated transport behavior")
	}
	upstream.Endpoint = netip.AddrPortFrom(address, port)
	return upstream, upstream.Validate()
}

func (o *linuxBootBootstrapExchange) exchangeResolved(ctx context.Context, network string, server netip.AddrPort, question []byte) ([]byte, error) {
	resolver := o.original.resolver
	if server != netip.MustParseAddrPort("127.0.0.53:53") || resolver.helper == nil || o.resolvedName == "" || !systembootstrap.QuestionMatchesName(question, o.resolvedName) {
		return nil, errors.New("resolved exchange escaped original source question")
	}
	policy, local, err := resolver.helper.observe(ctx, o.resolvedName)
	if err != nil {
		return nil, err
	}
	if local.Local {
		return nil, errors.New("original daemon supplied a local answer before upstream admission")
	}
	routes, err := policy.ResolvedRoutes(o.resolvedName)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if route.DNSSEC == "yes" || route.DNSSEC == "allow-downgrade" {
			return o.exchangeResolvedDNSSEC(ctx, policy, network, question)
		}
	}
	upstreams, err := resolvedSelectedUpstreams(policy, o.resolvedName, network)
	if err != nil {
		return nil, err
	}
	for i := range upstreams {
		if capability := upstreams[i].opportunistic; capability != nil {
			upstreams[i].current = func(check context.Context) error {
				if err := check.Err(); err != nil {
					return err
				}
				observed, local, err := resolver.helper.observeScoped(check, o.operation, o.resolvedName)
				if err != nil {
					return err
				}
				if local.Local || !capability.MatchesPolicy(observed) {
					return errors.New("opportunistic exchange lost original daemon policy or local decision")
				}
				return check.Err()
			}
		}
	}
	if err = o.Current(ctx); err != nil {
		return nil, err
	}
	group, err := o.native.BeginBootstrapDNSGroup(o.operation, o.lease.lock)
	if err != nil {
		return nil, err
	}
	// Current enters the same native baseline gate retained by this group.
	// It must run only before Begin and after joined Close, never in a worker.
	answer, err := resolveOriginalScopes(ctx, group, upstreams, question)
	var unjoined *resolvedGroupRetirementError
	if errors.As(err, &unjoined) {
		return nil, err
	}
	// The live owner is checked after every physical exchange, even a failed
	// one. Neither an answer nor a cached policy hash masks original-owner loss.
	_, after, observed := resolver.helper.observe(ctx, o.resolvedName)
	if observed != nil || after.Local {
		return nil, errors.Join(err, observed, errors.New("resolved owner or local-source decision changed during physical query"))
	}
	if current := o.Current(ctx); current != nil {
		return nil, errors.Join(err, current)
	}
	return answer, err
}
