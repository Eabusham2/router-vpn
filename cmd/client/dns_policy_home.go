package main

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"

	"router-vpn/internal/common"
)

// Home is the selected node's AdGuard service with an explicit transport. This
// pure editor/proof normalizer does not establish node identity or reachability;
// the native compiler and connection owner still require their actual proofs.
func applyRouterHomeDNSPolicy(profile common.RouterProfile, request dnsPolicyRequest) (common.RouterProfile, error) {
	if externalDNSProfile(profile) {
		return profile, errors.New("Home DNS on an external path requires its separately captured entry")
	}
	addresses := make([]string, 0, 2)
	for i, text := range []string{profile.AdGuardIPv4, profile.AdGuardIPv6} {
		if text == "" {
			continue
		}
		address, err := netip.ParseAddr(text)
		if err != nil || !address.IsPrivate() || address.Is4In6() || address.Zone() != "" || address.String() != text || (i == 0) != address.Is4() {
			return profile, errors.New("Home DNS requires the selected node's canonical private AdGuard addresses")
		}
		addresses = append(addresses, text)
	}
	if len(addresses) == 0 {
		return profile, errors.New("Home AdGuard address is missing from this Router VPN node")
	}
	request.Host = strings.Trim(strings.TrimSpace(request.Host), "[]")
	if request.Host == "" {
		request.Host = addresses[0]
	}
	request, err := normalizeHomeDNSTransport(request)
	if err != nil {
		return profile, err
	}
	matched := false
	for _, address := range addresses {
		matched = matched || request.Host == address
	}
	if !matched {
		return profile, errors.New("selected Home DNS belongs to a different node; choose this node's saved AdGuard address")
	}
	if strings.EqualFold(strings.TrimSpace(profile.IPv6Mode), "off") && netip.MustParseAddr(request.Host).Is6() {
		return profile, errors.New("the selected IPv6 Home resolver cannot be used while IPv6 is Off")
	}
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost = "home", request.Protocol, request.Host
	profile.DNSPort, profile.DNSServerName, profile.DNSPath = request.Port, request.ServerName, request.Path
	return profile, nil
}

// Saved connection profiles can validate syntax before the private node is
// linked. Matching this address to that exact node remains mandatory at Load.
// There is no fabricated node/proof identity or inferred public resolver here.
func normalizeHomeDNSTransport(request dnsPolicyRequest) (dnsPolicyRequest, error) {
	request.Mode = "home"
	address, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(request.Host), "[]"))
	if err != nil || !address.IsPrivate() || address.Is4In6() || address.Zone() != "" {
		return request, errors.New("Home DNS requires an explicit private AdGuard IP address")
	}
	request.Host = address.String()
	request.Protocol = strings.ToLower(strings.TrimSpace(request.Protocol))
	switch request.Protocol {
	case "", "udp":
		request.Protocol = "udp"
	case "tcp":
	case "dot", "tls":
		request.Protocol = "tls"
	case "doh", "https":
		request.Protocol = "https"
	case "doh3", "h3":
		request.Protocol = "h3"
	default:
		return request, errors.New("Home DNS transport must be UDP, TCP, DoT, DoH or DoH3")
	}
	if request.Port == 0 {
		switch request.Protocol {
		case "tls":
			request.Port = 853
		case "https", "h3":
			request.Port = 443
		default:
			request.Port = 53
		}
	}
	if request.Port < 1 || request.Port > 65535 {
		return request, errors.New("Home DNS port must be between 1 and 65535")
	}
	request.ServerName, request.Path = strings.TrimSpace(request.ServerName), strings.TrimSpace(request.Path)
	if request.Protocol == "udp" || request.Protocol == "tcp" {
		request.ServerName, request.Path = "", ""
		return request, nil
	}
	name, err := normalizeEndpoint(request.ServerName)
	_, ipErr := netip.ParseAddr(request.ServerName)
	if err != nil || ipErr == nil || name != strings.ToLower(request.ServerName) || !strings.Contains(name, ".") {
		return request, errors.New("encrypted Home DNS requires its exact TLS certificate hostname")
	}
	if request.Protocol == "tls" {
		request.Path = ""
		return request, nil
	}
	if request.Path == "" {
		request.Path = "/dns-query"
	}
	path, err := url.ParseRequestURI(request.Path)
	if err != nil || len(request.Path) > 2048 || strings.IndexFunc(request.Path, func(r rune) bool { return r <= 0x20 || r == 0x7f }) >= 0 || strings.ContainsAny(request.Path, "\\#") || !strings.HasPrefix(request.Path, "/") || strings.HasPrefix(request.Path, "//") || path.IsAbs() || path.Host != "" || path.Fragment != "" || path.RawQuery != "" || path.ForceQuery {
		return request, errors.New("Home DoH requires its exact local resolver path without a host, query or fragment")
	}
	return request, nil
}
