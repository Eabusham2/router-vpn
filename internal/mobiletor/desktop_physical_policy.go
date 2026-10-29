package mobiletor

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"router-vpn/internal/mobilemultihop"
)

const DesktopPhysicalOutboundType = "routervpn-desktop-tor-physical"
const DesktopPhysicalOutboundTag = "routervpn-tor-physical-egress"

// PhysicalDestinations projects only literal addresses explicitly retained by
// this immutable policy. It grants no socket, account, interface or firewall
// authority. The native guardian independently captures those resources before
// accepting a tuple. Hostnames are resolved through captured DNS, and cannot
// add private exceptions merely by returning a private address.
func (p *DesktopBridgePolicy) PhysicalDestinations() ([]mobilemultihop.PhysicalEgress, error) {
	if !p.PhysicalBroker() || p.metadata.TargetOS != "linux" || p.metadata.KillSwitchPolicy == "off" || p.predecessor != nil || p.server != nil {
		return nil, errors.New("physical destinations require the captured Linux Direct socket owner")
	}
	var result []mobilemultihop.PhysicalEgress
	seen := map[mobilemultihop.PhysicalEgress]bool{}
	add := func(host string, port int, network string) error {
		address, err := netip.ParseAddr(host)
		if err != nil { // A hostname is not an independently captured IP grant.
			return nil
		}
		if port < 1 || port > 65535 || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.IsLoopback() {
			return errors.New("captured physical destination is not a canonical unicast tuple")
		}
		row := mobilemultihop.PhysicalEgress{Host: address.String(), Port: port, Network: network}
		if !seen[row] {
			seen[row] = true
			result = append(result, row)
		}
		if len(result) > 64 {
			return errors.New("captured physical destinations exceed the native bound")
		}
		return nil
	}
	// Direct Tor currently requires a numeric TCP/DoT/DoH resolver. In
	// particular Home DNS cannot acquire private authority without its Router
	// predecessor. Preserve the exact selected port; never add a fallback.
	dns := p.metadata.DNS
	if dns.Transport != "tcp" && dns.Transport != "tls" && dns.Transport != "https" {
		return nil, errors.New("physical bootstrap lost its selected TCP resolver")
	}
	if _, err := netip.ParseAddr(dns.Address); err != nil {
		return nil, errors.New("physical bootstrap has no captured literal resolver")
	}
	if err := add(dns.Address, dns.Port, "tcp"); err != nil {
		return nil, err
	}
	if p.mode == "tor" {
		return result, nil
	}
	plan, err := p.Plan()
	if err != nil {
		return nil, err
	}
	for _, bridge := range plan.Bridges {
		if bridge.Transport == "obfs4" {
			host, text, err := net.SplitHostPort(bridge.Target)
			port, portErr := strconv.Atoi(text)
			if err != nil || portErr != nil {
				return nil, errors.New("physical bridge lost its exact literal endpoint")
			}
			if err := add(host, port, "tcp"); err != nil {
				return nil, err
			}
			continue
		}
		// Dynamic bridge.Target values can be protocol placeholders. Only the
		// actual selected HTTPS/front/STUN destinations become exceptions.
		endpoint, err := url.Parse(bridge.Arguments["url"])
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
			return nil, errors.New("physical bridge lost its captured HTTPS endpoint")
		}
		port := 443
		if text := endpoint.Port(); text != "" {
			port, err = strconv.Atoi(text)
			if err != nil || port < 1 || port > 65535 {
				return nil, errors.New("physical bridge has an invalid captured HTTPS port")
			}
		}
		if err := add(endpoint.Hostname(), port, "tcp"); err != nil {
			return nil, err
		}
		for _, front := range strings.Split(bridge.Arguments["front"], ",") {
			if err := add(strings.Trim(front, "[]"), port, "tcp"); err != nil {
				return nil, err
			}
		}
		if bridge.Transport != "snowflake" {
			continue
		}
		for _, raw := range strings.Split(bridge.Arguments["ice"], ",") {
			endpoint, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || endpoint.Scheme != "stun" && endpoint.Scheme != "stuns" {
				return nil, errors.New("physical Snowflake lost its captured STUN endpoint")
			}
			text := endpoint.Opaque
			if text == "" {
				text = endpoint.Host
			}
			network, port := "udp", 3478
			if endpoint.Scheme == "stuns" {
				network, port = "tcp", 5349
			}
			if transport := endpoint.Query().Get("transport"); transport != "" {
				if transport != "udp" && transport != "tcp" {
					return nil, errors.New("physical Snowflake has an invalid STUN transport")
				}
				network = transport
			}
			host, portText, err := net.SplitHostPort(text)
			if err != nil {
				host = strings.Trim(text, "[]")
			} else {
				port, err = strconv.Atoi(portText)
				if err != nil {
					return nil, errors.New("physical Snowflake has an invalid STUN port")
				}
			}
			if err := add(host, port, network); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}
