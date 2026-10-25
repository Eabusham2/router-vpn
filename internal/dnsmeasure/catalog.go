// Package dnsmeasure compares DNS answers through one retained, proved native
// connection. It has no network dialer, resolver, fallback or preference store.
package dnsmeasure

import (
	"net"
	"net/netip"
)

const Samples = 3
const Workers = 4

type Endpoint struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Transport  string `json:"transport"`
	ServerName string `json:"server_name,omitempty"`
	Path       string `json:"path,omitempty"`
	Route      string `json:"route"`
	RouteLabel string `json:"route_label"`
}

var publicCatalog = [...]Endpoint{
	{ID: "cf4a", Name: "Cloudflare Primary", Address: "1.1.1.1", ServerName: "cloudflare-dns.com"},
	{ID: "cf4b", Name: "Cloudflare Secondary", Address: "1.0.0.1", ServerName: "cloudflare-dns.com"},
	{ID: "cf6a", Name: "Cloudflare IPv6 Primary", Address: "2606:4700:4700::1111", ServerName: "cloudflare-dns.com"},
	{ID: "cf6b", Name: "Cloudflare IPv6 Secondary", Address: "2606:4700:4700::1001", ServerName: "cloudflare-dns.com"},
	{ID: "g4a", Name: "Google Primary", Address: "8.8.8.8", ServerName: "dns.google"},
	{ID: "g4b", Name: "Google Secondary", Address: "8.8.4.4", ServerName: "dns.google"},
	{ID: "g6a", Name: "Google IPv6 Primary", Address: "2001:4860:4860::8888", ServerName: "dns.google"},
	{ID: "g6b", Name: "Google IPv6 Secondary", Address: "2001:4860:4860::8844", ServerName: "dns.google"},
	{ID: "q4a", Name: "Quad9 Primary", Address: "9.9.9.9", ServerName: "dns.quad9.net"},
	{ID: "q4b", Name: "Quad9 Secondary", Address: "149.112.112.112", ServerName: "dns.quad9.net"},
	{ID: "q6a", Name: "Quad9 IPv6 Primary", Address: "2620:fe::fe", ServerName: "dns.quad9.net"},
	{ID: "q6b", Name: "Quad9 IPv6 Secondary", Address: "2620:fe::9", ServerName: "dns.quad9.net"},
}

func candidates(transport, routeLabel string) []Endpoint {
	result := make([]Endpoint, len(publicCatalog))
	for index, endpoint := range publicCatalog {
		endpoint.Kind, endpoint.Transport, endpoint.Route, endpoint.RouteLabel = "public", transport, "exit", routeLabel
		endpoint.Port = 53
		if transport == "tcp" {
			endpoint.ServerName = ""
		} else if transport == "tls" {
			endpoint.Port = 853
		} else {
			endpoint.Port, endpoint.Path = 443, "/dns-query"
		}
		result[index] = endpoint
	}
	return result
}

// PublicEndpoints returns the exact comparison identities for result adoption.
// It is a copy of the closed measurement catalog, never a resolver fallback.
func PublicEndpoints(transport, routeLabel string) []Endpoint {
	if transport != "tcp" && transport != "tls" && transport != "https" {
		return nil
	}
	return candidates(transport, routeLabel)
}

// AllowedPublicAddress lets the native adapter enforce the same closed catalog
// at its dial boundary. A host cannot supply an arbitrary destination or port.
func AllowedPublicAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	ip, parse := netip.ParseAddr(host)
	if err != nil || parse != nil || ip.Zone() != "" || ip.Is4In6() || (port != "53" && port != "853" && port != "443") {
		return false
	}
	for _, endpoint := range publicCatalog {
		if ip.String() == endpoint.Address && address == net.JoinHostPort(endpoint.Address, port) {
			return true
		}
	}
	return false
}
