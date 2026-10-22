package common

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ValidateExternalResponseProbe keeps the optional comparison endpoint on the
// exact imported server. Its TLS name is independent of the literal dial route.
func ValidateExternalResponseProbe(host string, probe *ExternalResponseProbe) error {
	bad := errors.New("node response probe requires verified HTTPS on the captured external server")
	if probe == nil {
		return bad
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return bad
	}
	u, err := url.Parse(probe.URL)
	if err != nil || len(probe.URL) > 2048 || strings.TrimSpace(probe.URL) != probe.URL || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Opaque != "" || u.Hostname() != host || strings.HasSuffix(u.Host, ":") {
		return bad
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return bad
		}
	}
	if probe.ServerName != "" {
		name := probe.ServerName
		if len(name) > 253 || strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") || strings.EqualFold(name, "localhost") || responseProbeLiteralName(name) {
			return bad
		}
		for _, label := range strings.Split(name, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return bad
			}
			for _, ch := range label {
				if ch < 'a' || ch > 'z' {
					if ch < 'A' || ch > 'Z' {
						if ch < '0' || ch > '9' {
							if ch != '-' {
								return bad
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func responseProbeLiteralName(name string) bool { _, err := netip.ParseAddr(name); return err == nil }
