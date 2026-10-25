package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func externalDNSProfile(p common.RouterProfile) bool {
	return p.External != nil || strings.EqualFold(strings.TrimSpace(p.NodeKind), "external")
}

// Call with a.mu held. The selected node and its saved entry are captured
// together; an editor never obtains an entry from a later UI selection.
func (a *app) dnsPolicySelectionLocked() (common.RouterProfile, common.RouterProfile, bool) {
	p, ok := a.profileByIDLocked(a.profiles.SelectedID)
	p = cloneRouterProfile(p)
	var entry common.RouterProfile
	if externalDNSProfile(p) && p.MultihopEnabled {
		entry, _ = a.profileByIDLocked(p.MultihopEntryID)
		entry = cloneRouterProfile(entry)
	}
	return p, entry, ok
}

func dnsPolicySelectionToken(p, entry common.RouterProfile) string {
	// Fastest is part of the policy's input. Include exact evidence so a
	// benchmark finishing while an editor is open cannot change its winner.
	// Float bits also make invalid historical samples deterministic without
	// allowing NaN/Infinity to break JSON token generation.
	type sample struct {
		Name, Address, Family string
		Latency               uint64
		Working               bool
	}
	identity := struct {
		Profile, Entry, Fastest string
		Latency                 uint64
		Results                 []sample
	}{Profile: profileStartupSettingsToken(p), Entry: profileStartupSettingsToken(entry), Fastest: p.FastestDNSHost, Latency: math.Float64bits(p.FastestDNSLatencyMs)}
	for _, result := range p.DNSResults {
		identity.Results = append(identity.Results, sample{result.Name, result.Address, result.Family, math.Float64bits(result.LatencyMs), result.Working})
	}
	encoded, _ := json.Marshal(identity)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func copyDNSPolicy(target *common.RouterProfile, source common.RouterProfile) {
	target.DNSMode, target.DNSProtocol, target.DNSHost = source.DNSMode, source.DNSProtocol, source.DNSHost
	target.DNSPort, target.DNSServerName, target.DNSPath = source.DNSPort, source.DNSServerName, source.DNSPath
}

func applyCapturedDNSPolicy(profile, entry common.RouterProfile, request dnsPolicyRequest) (common.RouterProfile, error) {
	if !externalDNSProfile(profile) {
		return applyDNSPolicyToProfile(profile, request)
	}
	if profile.NodeKind != "external" || profile.External == nil {
		return profile, errors.New("DNS settings require the complete captured external node")
	}
	updated := cloneRouterProfile(profile)
	mode := strings.ToLower(strings.TrimSpace(request.Mode))
	if mode != "rescue" && mode != "fastest" {
		if address, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(request.Host), "[]")); err == nil && (address.Is4In6() || address.Zone() != "") {
			return profile, errors.New("external DNS requires a canonical IPv4 or IPv6 resolver address without a mapped family or zone")
		}
	}
	var err error
	switch mode {
	case "fastest":
		// Historical DNSResults/FastestDNSHost carry no native path, transport
		// or freshness. In particular, a TLS timing cannot authorize UDP/53.
		return profile, errors.New("external Fastest needs a current native DNS result with its exact transport and path; use DNS Retest and explicitly select a measured resolver")
	case "home":
		// Home remains a saved intent for a direct ordinary external node.
		// The shared idle validator permits only an empty/private address;
		// connection still requires the exact authenticated Router entry.
		updated.DNSMode = "home"
		updated.DNSProtocol = strings.ToLower(strings.TrimSpace(request.Protocol))
		updated.DNSHost, updated.DNSServerName, updated.DNSPath = strings.TrimSpace(request.Host), strings.TrimSpace(request.ServerName), strings.TrimSpace(request.Path)
		updated.DNSPort = request.Port
		if updated.DNSHost == "" && entry.ID != "" {
			updated.DNSHost = strings.TrimSpace(entry.AdGuardIPv4)
			if updated.DNSHost == "" {
				updated.DNSHost = strings.TrimSpace(entry.AdGuardIPv6)
			}
		}
		switch updated.DNSProtocol {
		case "", "udp":
			updated.DNSProtocol = "udp"
		case "tcp":
		case "dot", "tls":
			updated.DNSProtocol = "tls"
		case "doh", "https":
			updated.DNSProtocol = "https"
		case "doh3", "h3":
			updated.DNSProtocol = "h3"
		default:
			return profile, errors.New("Home DNS transport must be UDP, TCP, DoT, DoH or DoH3")
		}
		if updated.DNSPort == 0 {
			switch updated.DNSProtocol {
			case "tls":
				updated.DNSPort = 853
			case "https", "h3":
				updated.DNSPort = 443
			default:
				updated.DNSPort = 53
			}
		}
		if updated.DNSServerName == "" && updated.DNSProtocol != "udp" && updated.DNSProtocol != "tcp" {
			updated.DNSServerName = inferDNSServerName(updated.DNSHost)
		}
	case "rescue":
		// Match the explicit preset used by the shared external compiler.
		updated.DNSMode, updated.DNSProtocol, updated.DNSHost, updated.DNSPort = "rescue", "https", "1.1.1.1", 443
		updated.DNSServerName, updated.DNSPath = "cloudflare-dns.com", "/dns-query"
	default:
		updated, err = applyDNSPolicyToProfile(updated, request)
		if err != nil {
			return profile, err
		}
	}
	// Remove only fields the selected transport does not use. What the editor
	// displays and persists must describe the actual runtime DNS transport.
	if updated.DNSProtocol == "udp" || updated.DNSProtocol == "tcp" {
		updated.DNSServerName, updated.DNSPath = "", ""
	} else if updated.DNSProtocol == "tls" {
		updated.DNSPath = ""
	} else if updated.DNSProtocol == "https" || updated.DNSProtocol == "h3" {
		if updated.DNSPath == "" {
			updated.DNSPath = "/dns-query"
		}
	}
	if err := validateDesktopExternalDNSPolicy(updated, entry); err != nil {
		return profile, err
	}
	return updated, nil
}

func validateDesktopExternalDNSPolicy(profile, entry common.RouterProfile) error {
	if profile.NodeKind != "external" || profile.External == nil {
		return errors.New("external DNS has no captured private protocol")
	}
	if profile.External.Protocol == "tor-bridge" {
		// Tor has its own dynamic exit proof adapter. Use its real transport
		// parser, never pretend this node is an ordinary fixed-public-IP exit.
		if profile.MultihopEnabled || entry.ID != "" {
			return errors.New("Tor bridge DNS requires its supported direct path")
		}
		if _, err := selectedTorBridgeDNS(profile); err != nil {
			return err
		}
		address, err := netip.ParseAddr(profile.DNSHost)
		if err != nil || address.Is4In6() || address.Zone() != "" || !address.IsGlobalUnicast() || address.IsLoopback() || address.String() != profile.DNSHost {
			return errors.New("Tor DNS requires an explicit literal resolver address through its circuit")
		}
		if profile.DNSProtocol == "https" {
			path, err := url.ParseRequestURI(profile.DNSPath)
			if err != nil || len(profile.DNSPath) > 2048 || strings.ContainsAny(profile.DNSPath, "\x00\r\n\\") || !strings.HasPrefix(profile.DNSPath, "/") || strings.HasPrefix(profile.DNSPath, "//") || path.IsAbs() || path.Host != "" || path.Fragment != "" || path.RawQuery != "" || path.ForceQuery {
				return errors.New("Tor DoH requires its exact resolver path without a host, query or fragment")
			}
		}
		return nil
	}
	// Match entry selection in the genuine desktop launch path, but keep these
	// derived runtime fields out of the saved external node and its credentials.
	if profile.MultihopEnabled {
		if entry.ID == "" || profile.MultihopEntryID != entry.ID || profile.MultihopExitID != profile.ID || entry.ID == profile.ID {
			return errors.New("external DNS requires the exact linked entry from the saved path")
		}
		if externalDNSProfile(entry) {
			if entry.NodeKind != "external" || entry.External == nil {
				return errors.New("external DNS entry has no captured protocol")
			}
			profile.MultihopEntryMode = entry.External.Protocol
		} else {
			mode, err := desktopExternalEntryMode(profile, entry, "", "")
			if err != nil {
				return err
			}
			profile.MultihopEntryMode = mode
		}
	} else if entry.ID != "" {
		return errors.New("direct external DNS cannot acquire an unrelated entry")
	}
	type profileWire common.RouterProfile
	raw, err := json.Marshal(profileWire(profile))
	if err != nil {
		return errors.New("external DNS profile contains invalid policy or measurement values")
	}
	var captured map[string]any
	if json.Unmarshal(raw, &captured) != nil {
		return errors.New("external DNS capture is invalid")
	}
	captured["multihop_exit_mode"] = profile.External.Protocol
	raw, err = json.Marshal(captured)
	if err != nil {
		return err
	}
	entryJSON := ""
	if entry.ID != "" {
		encoded, err := json.Marshal(profileWire(entry))
		if err != nil {
			return errors.New("external DNS entry contains invalid saved values")
		}
		entryJSON = string(encoded)
	}
	return mobilemultihop.ValidateExternalDNS(string(raw), entryJSON)
}
