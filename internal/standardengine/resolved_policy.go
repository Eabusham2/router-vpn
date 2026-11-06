package standardengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
)

// ResolvedPolicy is an observation of one original daemon, not a capability to
// adopt a daemon, open a socket, or change DNS. The native owner must remain live
// and check its retained descriptors before and after every use of this data.
// Arrays retain the daemon's order: sorting DNS or search domains changes policy.
type ResolvedPolicy struct {
	Schema        int               `json:"schema"`
	Authority     ResolvedAuthority `json:"authority"`
	LLMNRHostname string            `json:"llmnr_hostname"`
	Manager       ResolvedScope     `json:"manager"`
	FallbackDNS   []ResolvedDNS     `json:"fallback_dns"`
	Links         []ResolvedScope   `json:"links"`
}

type ResolvedAuthority struct {
	BusID           string `json:"bus_id"`
	UniqueOwner     string `json:"unique_owner"`
	PID             uint32 `json:"pid"`
	NamespaceDevice uint64 `json:"namespace_device"`
	NamespaceInode  uint64 `json:"namespace_inode"`
	PhysicalSHA256  string `json:"physical_sha256"`
}

type ResolvedDNS struct {
	Index      int32  `json:"index"`
	Address    string `json:"address"`
	Port       uint16 `json:"port"`
	ServerName string `json:"server_name"`
}

type ResolvedDomain struct {
	Index       int32  `json:"index"`
	Name        string `json:"name"`
	RoutingOnly bool   `json:"routing_only"`
}

type ResolvedScope struct {
	CurrentDNS           *ResolvedDNS     `json:"current_dns"`
	Index                int32            `json:"index"`
	DNS                  []ResolvedDNS    `json:"dns"`
	Domains              []ResolvedDomain `json:"domains"`
	DefaultRoute         bool             `json:"default_route"`
	LLMNR                string           `json:"llmnr"`
	MulticastDNS         string           `json:"multicast_dns"`
	DNSOverTLS           string           `json:"dns_over_tls"`
	DNSSEC               string           `json:"dnssec"`
	NegativeTrustAnchors []string         `json:"negative_trust_anchors"`
}

const MaxResolvedPolicy = 256 << 10

// ResolvedName accepts bounded ASCII DNS names without rewriting their original
// spelling. IDNA conversion belongs to the original resolver, not this wire gate.
func ResolvedName(name string, root bool) bool {
	if root && name == "." {
		return true
	}
	if len(name) == 0 || len(name) > 254 {
		return false
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func resolvedChoice(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func resolvedDNSValid(servers []ResolvedDNS) bool {
	if len(servers) > 64 {
		return false
	}
	for _, server := range servers {
		ip, err := netip.ParseAddr(server.Address)
		if server.Index < 0 || err != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != server.Address || server.ServerName != "" && !ResolvedName(server.ServerName, false) {
			return false
		}
	}
	return true
}

func (s ResolvedScope) valid() bool {
	if s.Index < 0 || !resolvedDNSValid(s.DNS) || len(s.Domains) > 128 || len(s.NegativeTrustAnchors) > 128 {
		return false
	}
	if !resolvedChoice(s.LLMNR, "", "yes", "no", "resolve") || !resolvedChoice(s.MulticastDNS, "", "yes", "no", "resolve") || !resolvedChoice(s.DNSOverTLS, "", "yes", "no", "opportunistic") || !resolvedChoice(s.DNSSEC, "", "yes", "no", "allow-downgrade") {
		return false
	}
	if s.CurrentDNS != nil && !resolvedDNSValid([]ResolvedDNS{*s.CurrentDNS}) {
		return false
	}
	for _, server := range s.DNS {
		if s.Index != 0 && server.Index != s.Index {
			return false
		}
	}
	if s.CurrentDNS != nil && s.Index != 0 && s.CurrentDNS.Index != s.Index {
		return false
	}
	for _, domain := range s.Domains {
		if domain.Index < 0 || s.Index != 0 && domain.Index != s.Index {
			return false
		}
		if !ResolvedName(domain.Name, true) || domain.Name == "." && !domain.RoutingOnly {
			return false
		}
	}
	for _, name := range s.NegativeTrustAnchors {
		if !ResolvedName(name, false) {
			return false
		}
	}
	return true
}

func (p ResolvedPolicy) Canonical() ([]byte, error) {
	bad := errors.New("resolved policy has no complete original bounded observation")
	a := p.Authority
	if p.Schema != 1 || !resolvedDigest(a.BusID, 16) || a.PID == 0 || a.NamespaceInode == 0 || !resolvedDigest(a.PhysicalSHA256, 32) || !resolvedUniqueOwner(a.UniqueOwner) || !ResolvedName(p.LLMNRHostname, false) || p.Manager.Index != 0 || !p.Manager.valid() || !resolvedDNSValid(p.FallbackDNS) || len(p.Links) > 256 {
		return nil, bad
	}
	seen := map[int32]bool{}
	for _, link := range p.Links {
		if link.Index == 0 || seen[link.Index] || !link.valid() {
			return nil, bad
		}
		seen[link.Index] = true
	}
	for _, row := range append(append([]ResolvedDNS(nil), p.Manager.DNS...), p.FallbackDNS...) {
		if row.Index != 0 && !seen[row.Index] {
			return nil, bad
		}
	}
	if p.Manager.CurrentDNS != nil && p.Manager.CurrentDNS.Index != 0 && !seen[p.Manager.CurrentDNS.Index] {
		return nil, bad
	}
	for _, row := range p.Manager.Domains {
		if row.Index != 0 && !seen[row.Index] {
			return nil, bad
		}
	}

	for _, link := range p.Links {
		var servers []ResolvedDNS
		var domains []ResolvedDomain
		for _, row := range p.Manager.DNS {
			if row.Index == link.Index {
				servers = append(servers, row)
			}
		}
		for _, row := range p.Manager.Domains {
			if row.Index == link.Index {
				domains = append(domains, row)
			}
		}
		if !reflect.DeepEqual(servers, append([]ResolvedDNS(nil), link.DNS...)) || !reflect.DeepEqual(domains, append([]ResolvedDomain(nil), link.Domains...)) {
			return nil, bad
		}
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxResolvedPolicy {
		return nil, bad
	}
	return raw, nil
}

// ResolvedPolicySHA256 identifies bytes; the retained native owner authenticates them.
func ResolvedPolicySHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func resolvedDigest(value string, size int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == size && hex.EncodeToString(raw) == value && !bytes.Equal(raw, make([]byte, size))
}

func resolvedUniqueOwner(value string) bool {
	if len(value) < 4 || len(value) > 255 || value[0] != ':' {
		return false
	}
	parts := strings.Split(value[1:], ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}
