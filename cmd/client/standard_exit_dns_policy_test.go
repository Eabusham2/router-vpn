package main

import (
	"testing"

	"router-vpn/internal/common"
)

func TestStandardExitDNSNeverSubstitutesAnotherSelectedPolicy(t *testing.T) {
	for _, mode := range []string{"", "home", "fastest", "custom", "dot", "doh", "doh3"} {
		t.Run(mode, func(t *testing.T) {
			policy := common.RouterProfile{DNSMode: mode, DNSProtocol: "udp", DNSServerName: "selected.example.test"}
			if mode != "fastest" {
				// A previous benchmark is not permission to replace the selected
				// resolver when its address is absent.
				policy.FastestDNSHost = "9.9.9.9"
			}
			if _, err := selectedStandardExitDNS(policy, false); err == nil {
				t.Fatal("missing selected resolver silently adopted a public or cached resolver")
			}
		})
	}
	// Rescue is an explicit user choice with an established default resolver.
	dns, err := selectedStandardExitDNS(common.RouterProfile{DNSMode: "rescue"}, true)
	if err != nil || dns["server"] != "1.1.1.1" || dns["detour"] != "custom-exit" {
		t.Fatalf("explicit Rescue policy changed: dns=%v err=%v", dns, err)
	}
}

func TestStandardExitHomeDNSPreservesCapturedTransportAndPort(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			policy := common.RouterProfile{
				DNSMode: "home", DNSProtocol: protocol, DNSHost: "192.168.50.133", DNSPort: 5353,
				DNSServerName: "adguard.example.test", DNSPath: "/selected-query",
				AdGuardIPv4: "10.77.0.1", FastestDNSHost: "9.9.9.9",
			}
			dns, err := selectedStandardExitDNS(policy, false)
			if err != nil {
				t.Fatal(err)
			}
			if dns["type"] != protocol || dns["server"] != policy.DNSHost || dns["server_port"] != 5353 || dns["detour"] != "entry-wg" {
				t.Fatalf("Home DNS capture changed: %#v", dns)
			}
			if protocol == "tls" || protocol == "https" || protocol == "h3" {
				if tls := dns["tls"].(map[string]any); tls["enabled"] != true || tls["server_name"] != policy.DNSServerName {
					t.Fatalf("Home DNS lost its TLS identity: %#v", dns)
				}
			}
			if protocol == "https" || protocol == "h3" {
				if dns["path"] != policy.DNSPath {
					t.Fatalf("Home DNS lost its selected path: %#v", dns)
				}
			}
			if _, err := selectedStandardExitDNS(policy, true); err == nil {
				t.Fatal("captured Home DNS bypassed the Router entry requirement")
			}
		})
	}
}
