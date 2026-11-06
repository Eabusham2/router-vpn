//go:build linux

package mobiletor

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/standardengine"
)

func bootstrapOpportunisticPolicy(address string, port uint16, name string) standardengine.ResolvedPolicy {
	selected := standardengine.ResolvedDNS{Address: address, Port: port, ServerName: name}
	return standardengine.ResolvedPolicy{Schema: 1, Authority: standardengine.ResolvedAuthority{BusID: strings.Repeat("ab", 16), UniqueOwner: ":1.77", PID: 123, NamespaceDevice: 1, NamespaceInode: 2, PhysicalSHA256: strings.Repeat("cd", 32)}, LLMNRHostname: "original-host", Manager: standardengine.ResolvedScope{DNS: []standardengine.ResolvedDNS{selected}, CurrentDNS: &selected, Domains: []standardengine.ResolvedDomain{{Name: ".", RoutingOnly: true}}, DNSOverTLS: "opportunistic", DNSSEC: "no"}}
}
func TestLinuxStandardBootstrapOpportunisticCapturedPolicy(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			for _, port := range []uint16{0, 5353} {
				policy := bootstrapOpportunisticPolicy("192.0.2.53", port, "resolver.example")
				capability, err := NewDesktopLinuxOpportunisticDNS(policy, "node.example", 0, network)
				if err != nil {
					t.Fatal(err)
				}
				secure, plain, err := capability.upstreams()
				if err != nil {
					t.Fatal(err)
				}
				tlsPort, plainPort := port, port
				if port == 0 {
					tlsPort = 853
					plainPort = 53
				}
				if secure.Endpoint.Port() != tlsPort || plain.Endpoint.Port() != plainPort || plain.Network != network || secure.Network != "tls" || secure.TLSServerName != "resolver.example" || plain.TLSServerName != "" {
					t.Fatal("opportunistic scope changed captured transport/port/SNI")
				}
				if !capability.MatchesPolicy(policy) {
					t.Fatal("original policy lost")
				}
				policy.Manager.DNSOverTLS = "yes"
				if capability.MatchesPolicy(policy) {
					t.Fatal("changed original security policy adopted")
				}
			}
		})
	}
}
func TestLinuxStandardBootstrapOpportunisticRejectsForeignPolicy(t *testing.T) {
	for _, fault := range []string{"strict", "plain", "unset", "missing-current", "changed-current", "wrong-route", "bad-network", "missing-authority"} {
		t.Run(fault, func(t *testing.T) {
			p := bootstrapOpportunisticPolicy("192.0.2.53", 853, "resolver.example")
			index := int32(0)
			network := "udp"
			switch fault {
			case "strict":
				p.Manager.DNSOverTLS = "yes"
			case "plain":
				p.Manager.DNSOverTLS = "no"
			case "unset":
				p.Manager.DNSOverTLS = ""
			case "missing-current":
				p.Manager.CurrentDNS = nil
			case "changed-current":
				copy := *p.Manager.CurrentDNS
				copy.Port++
				p.Manager.CurrentDNS = &copy
			case "wrong-route":
				index = 7
			case "bad-network":
				network = "tls"
			case "missing-authority":
				p.Authority.PID = 0
			}
			if _, err := NewDesktopLinuxOpportunisticDNS(p, "node.example", index, network); err == nil {
				t.Fatal("foreign or non-opportunistic policy acquired private TLS capability")
			}
		})
	}
}
func TestLinuxStandardBootstrapOpportunisticTLSIdentityBoundary(t *testing.T) {
	for _, mode := range []string{"captured-sni", "empty-sni", "strict-rejects"} {
		t.Run(mode, func(t *testing.T) {
			name := "resolver.example"
			if mode == "empty-sni" {
				name = ""
			}
			policy := bootstrapOpportunisticPolicy("192.0.2.53", 853, name)
			capability, err := NewDesktopLinuxOpportunisticDNS(policy, "node.example", 0, "udp")
			if err != nil {
				t.Fatal(err)
			}
			config := capability.tlsConfig()
			if mode == "strict-rejects" {
				secure, _, _ := capability.upstreams()
				config, err = secure.tlsConfig()
				if err != nil {
					t.Fatal(err)
				}
				if config.InsecureSkipVerify {
					t.Fatal("strict API acquired opportunistic bypass")
				}
			}
			certificate, _ := bootstrapUpstreamCertificate(t)
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = left.SetDeadline(time.Now().Add(time.Second))
			_ = right.SetDeadline(time.Now().Add(time.Second))
			sni := make(chan string, 1)
			done := make(chan error, 1)
			go func() {
				server := tls.Server(right, &tls.Config{Certificates: []tls.Certificate{certificate}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni <- hello.ServerName; return nil, nil }})
				done <- server.HandshakeContext(ctx)
				right.Close()
			}()
			client := tls.Client(left, config)
			err = client.HandshakeContext(ctx)
			left.Close()
			serverErr := <-done
			if mode == "strict-rejects" {
				if err == nil {
					t.Fatal("strict TLS accepted independent untrusted certificate")
				}
			} else if err != nil || serverErr != nil {
				t.Fatal("captured opportunistic TLS did not negotiate", err, serverErr)
			}
			if got := <-sni; got != name {
				t.Fatal("opportunistic TLS fabricated or changed original SNI", got, name)
			}
		})
	}
}
func TestLinuxStandardBootstrapOpportunisticFailureBoundary(t *testing.T) {
	for _, err := range []error{syscall.ECONNREFUSED, io.EOF, io.ErrUnexpectedEOF, tls.RecordHeaderError{Msg: "not TLS"}} {
		if !desktopLinuxBootstrapTLSProtocolFailure(err) {
			t.Fatal("pre-DNS transport failure lost", err)
		}
	}
	for _, err := range []error{nil, context.Canceled, errors.New("original daemon replaced"), errors.New("grant expired"), errors.New("DNS response truncated")} {
		if desktopLinuxBootstrapTLSProtocolFailure(err) {
			t.Fatal("owner/cancel/DNS failure became plaintext permission", err)
		}
	}
	g := &DesktopLinuxBootstrapDNSGroup{}
	if _, err := g.ExchangeOpportunistic(context.Background(), nil, bootstrapUpstreamQuestion(), nil); err == nil {
		t.Fatal("missing original guard admitted")
	}
}
