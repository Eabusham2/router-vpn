//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"
)

func bootstrapUpstreamQuestion() []byte {
	return []byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 'n', 'o', 'd', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
}
func TestLinuxStandardBootstrapUpstreamPreservesExactTransport(t *testing.T) {
	route := desktopLinuxBootstrapRoute{Interface: net.Interface{Name: "eth0", Index: 2}, Address: netip.MustParseAddr("192.0.2.2")}
	local := netip.MustParseAddrPort("192.0.2.2:40000")
	for _, network := range []string{"udp", "tcp", "tls"} {
		for _, port := range []uint16{53, 853, 5353} {
			t.Run(network+"/"+netip.AddrPortFrom(netip.MustParseAddr("192.0.2.53"), port).String(), func(t *testing.T) {
				upstream := DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.53"), port), Network: network, InterfaceIndex: 2}
				if network == "tls" {
					upstream.TLSServerName = "resolver.example"
				}
				wire, err := desktopLinuxBootstrapRuleWireForUpstream(route, local, upstream, 0x92345678, "rvb_0123456789abcdef01")
				if err != nil {
					t.Fatal(err)
				}
				attrs, _ := desktopLinuxBootstrapAttributeMap(wire, 0)
				shape, err := desktopLinuxBootstrapExpressionShape(attrs[4])
				if err != nil {
					t.Fatal(err)
				}
				protocol := byte(17)
				if network != "udp" {
					protocol = 6
				}
				ports := make([]byte, 4)
				binary.BigEndian.PutUint16(ports, 40000)
				binary.BigEndian.PutUint16(ports[2:], port)
				foundProto, foundPorts, lookups := false, false, 0
				for _, item := range shape {
					row := item.([]any)
					name := row[0].(string)
					fields := row[1].(map[uint16][]byte)
					if name == "cmp" {
						foundProto = foundProto || bytes.Equal(fields[3], []byte{protocol})
						foundPorts = foundPorts || bytes.Equal(fields[3], ports)
					}
					if name == "lookup" {
						lookups++
					}
				}
				if !foundProto || !foundPorts || lookups != 1 {
					t.Fatal("captured resolver transport lost exact kernel tuple/expiry")
				}
				changed := upstream
				changed.InterfaceIndex = 3
				if _, err := desktopLinuxBootstrapRuleWireForUpstream(route, local, changed, 0x92345678, "rvb_0123456789abcdef01"); err == nil {
					t.Fatal("another physical link acquired selected resolver authority")
				}
				if port != 53 {
					if _, err := desktopLinuxBootstrapRuleWire(route, local, upstream.Endpoint, 0x92345678, upstream.socketNetwork(), "rvb_0123456789abcdef01"); err == nil {
						t.Fatal("legacy DNS53 rule silently broadened")
					}
				}
			})
		}
	}
}
func TestLinuxStandardBootstrapUpstreamRejectsDowngrades(t *testing.T) {
	original := DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.MustParseAddrPort("192.0.2.53:853"), Network: "tls", TLSServerName: "resolver.example", InterfaceIndex: 2}
	for _, fault := range []string{"plain-with-name", "unknown-transport", "zero-port", "negative-link", "huge-link", "loopback", "mapped", "multicast", "zone", "name-port", "name-path", "name-wildcard", "name-space", "name-empty-label"} {
		t.Run(fault, func(t *testing.T) {
			u := original
			switch fault {
			case "plain-with-name":
				u.Network = "udp"
			case "unknown-transport":
				u.Network = "https"
			case "zero-port":
				u.Endpoint = netip.AddrPortFrom(u.Endpoint.Addr(), 0)
			case "negative-link":
				u.InterfaceIndex = -1
			case "huge-link":
				tooLarge := int64(1) << 31
				u.InterfaceIndex = int(tooLarge)
			case "loopback":
				u.Endpoint = netip.MustParseAddrPort("127.0.0.1:853")
			case "mapped":
				u.Endpoint = netip.MustParseAddrPort("[::ffff:192.0.2.53]:853")
			case "multicast":
				u.Endpoint = netip.MustParseAddrPort("224.0.0.1:853")
			case "zone":
				u.Endpoint = netip.MustParseAddrPort("[2001:db8::53%eth0]:853")
			case "name-port":
				u.TLSServerName = "resolver.example:853"
			case "name-path":
				u.TLSServerName = "resolver.example/path"
			case "name-wildcard":
				u.TLSServerName = "*.example"
			case "name-space":
				u.TLSServerName = " resolver.example"
			case "name-empty-label":
				u.TLSServerName = "resolver..example"
			}
			if err := u.Validate(); err == nil {
				t.Fatal("changed captured security scope accepted")
			}
			p := &DesktopLinuxStandardProtection{}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := p.BootstrapDNSExchangeUpstream(ctx, ctx, nil, u, bootstrapUpstreamQuestion()); err == nil || p.bootstrap != nil {
				t.Fatal("invalid scope reached retained socket", err)
			}
		})
	}
}
func bootstrapUpstreamCertificate(t *testing.T, addresses ...net.IP) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "independent bootstrap fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"resolver.example"}, IPAddresses: append([]net.IP{net.ParseIP("192.0.2.53")}, addresses...), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return tls.Certificate{Certificate: [][]byte{der, rootDER}, PrivateKey: key}, pool
}
func TestLinuxStandardBootstrapUpstreamTLSProvesIdentityAndFraming(t *testing.T) {
	certificate, roots := bootstrapUpstreamCertificate(t)
	for _, mode := range []string{"captured-sni", "captured-ip-no-sni", "wrong-sni", "wrong-ip", "untrusted-root"} {
		t.Run(mode, func(t *testing.T) {
			u := DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.MustParseAddrPort("192.0.2.53:853"), Network: "tls", TLSServerName: "resolver.example"}
			if mode == "captured-ip-no-sni" || mode == "wrong-ip" {
				u.TLSServerName = ""
			}
			if mode == "wrong-ip" {
				u.Endpoint = netip.MustParseAddrPort("192.0.2.54:853")
			}
			if mode == "wrong-sni" {
				u.TLSServerName = "replacement.example"
			}
			config, err := u.tlsConfig()
			if err != nil {
				t.Fatal(err)
			}
			if config.InsecureSkipVerify || config.RootCAs != nil || config.MinVersion != tls.VersionTLS12 || config.VerifyConnection != nil || config.VerifyPeerCertificate != nil {
				t.Fatal("production TLS policy discarded system verification")
			}
			// Replace only the memory peer's trust fixture. Shipping API never accepts
			// a CA override or insecure flag; actual system-root native proof is gated.
			config.RootCAs = roots
			if mode == "untrusted-root" {
				config.RootCAs = x509.NewCertPool()
			}
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
				server := tls.Server(right, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni <- hello.ServerName; return nil, nil }})
				err := server.HandshakeContext(ctx)
				if err == nil {
					var length [2]byte
					_, err = io.ReadFull(server, length[:])
					if err == nil {
						size := int(binary.BigEndian.Uint16(length[:]))
						if size != len(bootstrapUpstreamQuestion()) {
							err = errors.New("TLS peer received changed DNS frame")
						} else {
							body := make([]byte, size)
							_, err = io.ReadFull(server, body)
							if err == nil && !bytes.Equal(body, bootstrapUpstreamQuestion()) {
								err = errors.New("TLS peer received changed DNS question")
							}
							if err == nil {
								_, err = server.Write(append(length[:], body...))
							}
						}
					}
				}
				done <- err
				right.Close()
			}()
			client := tls.Client(left, config)
			err = client.HandshakeContext(ctx)
			positive := mode == "captured-sni" || mode == "captured-ip-no-sni"
			if positive {
				if err != nil {
					t.Fatal(err)
				}
				answer, err := desktopLinuxBootstrapStreamExchange(client, bootstrapUpstreamQuestion())
				if err != nil || !bytes.Equal(answer, bootstrapUpstreamQuestion()) {
					t.Fatal("verified TLS DNS exchange", err)
				}
			} else if err == nil {
				t.Fatal("untrusted TLS became a plain/verified DNS result")
			}
			left.Close()
			serverErr := <-done
			if positive && serverErr != nil {
				t.Fatal(serverErr)
			}
			got := <-sni
			expected := u.TLSServerName
			if got != expected {
				t.Fatal("TLS changed captured SNI (IP must suppress SNI)", got, expected)
			}
		})
	}
}
func TestLinuxStandardBootstrapUpstreamTLSCancellationJoins(t *testing.T) {
	u := DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.MustParseAddrPort("192.0.2.53:853"), Network: "tls"}
	config, err := u.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err = tls.Client(left, config).HandshakeContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("TLS handshake escaped original query deadline", err)
	}
}
