//go:build linux

package mobiletor

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

// DesktopLinuxBootstrapDNSUpstream is an exact captured resolver transport,
// not resolver-policy authority. Its caller must retain and check the original
// daemon/policy owner before and after the operation and validate DNS responses.
// In particular, successful TLS is not DNSSEC validation. No fallback or system
// resolver selection occurs here.
type DesktopLinuxBootstrapDNSUpstream struct {
	Endpoint       netip.AddrPort
	Network        string
	TLSServerName  string
	InterfaceIndex int
}

func (u DesktopLinuxBootstrapDNSUpstream) Validate() error {
	ip := u.Endpoint.Addr()
	if !u.Endpoint.IsValid() || u.Endpoint.Port() == 0 || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" || u.InterfaceIndex < 0 || int64(u.InterfaceIndex) > 1<<31-1 {
		return errors.New("bootstrap upstream lacks an exact physical literal endpoint/scope")
	}
	if u.Network != "udp" && u.Network != "tcp" && u.Network != "tls" {
		return errors.New("bootstrap upstream transport is unsupported")
	}
	if u.Network != "tls" && u.TLSServerName != "" {
		return errors.New("plain bootstrap transport cannot discard captured TLS identity")
	}
	if u.TLSServerName != "" && !desktopLinuxBootstrapTLSName(u.TLSServerName) {
		return errors.New("bootstrap TLS identity is malformed")
	}
	return nil
}
func desktopLinuxBootstrapTLSName(name string) bool {
	if len(name) == 0 || len(name) > 254 {
		return false
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		return ip.Zone() == "" && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsLoopback()
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func (u DesktopLinuxBootstrapDNSUpstream) socketNetwork() string {
	if u.Network == "tls" {
		return "tcp"
	}
	return u.Network
}
func (u DesktopLinuxBootstrapDNSUpstream) tlsConfig() (*tls.Config, error) {
	if err := u.Validate(); err != nil {
		return nil, err
	}
	if u.Network != "tls" {
		return nil, errors.New("bootstrap TLS handshake requires original TLS selection")
	}
	identity := u.TLSServerName
	if identity == "" {
		identity = u.Endpoint.Addr().String()
	}
	// Go verifies ServerName against the certificate. An IP identity is verified
	// as an IP SAN and is not emitted as SNI. nil RootCAs uses system trust.
	// https://pkg.go.dev/crypto/tls#Config
	return &tls.Config{ServerName: identity, MinVersion: tls.VersionTLS12}, nil
}
func (u DesktopLinuxBootstrapDNSUpstream) route(ctx context.Context, mark uint32, local netip.AddrPort) (desktopLinuxBootstrapRoute, error) {
	if err := u.Validate(); err != nil {
		return desktopLinuxBootstrapRoute{}, err
	}
	route, err := desktopLinuxBootstrapRouteForTarget(ctx, u.Endpoint, mark, local, u.socketNetwork())
	if err != nil {
		return desktopLinuxBootstrapRoute{}, err
	}
	if u.InterfaceIndex != 0 && route.Interface.Index != u.InterfaceIndex {
		return desktopLinuxBootstrapRoute{}, errors.New("bootstrap route left its captured original resolver link")
	}
	return route, nil
}

// BootstrapDNSExchangeUpstream retains one original exact socket/finite grant.
// UDP, framed TCP and authenticated DNS-over-TLS are separate explicit choices.
// Failure never retries on another port, drops TLS, or selects ambient DNS.
func (p *DesktopLinuxStandardProtection) BootstrapDNSExchangeUpstream(original, query context.Context, lease *os.File, upstream DesktopLinuxBootstrapDNSUpstream, question []byte) ([]byte, error) {
	if err := upstream.Validate(); err != nil {
		return nil, err
	}
	return p.bootstrapDNSExchangeScoped(original, query, lease, upstream, question)
}
func desktopLinuxBootstrapRuleWireForUpstream(route desktopLinuxBootstrapRoute, local netip.AddrPort, u DesktopLinuxBootstrapDNSUpstream, mark uint32, set string) ([]byte, error) {
	if err := u.Validate(); err != nil {
		return nil, err
	}
	if u.InterfaceIndex != 0 && route.Interface.Index != u.InterfaceIndex {
		return nil, errors.New("bootstrap permit changed original resolver link")
	}
	return desktopLinuxBootstrapRuleWireTarget(route, local, u.Endpoint, mark, u.socketNetwork(), set)
}

func desktopLinuxBootstrapStreamExchange(connection net.Conn, question []byte) ([]byte, error) {
	if connection == nil || desktopLinuxBootstrapQuestion(question) != nil {
		return nil, errors.New("bootstrap stream omitted original bounded question")
	}
	return desktopLinuxBootstrapFramedExchange(connection, question, 16<<10)
}

// Callers first validate their own ordinary or typed DNSSEC question. Framing
// alone never provides query authority or changes the ordinary response bound.
func desktopLinuxBootstrapFramedExchange(connection net.Conn, question []byte, bound int) ([]byte, error) {
	if connection == nil || len(question) < 12 || len(question) > 65535 || bound < 12 || bound > 65535 {
		return nil, errors.New("bootstrap framed exchange exceeded captured bounds")
	}
	frame := make([]byte, len(question)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(question)))
	copy(frame[2:], question)
	for len(frame) > 0 {
		n, err := connection.Write(frame)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		frame = frame[n:]
	}
	var length [2]byte
	if _, err := io.ReadFull(connection, length[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(length[:]))
	if size < 12 || size > bound {
		return nil, errors.New("bootstrap TCP answer exceeds bound")
	}
	answer := make([]byte, size)
	if _, err := io.ReadFull(connection, answer); err != nil {
		return nil, err
	}
	return answer, nil
}
