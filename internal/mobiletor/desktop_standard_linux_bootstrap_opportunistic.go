//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
)

// DesktopLinuxOpportunisticDNS is a frozen selected policy, not proof of daemon
// provenance. The original helper/capture guard is required on every exchange.
// Its private fields cannot turn the ordinary strict-TLS API into a generic
// certificate-verification bypass.
type DesktopLinuxOpportunisticDNS struct {
	policy       []byte
	name         string
	selected     standardengine.ResolvedDNS
	plainNetwork string
	routeIndex   int32
}

func NewDesktopLinuxOpportunisticDNS(policy standardengine.ResolvedPolicy, name string, index int32, plainNetwork string) (*DesktopLinuxOpportunisticDNS, error) {
	if index < 0 || !standardengine.ResolvedName(name, false) || plainNetwork != "udp" && plainNetwork != "tcp" {
		return nil, errors.New("opportunistic DNS omitted original selected query/transport")
	}
	raw, err := policy.Canonical()
	if err != nil {
		return nil, err
	}
	routes, err := policy.ResolvedRoutes(name)
	if err != nil {
		return nil, err
	}
	var selected *standardengine.ResolvedDNS
	for _, route := range routes {
		if route.Index != index {
			continue
		}
		if selected != nil || route.DNSOverTLS != "opportunistic" || route.CurrentDNS == nil {
			return nil, errors.New("opportunistic DNS requires exact captured effective policy/current server")
		}
		copy := *route.CurrentDNS
		selected = &copy
	}
	if selected == nil {
		return nil, errors.New("opportunistic DNS selected scope is outside original route cohort")
	}
	c := &DesktopLinuxOpportunisticDNS{policy: bytes.Clone(raw), name: name, selected: *selected, plainNetwork: plainNetwork, routeIndex: index}
	secure, plain, err := c.upstreams()
	if err != nil {
		return nil, err
	}
	if secure.Validate() != nil || plain.Validate() != nil {
		return nil, errors.New("opportunistic DNS tuple is outside protected upstream bounds")
	}
	return c, nil
}

func (c *DesktopLinuxOpportunisticDNS) upstreams() (DesktopLinuxBootstrapDNSUpstream, DesktopLinuxBootstrapDNSUpstream, error) {
	var secure, plain DesktopLinuxBootstrapDNSUpstream
	if c == nil || len(c.policy) == 0 || c.plainNetwork != "udp" && c.plainNetwork != "tcp" {
		return secure, plain, errors.New("missing original opportunistic policy capability")
	}
	ip, err := netip.ParseAddr(c.selected.Address)
	if err != nil {
		return secure, plain, err
	}
	tlsPort, plainPort := c.selected.Port, c.selected.Port
	if tlsPort == 0 {
		tlsPort = 853
		plainPort = 53
	}
	secure = DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.AddrPortFrom(ip, tlsPort), Network: "tls", TLSServerName: c.selected.ServerName, InterfaceIndex: int(c.selected.Index)}
	plain = DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.AddrPortFrom(ip, plainPort), Network: c.plainNetwork, InterfaceIndex: int(c.selected.Index)}
	return secure, plain, nil
}

// MatchesPolicy lets the caller bind each original-helper observation to the
// same immutable policy. It grants no daemon authority by itself.
func (c *DesktopLinuxOpportunisticDNS) MatchesPolicy(policy standardengine.ResolvedPolicy) bool {
	if c == nil {
		return false
	}
	raw, err := policy.Canonical()
	return err == nil && bytes.Equal(c.policy, raw)
}

type desktopLinuxBootstrapTLSAttempt struct {
	config   *tls.Config
	deadline time.Time
}
type desktopLinuxBootstrapTLSUnavailable struct {
	cause  error
	member *desktopLinuxStandardBootstrap
}

func (e *desktopLinuxBootstrapTLSUnavailable) Error() string {
	return "original opportunistic TLS unavailable before DNS: " + e.cause.Error()
}
func (e *desktopLinuxBootstrapTLSUnavailable) Unwrap() error { return e.cause }

func desktopLinuxBootstrapTLSProtocolFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	for _, value := range []error{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EPIPE, syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH} {
		if errors.Is(err, value) {
			return true
		}
	}
	var network net.Error
	return errors.As(err, &network) && network.Timeout()
}

// The TLS failure is eligible only while every original owner/grant/socket is
// still current. Cancellation, a stale permit, or a control/setup failure is not
// evidence that this selected server lacks TLS and never permits plaintext.
func (g *DesktopLinuxBootstrapDNSGroup) unavailableTLS(ctx context.Context, t *desktopLinuxStandardBootstrap, cause error) error {
	if t == nil || t.group != g {
		return errors.Join(cause, errors.New("opportunistic TLS lost original group member"))
	}
	if ctx.Err() != nil || !desktopLinuxBootstrapTLSProtocolFailure(cause) {
		return cause
	}
	if err := desktopnetwork.LockContext(ctx, &g.mu); err != nil {
		return errors.Join(cause, err)
	}
	defer g.mu.Unlock()
	if g.closing || g.blocked != nil || t.grant == nil || !t.grant.complete() || t.grant.rejected {
		return errors.Join(cause, errors.New("opportunistic TLS failure lost original grant authority"))
	}
	if err := t.currentSocket(ctx); err != nil {
		return errors.Join(cause, err)
	}
	if _, err := g.observe(ctx); err != nil {
		return errors.Join(cause, err)
	}
	if !t.grantLive {
		return errors.Join(cause, errors.New("opportunistic TLS failure outlived original finite permit"))
	}
	return &desktopLinuxBootstrapTLSUnavailable{cause: cause, member: t}
}

// ExchangeOpportunistic implements the documented selected policy: attempt TLS
// first, permitting plain DNS only after an owned pre-DNS connection/handshake
// failure. It does not infer the daemon's next decision from historical feature
// levels. Strict TLS remains on Exchange's unchanged certificate-checked path.
// https://www.freedesktop.org/software/systemd/man/257/resolved.conf.html
// current must check original daemon/capture/operation, NOT acquire this group's
// baseline gate (e.g. it must not call protection.Current).
func (g *DesktopLinuxBootstrapDNSGroup) ExchangeOpportunistic(query context.Context, c *DesktopLinuxOpportunisticDNS, question []byte, current func(context.Context) error) ([]byte, error) {
	if query == nil || current == nil || c == nil || desktopLinuxBootstrapQuestion(question) != nil {
		return nil, errors.New("opportunistic DNS requires original policy/current-owner guard")
	}
	var labels []string
	for i := 12; question[i] != 0; {
		length := int(question[i])
		i++
		labels = append(labels, string(question[i:i+length]))
		i += length
	}
	if !strings.EqualFold(strings.Join(labels, "."), strings.TrimSuffix(c.name, ".")) {
		return nil, errors.New("opportunistic DNS question changed original selected name")
	}
	deadline, ok := query.Deadline()
	if !ok || query.Err() != nil || g == nil || g.ctx == nil || deadline.After(g.deadline) {
		return nil, errors.New("opportunistic DNS lost original bounded query")
	}
	secure, plain, err := c.upstreams()
	if err != nil {
		return nil, err
	}
	if err = current(query); err != nil {
		return nil, err
	}
	remaining := time.Until(deadline)
	if remaining < 200*time.Millisecond {
		return nil, errors.New("opportunistic DNS has no bounded TLS-first/fallback interval")
	}
	budget := remaining / 2
	if budget > time.Second {
		budget = time.Second
	}
	// Deliberately unauthenticated ONLY for captured opportunistic policy. Empty
	// captured SNI remains empty; this is not the strict path's IP-SAN identity.
	attempt := &desktopLinuxBootstrapTLSAttempt{config: c.tlsConfig(), deadline: time.Now().Add(budget)}
	answer, err := g.exchangeAttempt(query, secure, question, attempt)
	if err == nil {
		if check := current(query); check != nil {
			return nil, check
		}
		return answer, nil
	}
	var unavailable *desktopLinuxBootstrapTLSUnavailable
	if !errors.As(err, &unavailable) || query.Err() != nil || g.ctx.Err() != nil {
		return nil, err
	}
	if check := current(query); check != nil {
		return nil, errors.Join(err, check)
	}
	// The daemon guard may itself take time; recheck the original finite
	// permit again before admitting a distinct plain socket.
	confirmed := g.unavailableTLS(query, unavailable.member, unavailable.cause)
	var stillUnavailable *desktopLinuxBootstrapTLSUnavailable
	if !errors.As(confirmed, &stillUnavailable) {
		return nil, confirmed
	}
	answer, err = g.Exchange(query, plain, question)
	if err != nil {
		return nil, err
	}
	if check := current(query); check != nil {
		return nil, check
	}
	// A matching UDP truncation continues the already selected plaintext
	// transport on the same exact tuple. It never restarts TLS negotiation.
	if plain.Network == "udp" && len(answer) >= 12 && answer[2]&2 != 0 {
		if err = common.ValidateDNSForwardResponse(question, answer); err != nil {
			return nil, err
		}
		plain.Network = "tcp"
		answer, err = g.Exchange(query, plain, question)
		if err != nil {
			return nil, err
		}
		if check := current(query); check != nil {
			return nil, check
		}
		if len(answer) < 12 || answer[2]&2 != 0 {
			return nil, errors.New("opportunistic TCP response remained truncated")
		}
	}
	return answer, nil
}

func (c *DesktopLinuxOpportunisticDNS) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: c.selected.ServerName, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
}
