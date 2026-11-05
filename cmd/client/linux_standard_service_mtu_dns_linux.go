//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"

	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/mobilemtu"
)

// The benchmark host is fixed, and the DNS query traverses the already proved
// selected policy. Neither /etc/hosts nor the machine's ordinary resolver can
// supply a benchmark address for this captured VPN path.
func linuxStandardMTUBenchmarkQuery() ([]byte, error) {
	query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		5, 's', 'p', 'e', 'e', 'd', 10, 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	_, err := rand.Read(query[:2])
	return query, err
}

func (s *linuxStandardService) resolveMTUPublicHost(ctx context.Context, session *linuxStandardServiceSession) (addresses []string, failure error) {
	if session == nil || session != s.session || session.owner == nil || session.owner.dns == nil {
		return nil, errors.New("standard MTU DNS lost its original session")
	}
	if err := s.networkCurrent(ctx, session, true); err != nil {
		return nil, err
	}
	owner := session.owner
	if err := linuxStandardServiceDNSReceiptCurrent(ctx, owner); err != nil {
		return nil, err
	}
	if err := mobilemtu.LockContext(ctx, &owner.dns.mu); err != nil {
		return nil, err
	}
	proof := owner.dns.proof
	owner.dns.mu.Unlock()
	if proof == nil {
		return nil, errors.New("standard MTU DNS lacks original listener proof")
	}
	member, err := legacyDNSDuplicateChildFD(owner.originalPIDFD, proof.fd)
	if err != nil {
		return nil, err
	}
	defer func() {
		failure = errors.Join(failure, member.Close(), ctx.Err())
		if failure != nil {
			addresses = nil
		}
	}()
	endpoint := netip.MustParseAddrPort("127.0.0.1:1099")
	current := func() error {
		identity, err := legacyDNSListenerSnapshot(member, endpoint)
		if err != nil || identity != proof.listener {
			return errors.Join(err, errors.New("standard MTU DNS listener changed during query"))
		}
		return linuxStandardServiceDNSReceiptCurrent(ctx, owner)
	}
	if err := current(); err != nil {
		return nil, err
	}
	query, err := linuxStandardMTUBenchmarkQuery()
	if err != nil {
		return nil, err
	}
	response, err := exchangeLegacyStandardDNSQuery(ctx, endpoint.String(), query)
	if err != nil {
		return nil, err
	}
	answers, err := dnsmeasure.PublicIPv4Answers(query, response)
	if err != nil {
		return nil, err
	}
	if err := current(); err != nil {
		return nil, err
	}
	if err := s.networkCurrent(ctx, session, true); err != nil {
		return nil, err
	}
	for _, address := range answers {
		addresses = append(addresses, address.String())
	}
	return addresses, ctx.Err()
}
