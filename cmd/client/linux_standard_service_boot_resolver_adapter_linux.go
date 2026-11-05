//go:build linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"os"

	"router-vpn/internal/mobiletor"
)

// The service gate and original mutation lease remain held throughout policy
// resolution. Callers receive typed answers, never a native socket or grant.
type linuxBootBootstrapExchange struct {
	operation context.Context
	service   *linuxStandardService
	original  *linuxStandardServiceBootBootstrap
	lease     *legacyExitMutationLease
	native    *legacyExitNativeProtection
}

func (o *linuxBootBootstrapExchange) Current(ctx context.Context) error {
	if o == nil || o.service == nil || o.original == nil || o.lease == nil || o.native == nil {
		return errors.New("bootstrap exchange lost original authority")
	}
	return o.service.bootstrapCurrentLocked(ctx, o.original, o.lease)
}
func (o *linuxBootBootstrapExchange) Exchange(ctx context.Context, network string, server netip.AddrPort, question []byte) ([]byte, error) {
	if e := o.Current(ctx); e != nil {
		return nil, e
	}
	permitted := false
	for _, captured := range o.original.resolver.policy.Servers() {
		permitted = permitted || captured == server
	}
	if !permitted || server.Port() != 53 || network != "udp" && network != "tcp" {
		return nil, errors.New("bootstrap exchange changed captured resolver or transport")
	}
	answer, e := o.native.BootstrapDNSExchangeScoped(o.operation, ctx, o.lease.lock, server.Addr(), network, question)
	if current := o.Current(ctx); current != nil {
		return nil, errors.Join(e, current)
	}
	return answer, e
}

var _ interface {
	BootstrapDNSExchangeNetwork(context.Context, *os.File, netip.Addr, string, []byte) ([]byte, error)
} = (*mobiletor.DesktopLinuxStandardProtection)(nil)
