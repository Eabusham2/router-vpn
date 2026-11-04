//go:build !linux

package main

import "context"

func proveLegacyStandardDNS(context.Context, *app, observedConnection, string, dnsSelection) (dnsProofState, bool) {
	return dnsProofState{}, false
}
