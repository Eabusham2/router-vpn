package mobilemultihop

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
)

// ProveExternalPublicIP verifies the selected ordinary external address through
// one caller-owned native route. The literal HTTPS service is an address proof,
// not a DNS resolver or permission to use the ordinary network. The caller must
// capture its route owner before this call and reject a retired owner afterward.
// The synchronous HTTP primitive retains dial, TLS, IO and close completion;
// cancellation cannot leave an abandoned socket or produce a successful proof.
func ProveExternalPublicIP(parent context.Context, dial func(context.Context, string, string) (net.Conn, error), tag, expected string) error {
	return proveExternalPublicIP(parent, dial, tag, expected, nil)
}

// A private TLS-root seam allows isolated encrypted peers in package tests.
// Shipping callers cannot supply alternate roots or skip certificate checks.
func proveExternalPublicIP(parent context.Context, dial func(context.Context, string, string) (net.Conn, error), tag, expected string, testTLS *tls.Config) error {
	if parent == nil || parent.Err() != nil || dial == nil || !exactID.MatchString(tag) || !externalPublicIP(expected) {
		return errors.New("external public proof has no captured route and selected address")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("external proof nonce unavailable")
	}
	data, err := externalProofHTTP(parent, dial, tag, "https://1.1.1.1/cdn-cgi/trace?routervpn_proof="+hex.EncodeToString(nonce[:]), "", testTLS)
	if err != nil {
		return err
	}
	if parent.Err() != nil {
		return errors.New("external public proof was canceled before adoption")
	}
	return externalTraceAddress(data, expected)
}
